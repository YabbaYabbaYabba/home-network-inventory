"""Read-only client for stock ASUS router firmware (ASUSWRT).

It talks to the same endpoints the ASUS Router phone app uses:

    POST /login.cgi    login_authorization=base64(user:pass)  ->  {"asus_token": "..."}
    POST /appGet.cgi   hook=get_clientlist()                   ->  client list (Network Map)
    POST /appGet.cgi   hook=netdev(appobj)                     ->  interface byte counters
    GET  /getTraffic.asp                                       ->  per-client traffic (needs Traffic Analyzer / QoS)
    GET  /Logout.asp

It only reads. It never posts to apply.cgi, so it cannot change a setting.

One token is kept and reused until the router rejects it, so the app logs in rarely.
Stock firmware allows one admin web session at a time; see README "Router login".
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import re
import ssl
from urllib.parse import urlsplit

import aiohttp

log = logging.getLogger("asus")

# The ASUS Router app's user agent: with it, login.cgi answers in JSON with a token.
UA = "asusrouter-Android-DUTUtil-1.0.0.245"
TIMEOUT = aiohttp.ClientTimeout(total=15, connect=6)


class RouterError(Exception):
    """Any problem talking to the router. `message` is safe to show in the UI."""


class AuthError(RouterError):
    pass


class LockedOut(RouterError):
    def __init__(self, msg: str, seconds: int):
        super().__init__(msg)
        self.seconds = seconds


class CertChanged(RouterError):
    def __init__(self, expected: str, got: str):
        super().__init__(
            "The router's HTTPS certificate has changed. This happens after a firmware update or "
            "factory reset, but could also mean something is intercepting traffic. "
            f"New fingerprint SHA-256 {fmt_fp(got)}. Check it on the router, then accept it on the Status page.")
        self.expected, self.got = expected, got


def fmt_fp(hexstr: str) -> str:
    return ":".join(hexstr[i:i + 2] for i in range(0, len(hexstr), 2)).upper()


LOGIN_ERRORS = {
    "1": "The router refused the login (error 1).",
    "2": "Another admin is logged in to the router. Log out of the router's web page, then wait.",
    "3": "Wrong router username or password. Check ROUTER_USER and ROUTER_PASSWORD.",
    "7": "The router has locked logins after too many failed attempts.",
    "8": "The router has locked logins after too many failed attempts.",
    "10": "The router wants a CAPTCHA after failed logins. Log in once in a browser, then restart the app.",
}


def parse_json(text: str):
    """appGet.cgi output is JSON, but some firmware leaves trailing commas."""
    try:
        return json.loads(text)
    except ValueError:
        return json.loads(re.sub(r",\s*([}\]])", r"\1", text))


def band_name(code: str, model: str = "") -> str:
    code = str(code or "0")
    m = model.upper()
    six = "AXE" in m or "-BE" in m or m.startswith("BE") or "ET" in m.split("-")[0]
    return {
        "0": "wired", "1": "2.4 GHz", "2": "5 GHz",
        "3": "6 GHz" if six else "5 GHz-2", "4": "6 GHz", "5": "6 GHz-2",
    }.get(code, f"Wi-Fi {code}")


def _num(v) -> float | None:
    try:
        return float(str(v).strip()) if str(v).strip() not in ("", "-") else None
    except ValueError:
        return None


def parse_clientlist(data: dict, model: str = "") -> list[dict]:
    cl = data.get("get_clientlist", data)
    out = []
    for key, c in cl.items():
        if not isinstance(c, dict) or not re.fullmatch(r"[0-9A-Fa-f:]{17}", key):
            continue
        mac = (c.get("mac") or key).upper()
        online = str(c.get("isOnline", "1")) == "1"
        rssi = _num(c.get("rssi"))
        out.append({
            "mac": mac,
            "ip": c.get("ip") or None,
            "name": (c.get("nickName") or c.get("name") or "").strip() or None,
            "router_name": (c.get("name") or "").strip() or None,
            "vendor": (c.get("vendor") or "").strip() or None,
            "conn": band_name(c.get("isWL", "0"), model),
            "online": online,
            "rssi": int(rssi) if rssi not in (None, 0.0) else None,
            "link_tx": _num(c.get("curTx")),
            "link_rx": _num(c.get("curRx")),
            "ip_method": c.get("ipMethod") or None,
            "asus_type": str(c.get("type") or "") or None,
            "is_gateway": str(c.get("isGateway", "0")) == "1",
            "is_printer": str(c.get("isPrinter", "0")) == "1",
            "mesh_parent": (c.get("amesh_papMac") or "").upper() or None,
            "ssid": c.get("ssid") or None,
        })
    return out


def parse_netdev(data: dict) -> dict[str, dict[str, int]]:
    nd = data.get("netdev", data)
    out: dict[str, dict[str, int]] = {}
    for k, v in nd.items():
        m = re.fullmatch(r"(.+)_(rx|tx)", k)
        if not m:
            continue
        try:
            n = int(str(v), 0) if str(v).lower().startswith("0x") else int(str(v))
        except ValueError:
            continue
        out.setdefault(m.group(1), {})[m.group(2)] = n
    return out


TRAFFIC_RE = re.compile(
    r"""\[\s*["']([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})["']\s*,\s*["']?(\d+)["']?\s*,\s*["']?(\d+)["']?""")


def parse_traffic(text: str) -> dict[str, tuple[int, int]]:
    """getTraffic.asp: JavaScript arrays of [mac, tx, rx] byte counters (router's point of view)."""
    return {m.group(1).upper(): (int(m.group(2)), int(m.group(3))) for m in TRAFFIC_RE.finditer(text)}


class AsusRouter:
    def __init__(self, url: str, user: str, password: str, pin: str = "", saved_pin: str = "",
                 on_pin=None):
        self.url = url.rstrip("/")
        parts = urlsplit(self.url)
        self.host = parts.hostname or ""
        self.https = parts.scheme == "https"
        self.port = parts.port or (443 if self.https else 80)
        self.user, self.password = user, password
        self.pin_fixed = pin              # from ROUTER_CERT_SHA256: never changes on its own
        self.pin = pin or saved_pin       # in use (configured, or trusted on first use)
        self.on_pin = on_pin              # callback(hex) to save a TOFU pin
        self.token: str | None = None
        self.model = ""
        self.lock = asyncio.Lock()
        self._session: aiohttp.ClientSession | None = None

    # ------------------------------------------------------------ plumbing
    async def _sess(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(timeout=TIMEOUT, cookie_jar=aiohttp.DummyCookieJar())
        return self._session

    async def _ssl(self):
        if not self.https:
            return None
        if not self.pin:
            # Trust on first use: the router's certificate is self-signed, so pin its fingerprint.
            der = await asyncio.to_thread(_fetch_cert_der, self.host, self.port)
            self.pin = hashlib.sha256(der).hexdigest()
            log.info("Pinned the router's certificate, SHA-256 %s", fmt_fp(self.pin))
            if self.on_pin:
                self.on_pin(self.pin)
        return aiohttp.Fingerprint(bytes.fromhex(self.pin))

    def _headers(self) -> dict:
        h = {"User-Agent": UA, "Referer": f"{self.url}/"}
        if self.token:
            h["Cookie"] = f"asus_token={self.token}"
        return h

    async def _req(self, method: str, path: str, data: dict | None = None) -> str:
        s = await self._sess()
        try:
            async with s.request(method, self.url + path, data=data, headers=self._headers(),
                                 ssl=await self._ssl(), allow_redirects=False) as r:
                text = await r.text(errors="replace")
                if r.status in (401, 403) or r.status in (301, 302) and "login" in r.headers.get("Location", "").lower():
                    raise _Expired()
                if r.status >= 400:
                    raise RouterError(f"The router returned HTTP {r.status} for {path}.")
                return text
        except aiohttp.ServerFingerprintMismatch as e:
            raise CertChanged(e.expected.hex(), e.got.hex()) from None
        except (aiohttp.ClientConnectorError, asyncio.TimeoutError, OSError) as e:
            raise RouterError(f"Can't reach the router at {self.url} ({type(e).__name__}).") from None

    # ------------------------------------------------------------ session
    async def login(self) -> None:
        if not self.password:
            raise AuthError("ROUTER_PASSWORD is not set in .env.")
        self.token = None
        cred = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        text = await self._req("POST", "/login.cgi", {"login_authorization": cred})
        try:
            d = parse_json(text)
        except ValueError:
            raise RouterError("The router's login page didn't answer as expected. Is ROUTER_URL right?") from None
        if d.get("asus_token"):
            self.token = d["asus_token"]
            log.info("Logged in to the router")
            return
        code = str(d.get("error_status", "?"))
        msg = LOGIN_ERRORS.get(code, f"The router refused the login (error {code}).")
        if code in ("7", "8", "10"):
            wait = int(_num(d.get("remaining_lock_time")) or 300)
            raise LockedOut(msg, wait)
        raise AuthError(msg)

    async def logout(self) -> None:
        if self.token:
            try:
                await self._req("GET", "/Logout.asp")
            except RouterError:
                pass
            self.token = None
        if self._session:
            await self._session.close()

    async def _call(self, method: str, path: str, data: dict | None = None) -> str:
        """Request with the current token; log in again once if it has expired."""
        async with self.lock:
            for attempt in (1, 2):
                if not self.token:
                    await self.login()
                try:
                    text = await self._req(method, path, data)
                except _Expired:
                    self.token = None
                    continue
                if _looks_logged_out(text):
                    self.token = None
                    if attempt == 1:
                        continue
                    raise RouterError("The router keeps ending the session. Is someone logged in to its web page?")
                return text
            raise RouterError("The router keeps ending the session.")

    async def hook(self, hook: str):
        text = await self._call("POST", "/appGet.cgi", {"hook": hook})
        try:
            return parse_json(text)
        except ValueError:
            raise RouterError(f"Unexpected reply to {hook}: {text[:80]!r}") from None

    # ------------------------------------------------------------ data
    async def info(self) -> dict:
        keys = ["productid", "firmver", "buildno", "extendno", "lan_ipaddr", "lan_netmask", "label_mac"]
        d = await self.hook(";".join(f"nvram_get({k})" for k in keys))
        self.model = d.get("productid", "") or self.model
        return {k: d.get(k) for k in keys}

    async def clients(self) -> list[dict]:
        return parse_clientlist(await self.hook("get_clientlist()"), self.model)

    async def netdev(self) -> dict[str, dict[str, int]]:
        return parse_netdev(await self.hook("netdev(appobj)"))

    async def traffic(self) -> dict[str, tuple[int, int]]:
        return parse_traffic(await self._call("GET", "/getTraffic.asp"))

    async def raw(self, what: str) -> str:
        if what.startswith("/"):
            if what not in ("/getTraffic.asp",):
                raise RouterError("Only /getTraffic.asp can be read raw.")
            return await self._call("GET", what)
        if not re.fullmatch(r"[A-Za-z_]+\([A-Za-z_0-9]*\)(;[A-Za-z_]+\([A-Za-z_0-9]*\))*", what):
            raise RouterError("Not a read hook.")
        return await self._call("POST", "/appGet.cgi", {"hook": what})


class _Expired(Exception):
    pass


def _looks_logged_out(text: str) -> bool:
    t = text[:600]
    return ("Main_Login.asp" in t and "top.location" in t) or '"error_status"' in t


def _fetch_cert_der(host: str, port: int) -> bytes:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # only to read the self-signed cert so it can be pinned
    import socket
    with socket.create_connection((host, port), timeout=6) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(binary_form=True)
