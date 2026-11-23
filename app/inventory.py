"""The inventory engine: merges what the router and the scanner see, classifies, keeps history."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from urllib.parse import urlsplit

import aiohttp

from . import discovery
from .asus import AsusRouter, AuthError, CertChanged, LockedOut, RouterError, band_name, fmt_fp
from .classify import GROUP_IDS, classify, model_text
from .store import Store

log = logging.getLogger("inventory")

try:
    from netaddr import EUI
except ImportError:  # pragma: no cover
    EUI = None


def oui_vendor(mac: str) -> str | None:
    if EUI is None or discovery.is_random_mac(mac):
        return None
    try:
        return EUI(mac).oui.registration().org.strip()
    except Exception:  # noqa: BLE001 - unregistered prefix
        return None


def display_name(d: dict) -> str:
    sig = d.get("signals") or {}
    r = sig.get("router") or {}
    md = sig.get("mdns") or {}
    sd = sig.get("ssdp") or {}
    for n in (d.get("label"), r.get("name"), (md.get("instances") or [None])[0], sig.get("ptr"),
              md.get("hostname"), sig.get("netbios"), sd.get("friendlyName")):
        if n and n.strip() and n.strip().upper() != d["mac"] and not n.strip().startswith("*"):
            return n.strip()
    if d.get("is_self"):
        return "This NAS (inventory scanner)"
    v = d.get("vendor") or ("Private address" if d.get("random_mac") else "Unknown")
    return f"{v.split(',')[0].split(' ')[0]} ·{d['mac'][-5:].replace(':', '')}"


class Inventory:
    def __init__(self, store: Store, cfg: dict):
        self.store, self.cfg = store, cfg
        self.devices: dict[str, dict] = store.load_devices()
        for d in self.devices.values():
            d["online"] = False  # nothing is online until it's seen again
        self.router = AsusRouter(cfg["router_url"], cfg["router_user"], cfg["router_password"],
                                 pin=cfg["router_cert_sha256"], saved_pin=store.get_meta("router_cert") or "",
                                 on_pin=lambda p: store.set_meta("router_cert", p))
        self.router_host = urlsplit(cfg["router_url"]).hostname or ""
        self.info: dict = {}
        self.rstate = {"ok": None, "error": None, "fails": 0, "next_try": 0.0, "paused_until": 0.0,
                       "cert_pending": None, "last_ok": None, "last_clients": None}
        self.sstate = {"enabled": cfg["scan"], "error": None, "last": None, "found": 0, "subnet": None,
                       "running": False, "last_enrich": 0.0}
        self.subnet: ipaddress.IPv4Network | None = None
        self.local_ip = self.iface = self.local_mac = None
        self.baseline = store.get_meta("baseline_done") == "1"
        self.version = 1  # bumps whenever the device list changes, so the page can skip unchanged polls
        # live traffic
        self.viewer_ts = 0.0
        self.live: dict = {"ts": None, "ifaces": {}, "devices": {}, "device_traffic": cfg["device_traffic"]}
        self._prev_nd: tuple[float, dict] | None = None
        self._prev_tr: tuple[float, dict] | None = None
        self._tr_fails = 0
        self._tr_retry = 0.0
        self._alert_session: aiohttp.ClientSession | None = None

    # ================================================================ devices
    def observe(self, mac: str, ip: str | None, source: str, ts: float, online: bool = True,
                router: dict | None = None) -> dict:
        d = self.devices.get(mac)
        if d is None:
            d = {"mac": mac, "first_seen": ts, "last_seen": ts if online else 0, "ip": ip, "online": False,
                 "vendor": oui_vendor(mac) or (router or {}).get("vendor"),
                 "random_mac": discovery.is_random_mac(mac), "signals": {"router": router} if router else {},
                 "conn": (router or {}).get("conn") if online else None,
                 "label": None, "group_manual": None, "notes": "", "approved": False, "seen": {}}
            self.devices[mac] = d
            self._maybe_same(d)
            self._event("new", mac, f"New device: {display_name(d)}" + (f" at {ip}" if ip else "")
                        + ("" if online else " (from the router's history, offline)"), alert=online)
        if online:
            d["last_seen"] = max(d.get("last_seen") or 0, ts)
            d.setdefault("seen", {})[source] = ts
            if not d.get("online"):
                d["online"] = True
                if d.get("first_seen") != ts:
                    self._event("online", mac, f"{display_name(d)} came online")
        if ip and online:
            if d.get("ip") and d["ip"] != ip:
                self._event("ip", mac, f"{display_name(d)} moved from {d['ip']} to {ip}")
            d["ip"] = ip
            self.store.seen_ip(mac, ip, ts)
        elif ip and not d.get("ip"):
            d["ip"] = ip
        return d

    def _maybe_same(self, d: dict) -> None:
        """Phones get a new random MAC now and then; point at the device it probably replaced."""
        if not d["random_mac"]:
            return
        name = display_name(d)
        for o in self.devices.values():
            if o is not d and o.get("random_mac") and display_name(o) == name and not o.get("online"):
                d["maybe_same"] = o["mac"]
                break

    def reclassify(self, d: dict) -> None:
        d["auto"] = classify(d)
        d["model"] = model_text(d)
        d["name"] = display_name(d)

    def group_of(self, d: dict) -> str:
        g = d.get("group_manual")
        return g if g in GROUP_IDS else (d.get("auto") or {}).get("group", "unknown")

    def save(self, d: dict) -> None:
        self.reclassify(d)
        self.store.save_device(d)

    def update_device(self, mac: str, changes: dict) -> dict:
        d = self.devices[mac]
        if "label" in changes:
            d["label"] = (str(changes["label"] or "").strip()[:80]) or None
        if "group" in changes:
            g = changes["group"]
            d["group_manual"] = g if g in GROUP_IDS else None
        if "notes" in changes:
            d["notes"] = str(changes["notes"] or "")[:2000]
        if "approved" in changes:
            was = d.get("approved")
            d["approved"] = bool(changes["approved"])
            if d["approved"] and not was:
                self._event("approved", mac, f"{display_name(d)} approved")
        self.save(d)
        self.notify()
        return d

    def forget(self, mac: str) -> None:
        d = self.devices.pop(mac, None)
        if d:
            self.store.delete_device(mac)
            self._event("forgot", mac, f"Removed {display_name(d)} from the inventory")

    def approve_all(self) -> int:
        n = 0
        for d in self.devices.values():
            if not d.get("approved"):
                d["approved"] = True
                self.save(d)
                n += 1
        if n:
            self._event("approved", None, f"Approved {n} devices")
        return n

    # ================================================================ events + alerts
    def _event(self, kind: str, mac: str | None, text: str, alert: bool = False) -> None:
        self.store.add_event(kind, mac, text)
        log.info("%s", text)
        if alert and self.baseline and self.cfg["alert_webhook"]:
            asyncio.get_event_loop().create_task(self._webhook(kind, mac, text))

    async def _webhook(self, kind: str, mac: str | None, text: str) -> None:
        url = self.cfg["alert_webhook"]
        d = self.devices.get(mac or "", {})
        dev = {k: d.get(k) for k in ("mac", "ip", "vendor", "name", "conn")} if d else None
        if self._alert_session is None or self._alert_session.closed:
            self._alert_session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10))
        try:
            if "ntfy" in (urlsplit(url).hostname or ""):
                await self._alert_session.post(url, data=text.encode(), headers={
                    "Title": "Home network: new device", "Tags": "warning"})
            else:  # Slack, Discord, Home Assistant and most others accept one of these keys
                await self._alert_session.post(url, json={"text": text, "content": text, "title": "New device",
                                                          "event": kind, "device": dev})
        except Exception as e:  # noqa: BLE001
            log.warning("Alert webhook failed: %s", e)

    def notify(self) -> None:
        self.version += 1

    # ================================================================ router
    def router_allowed(self) -> bool:
        now = time.time()
        r = self.rstate
        return not r["cert_pending"] and now >= r["next_try"] and now >= r["paused_until"]

    def _router_ok(self) -> None:
        self.rstate.update(ok=True, error=None, fails=0, next_try=0.0, last_ok=time.time())

    def _router_fail(self, e: Exception) -> None:
        r = self.rstate
        r["fails"] += 1
        r["ok"] = False
        if isinstance(e, CertChanged):
            r["cert_pending"] = e.got
            delay = 0
        elif isinstance(e, LockedOut):
            delay = max(e.seconds, 300)
        elif isinstance(e, AuthError):
            delay = 1800  # wrong password: don't keep trying and trip the router's lockout
        else:
            delay = min(30 * 2 ** (r["fails"] - 1), 600)
        r["error"] = str(e) or type(e).__name__
        r["next_try"] = time.time() + delay
        log.warning("Router: %s (next try in %ss)", r["error"], delay)

    async def router_clients(self) -> None:
        if not self.info:
            self.info = await self.router.info()
            self._add_router_device()
        clients = await self.router.clients()
        now = time.time()
        router_mac = (self.info.get("label_mac") or "").upper()
        parents = {c["mesh_parent"] for c in clients if c.get("mesh_parent")} - {router_mac, ""}
        for c in clients:
            d = self.observe(c["mac"], c["ip"], "router", now, online=c["online"], router=c)
            d.setdefault("signals", {})["router"] = c
            if c["online"]:
                d["conn"] = c["conn"]
                d["mesh_parent"] = c["mesh_parent"] if c["mesh_parent"] in parents else None
            if not d.get("vendor") and c.get("vendor"):
                d["vendor"] = c["vendor"]
            d["mesh_node"] = c["mac"] in parents
            self.save(d)
        self.rstate["last_clients"] = now
        self.notify()

    def _add_router_device(self) -> None:
        mac = discovery.norm_mac(self.info.get("label_mac") or "")
        if not mac:
            return
        d = self.observe(mac, self.info.get("lan_ipaddr"), "router", time.time())
        d.update(is_router=True, conn="wired", approved=True)
        if not d.get("label"):
            d["label"] = f"ASUS {self.info.get('productid') or 'router'}"
        d["group_manual"] = d.get("group_manual") or "network"
        self.save(d)

    async def router_loop(self) -> None:
        while True:
            if self.router_allowed():
                try:
                    await self.router_clients()
                    self._router_ok()
                except RouterError as e:
                    self._router_fail(e)
                except Exception as e:  # noqa: BLE001
                    log.exception("Router read failed")
                    self._router_fail(e)
            await asyncio.sleep(self.cfg["clients_seconds"])

    # ================================================================ scanning
    def _setup_scan(self) -> None:
        target = self.router_host or "192.168.50.1"
        if self.cfg["subnet"]:
            try:
                target = str(next(ipaddress.ip_network(self.cfg["subnet"], strict=False).hosts()))
            except (ValueError, StopIteration):
                pass
        self.local_ip = discovery.local_ip_towards(target)
        if self.local_ip:
            self.iface, self.local_mac = discovery.iface_for_ip(self.local_ip)
        sub = self.cfg["subnet"]
        if not sub and self.info.get("lan_ipaddr") and self.info.get("lan_netmask"):
            sub = f"{self.info['lan_ipaddr']}/{self.info['lan_netmask']}"
        if not sub and self.local_ip:
            sub = f"{self.local_ip}/24"
        try:
            self.subnet = ipaddress.ip_network(sub, strict=False) if sub else None
        except ValueError:
            self.subnet = None
        self.sstate["subnet"] = str(self.subnet) if self.subnet else None
        if self.subnet and self.subnet.num_addresses > discovery.MAX_HOSTS + 2:
            self.sstate["error"] = f"{self.subnet} is large; only the first {discovery.MAX_HOSTS} addresses are scanned."
        if not self.cfg["scan"]:
            self.sstate.update(enabled=False, error=None)
        elif not self.local_ip or not self.subnet or ipaddress.ip_address(self.local_ip) not in self.subnet:
            self.sstate.update(enabled=False, error=(
                "Scanning is off: this container isn't on the home network "
                f"(its address is {self.local_ip or 'unknown'}). Use network_mode: host. "
                "Devices still come from the router's list."))

    async def scan_loop(self) -> None:
        # Give the router a moment, so its subnet and the router device are known first
        for _ in range(20):
            if self.info or self.rstate["error"]:
                break
            await asyncio.sleep(1)
        self._setup_scan()
        if self.local_mac and self.local_ip and self.sstate["enabled"]:
            d = self.observe(self.local_mac, self.local_ip, "scan", time.time())
            d["is_self"] = True
            d["approved"] = True
            d["conn"] = d.get("conn") or "wired"
            d["group_manual"] = d.get("group_manual") or "servers"
            self.save(d)
        while True:
            if self.sstate["enabled"]:
                try:
                    await self.scan_once()
                    self.sstate["error"] = None if self.subnet.num_addresses <= discovery.MAX_HOSTS + 2 else self.sstate["error"]
                except Exception as e:  # noqa: BLE001
                    log.exception("Scan failed")
                    self.sstate["error"] = f"Scan failed: {e}"
            try:
                await self.enrich()
            except Exception:  # noqa: BLE001
                log.exception("Discovery failed")
            if not self.baseline and (self.rstate["last_clients"] or self.sstate["last"]):
                self.baseline = True
                self.store.set_meta("baseline_done", "1")
                self._event("baseline", None, f"First inventory done: {len(self.devices)} devices. "
                                              "New devices from now on raise alerts.")
            self.notify()
            await asyncio.sleep(self.cfg["scan_seconds"])

    async def scan_once(self) -> None:
        self.sstate["running"] = True
        try:
            skip = {self.local_ip} if self.local_ip else set()
            found = await discovery.sweep(self.subnet, self.iface, skip)
        finally:
            self.sstate["running"] = False
        now = time.time()
        for ip, mac in found.items():
            self.save(self.observe(mac, ip, "scan", now))
        if self.local_mac in self.devices:
            self.observe(self.local_mac, self.local_ip, "scan", now)
        self.sstate.update(last=now, found=len(found))

    async def enrich(self) -> None:
        """Names and service clues: cheap lookups for new/unnamed devices, multicast discovery every 15 min."""
        now = time.time()
        online = {d["ip"]: d for d in self.devices.values() if d.get("online") and d.get("ip")}
        if self.subnet:
            online = {ip: d for ip, d in online.items() if ipaddress.ip_address(ip) in self.subnet}
        stale = [ip for ip, d in online.items() if now - (d.get("enriched") or 0) > 6 * 3600]
        full = now - self.sstate["last_enrich"] > 900
        if not stale and not full:
            return
        dns_server = self.info.get("lan_ipaddr") or self.router_host
        tasks = {}
        if stale and dns_server:
            tasks["ptr"] = discovery.reverse_dns(stale, dns_server)
        if stale and self.cfg["netbios"]:
            tasks["netbios"] = discovery.netbios(stale)
        if full and self.cfg["mdns"] and self.sstate["enabled"]:
            unnamed = [ip for ip, d in online.items() if not (d.get("signals") or {}).get("mdns")]
            tasks["mdns"] = discovery.mdns(unnamed)
        if full and self.cfg["ssdp"] and self.sstate["enabled"] and self.subnet:
            tasks["ssdp"] = discovery.ssdp(self.subnet)
        results = dict(zip(tasks, await asyncio.gather(*tasks.values(), return_exceptions=True)))
        for key, res in results.items():
            if isinstance(res, Exception):
                log.warning("%s discovery failed: %s", key, res)
                continue
            for ip, val in res.items():
                d = online.get(ip)
                if d is not None:
                    d.setdefault("signals", {})[key] = val
        for ip in stale:
            online[ip]["enriched"] = now
        if self.cfg["port_probe"]:
            for ip in stale:
                d = online[ip]
                if "ports" not in d.get("signals", {}):
                    d["signals"]["ports"] = await discovery.port_probe(ip)
        if full:
            self.sstate["last_enrich"] = now
        for d in online.values():
            self.save(d)

    async def probe_now(self, mac: str) -> list[int]:
        d = self.devices[mac]
        if not d.get("ip"):
            return []
        d.setdefault("signals", {})["ports"] = await discovery.port_probe(d["ip"])
        self.save(d)
        return d["signals"]["ports"]

    async def offline_loop(self) -> None:
        n = 0
        while True:
            await asyncio.sleep(30)
            now = time.time()
            changed = False
            for d in self.devices.values():
                if d.get("is_router") and self.rstate["ok"]:
                    d["last_seen"] = now
                    continue
                if d.get("online") and now - (d.get("last_seen") or 0) > self.cfg["offline_after"]:
                    d["online"] = False
                    self._event("offline", d["mac"], f"{display_name(d)} went offline")
                    self.store.save_device(d)
                    changed = True
            if changed:
                self.notify()
            n += 1
            if n % 2880 == 0:
                self.store.prune(self.cfg["keep_days"])

    # ================================================================ live traffic
    async def traffic_loop(self) -> None:
        while True:
            if time.time() - self.viewer_ts < self.cfg["idle_traffic_seconds"] and self.router_allowed():
                try:
                    await self.sample_traffic()
                    self._router_ok()
                except RouterError as e:
                    self._router_fail(e)
                except Exception as e:  # noqa: BLE001
                    log.exception("Traffic read failed")
                    self._router_fail(e)
                await asyncio.sleep(self.cfg["live_seconds"])
            else:
                self._prev_nd = self._prev_tr = None
                await asyncio.sleep(1)

    def _hub(self, iface: str) -> str | None:
        if iface == "INTERNET":
            return "wan"
        if iface == "WIRED":
            return "wired"
        if iface.startswith("WIRELESS") and iface[8:].isdigit():
            return band_name(str(int(iface[8:]) + 1), self.info.get("productid") or "")
        return None

    async def sample_traffic(self) -> None:
        now = time.time()
        nd = await self.router.netdev()
        ifaces = {}
        if self._prev_nd:
            t0, prev = self._prev_nd
            dt = max(now - t0, 0.5)
            for name, cur in nd.items():
                hub = self._hub(name)
                if not hub or name not in prev:
                    continue
                rx = _delta(prev[name].get("rx"), cur.get("rx")) * 8 / dt
                tx = _delta(prev[name].get("tx"), cur.get("tx")) * 8 / dt
                # WAN: rx is download. LAN/Wi-Fi: the router transmits what devices download.
                ifaces[hub] = {"down": rx, "up": tx} if hub == "wan" else {"down": tx, "up": rx}
        self._prev_nd = (now, nd)
        devices = {}
        mode = self.cfg["device_traffic"]
        state = self.live.get("device_traffic")
        if mode != "off" and (state != "unavailable" or now >= self._tr_retry):
            try:
                tr = await self.router.traffic()
                if not tr:
                    raise RouterError("empty")
                if self._prev_tr:
                    t0, prev = self._prev_tr
                    dt = max(now - t0, 0.5)
                    for mac, (tx, rx) in tr.items():
                        if mac in prev:
                            devices[mac] = {"down": _delta(prev[mac][0], tx) * 8 / dt,
                                            "up": _delta(prev[mac][1], rx) * 8 / dt}
                self._prev_tr = (now, tr)
                state, self._tr_fails = "on", 0
            except (RouterError, ValueError) as e:
                if isinstance(e, (AuthError, CertChanged, LockedOut)):
                    raise
                self._tr_fails += 1
                if self._tr_fails >= 2 or mode == "auto":
                    state = "unavailable"
                    self._tr_retry = now + 600
                    self._prev_tr = None
        else:
            state = "off" if mode == "off" else state
        self.live = {"ts": now, "ifaces": ifaces, "devices": devices, "device_traffic": state}

    # ================================================================ lifecycle
    async def run(self) -> None:
        await asyncio.gather(self.router_loop(), self.scan_loop(), self.offline_loop(), self.traffic_loop())

    async def close(self) -> None:
        await self.router.logout()
        if self._alert_session:
            await self._alert_session.close()

    def pause_router(self, minutes: int) -> None:
        self.rstate["paused_until"] = time.time() + minutes * 60
        asyncio.get_event_loop().create_task(self.router.logout())

    def resume_router(self) -> None:
        self.rstate.update(paused_until=0.0, next_try=0.0)

    def trust_cert(self) -> str | None:
        got = self.rstate.get("cert_pending")
        if not got or self.router.pin_fixed:
            return None
        self.router.pin = got
        self.store.set_meta("router_cert", got)
        self.rstate.update(cert_pending=None, next_try=0.0, error=None)
        self._event("cert", None, f"Trusted the router's new certificate {fmt_fp(got)}")
        return got


def _delta(a, b) -> float:
    if a is None or b is None:
        return 0.0
    d = b - a
    if d < 0:
        d += 2 ** 32 if a < 2 ** 32 else 2 ** 64  # counter wrapped
        if d > 2 ** 31:  # more likely the counter was reset (router reboot)
            return 0.0
    return float(d)
