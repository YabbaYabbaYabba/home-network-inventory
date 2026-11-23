"""A fake stock-firmware ASUS router, for trying the app without the real one.

    python tests/fake_asus.py                     # http://127.0.0.1:8443
    FAKE_TLS=1 python tests/fake_asus.py          # https with a throwaway self-signed certificate
    ROUTER_URL=http://127.0.0.1:8443 ROUTER_PASSWORD=pw SCAN=0 python -m app.server

It serves a generic home network of about 25 devices, an AiMesh node, moving traffic counters, and
a new device that joins NEW_AFTER seconds after start (default 90).
"""

import base64
import json
import os
import random
import secrets
import ssl
import subprocess
import sys
import tempfile
import time

from aiohttp import web

START = time.time()
USER, PASSWORD = os.environ.get("FAKE_USER", "admin"), os.environ.get("FAKE_PASSWORD", "pw")
NEW_AFTER = int(os.environ.get("NEW_AFTER", "90"))
TRAFFIC = os.environ.get("FAKE_TRAFFIC", "1") == "1"  # 0 = like Traffic Analyzer turned off
TOKENS: set[str] = set()
STATS = {"logins": 0, "bad_logins": 0, "requests": 0}
# Generic demo data. 10:1D:42 is not a registered vendor prefix, so no brand names appear.
ROUTER_MAC = "10:1D:42:00:00:01"
MESH_MAC = "10:1D:42:00:00:02"
P = "10:1D:42:00:01:"

# mac, name, vendor (as the router shows it), isWL (0 wired, 1 2.4G, 2 5G), ip suffix, typical Mbps
DEVICES = [
    (MESH_MAC, "Mesh-Node-1", "", "0", 2, 0),
    (P + "10", "NAS-1", "", "0", 10, 6),
    (P + "11", "Server-1", "", "0", 11, 0.2),
    (P + "20", "Laptop-1", "", "2", 20, 18),
    (P + "21", "Laptop-2", "", "2", 21, 3),
    (P + "22", "Desktop-1", "", "0", 22, 25),
    ("DA:A1:19:5C:3E:01", "Phone-1", "", "2", 30, 2),
    ("6E:4B:7C:21:90:AA", "Phone-2", "", "2", 31, 5),
    ("A6:21:0F:88:12:34", "Tablet-1", "", "2", 32, 8),
    ("AE:21:0F:88:12:35", "Tablet-2", "", "2", 33, 0),
    (P + "40", "TV-1", "", "2", 40, 22),
    (P + "41", "TV-2", "", "0", 41, 0.5),
    (P + "42", "Soundbar-1", "", "2", 42, 0.3),
    (P + "43", "Console-1", "", "0", 43, 0.1),
    (P + "50", "Smart-Plug-1", "", "1", 50, 0.01),
    (P + "51", "Smart-Plug-2", "", "1", 51, 0.01),
    (P + "52", "Bulb-1", "", "1", 52, 0.01),
    (P + "53", "Thermostat-1", "", "1", 53, 0.02),
    (P + "54", "Sensor-1", "", "1", 54, 0.01),
    (P + "55", "Hub-1", "", "0", 55, 0.01),
    (P + "60", "Camera-1", "", "1", 60, 2.5),
    (P + "61", "Camera-2", "", "0", 61, 3),
    (P + "62", "Doorbell-1", "", "1", 62, 1.5),
    (P + "70", "Printer-1", "", "2", 70, 0),
    (P + "80", "", "", "0", 80, 0),
]
NEWCOMER = ("E2:11:4F:9A:00:01", "", "", "2", 199, 0.5)
OFFLINE = {"AE:21:0F:88:12:35"}  # in the router's history but switched off
BEHIND_MESH = {"6E:4B:7C:21:90:AA", P + "60", P + "70"}

COUNTERS: dict = {}


def devices():
    out = list(DEVICES)
    if time.time() - START > NEW_AFTER:
        out.append(NEWCOMER)
    return out


def clientlist():
    cl = {}
    for mac, name, vendor, wl, ip, _ in devices():
        cl[mac] = {
            "type": "0", "defaultType": "0", "name": name, "nickName": "", "ip": f"192.168.50.{ip}",
            "mac": mac, "from": "networkmapd", "macRepeat": "0", "isGateway": "0", "isWebServer": "0",
            "isPrinter": "0", "isITunes": "0", "dpiType": "", "dpiDevice": "", "vendor": vendor,
            "isWL": wl, "isGN": "", "isOnline": "0" if mac in OFFLINE else "1", "ssid": "",
            "isLogin": "0", "opMode": "0", "rssi": str(-40 - random.randint(0, 35)) if wl != "0" else "0",
            "curTx": str(random.choice([144, 286, 573, 866, 1201])) if wl != "0" else "",
            "curRx": str(random.choice([72, 144, 286, 573])) if wl != "0" else "",
            "totalTx": "", "totalRx": "", "wlConnectTime": "", "ipMethod": "DHCP", "ROG": "0",
            "group": "", "callback": "", "keeparp": "", "qosLevel": "", "wtfast": "0",
            "internetMode": "allow", "internetState": "1",
            "amesh_isReClient": "1" if mac in BEHIND_MESH else "0",
            "amesh_papMac": MESH_MAC if mac in BEHIND_MESH else ROUTER_MAC,
        }
    cl["maclist"] = list(cl)
    cl["ClientAPILevel"] = "2"
    return {"get_clientlist": cl}


def tick_counters():
    now = time.time()
    last = COUNTERS.get("_t", now)
    dt = now - last
    COUNTERS["_t"] = now
    wobble = lambda base: max(0.0, base * random.uniform(0.3, 1.8))  # noqa: E731
    tot = {"INTERNET": [0, 0], "WIRED": [0, 0], "WIRELESS0": [0, 0], "WIRELESS1": [0, 0]}
    for mac, _, _, wl, _, mbps in devices():
        if mac in OFFLINE:
            continue
        down = wobble(mbps) * 1e6 / 8 * dt
        up = down * random.uniform(0.05, 0.3)
        c = COUNTERS.setdefault(mac, [random.randint(10**8, 10**10), random.randint(10**7, 10**9)])
        c[0] += int(down)
        c[1] += int(up)
        iface = {"0": "WIRED", "1": "WIRELESS0", "2": "WIRELESS1"}[wl]
        tot[iface][0] += down
        tot[iface][1] += up
        tot["INTERNET"][0] += down * 0.8
        tot["INTERNET"][1] += up * 0.8
    for k, (d, u) in tot.items():
        c = COUNTERS.setdefault(k, [random.randint(10**9, 10**11), random.randint(10**8, 10**10)])
        if k == "INTERNET":
            c[0] += int(d)
            c[1] += int(u)
        else:  # router tx = what clients download
            c[0] += int(u)
            c[1] += int(d)


def netdev():
    tick_counters()
    nd = {}
    for k in ("INTERNET", "WIRED", "WIRELESS0", "WIRELESS1", "BRIDGE"):
        rx, tx = COUNTERS.get(k, [0, 0])
        nd[f"{k}_rx"] = hex(rx)
        nd[f"{k}_tx"] = hex(tx)
    return {"netdev": nd}


def authed(request) -> bool:
    cookie = request.headers.get("Cookie", "")
    return any(f"asus_token={t}" in cookie for t in TOKENS)


LOGOUT_PAGE = "<html><script>top.location.href='/Main_Login.asp';</script></html>"


async def login(request):
    STATS["logins"] += 1
    form = await request.post()
    try:
        user, pw = base64.b64decode(form.get("login_authorization", "")).decode().split(":", 1)
    except Exception:  # noqa: BLE001
        user = pw = ""
    if (user, pw) != (USER, PASSWORD):
        STATS["bad_logins"] += 1
        if STATS["bad_logins"] >= 5:
            return web.json_response({"error_status": "7", "remaining_lock_time": "300"})
        return web.json_response({"error_status": "3"})
    tok = secrets.token_hex(16)
    TOKENS.clear()  # one admin session at a time, like the real thing
    TOKENS.add(tok)
    return web.json_response({"asus_token": tok}, headers={"Set-Cookie": f"asus_token={tok}; HttpOnly;"})


async def appget(request):
    STATS["requests"] += 1
    if not authed(request):
        return web.Response(text=LOGOUT_PAGE, content_type="text/html")
    hook = (await request.post()).get("hook", "")
    if hook == "get_clientlist()":
        return web.Response(text=json.dumps(clientlist()), content_type="application/json")
    if hook == "netdev(appobj)":
        return web.Response(text=json.dumps(netdev()), content_type="application/json")
    if hook.startswith("nvram_get("):
        vals = {"productid": "RT-AXDEMO", "firmver": "3.0.0.6", "buildno": "102_34372",
                "extendno": "0-g1a2b3c", "lan_ipaddr": "192.168.50.1", "lan_netmask": "255.255.255.0",
                "label_mac": ROUTER_MAC}
        keys = [h[len("nvram_get("):-1] for h in hook.split(";")]
        # trailing comma, as some firmware sends
        return web.Response(text="{" + ",".join(f'"{k}":"{vals.get(k, "")}"' for k in keys) + ",}",
                            content_type="application/json")
    return web.json_response({})


async def gettraffic(request):
    if not authed(request):
        return web.Response(text=LOGOUT_PAGE, content_type="text/html")
    if not TRAFFIC:
        return web.Response(status=404)
    rows = ",".join(f'["{m}", "{COUNTERS[m][0]}", "{COUNTERS[m][1]}"]'
                    for m, *_ in devices() if m in COUNTERS)
    return web.Response(text=f"router_traffic = [];\narray_statistics = [{rows}];\n",
                        content_type="application/javascript")


async def logout(request):
    TOKENS.clear()
    return web.Response(text="ok")


async def stats(_):
    return web.json_response(STATS)


def make_app():
    app = web.Application()
    app.router.add_post("/login.cgi", login)
    app.router.add_post("/appGet.cgi", appget)
    app.router.add_get("/getTraffic.asp", gettraffic)
    app.router.add_get("/Logout.asp", logout)
    app.router.add_get("/_stats", stats)
    return app


def self_signed() -> ssl.SSLContext:
    d = tempfile.mkdtemp()
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                    "-subj", "/CN=router.asus.com", "-keyout", f"{d}/k.pem", "-out", f"{d}/c.pem"],
                   check=True, capture_output=True)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(f"{d}/c.pem", f"{d}/k.pem")
    return ctx


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8443
    tls = self_signed() if os.environ.get("FAKE_TLS") == "1" else None
    web.run_app(make_app(), host="127.0.0.1", port=port, ssl_context=tls, access_log=None)
