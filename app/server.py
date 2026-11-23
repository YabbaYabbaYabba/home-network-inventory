"""Home Network Inventory: web app and API.

Run:  python -m app.server   (settings come from environment variables / .env)
"""

from __future__ import annotations

import asyncio
import base64
import csv
import hmac
import io
import json
import logging
import time

from aiohttp import web

from .asus import RouterError, fmt_fp
from .classify import GROUPS, GROUP_IDS
from .config import BASE, CFG
from .inventory import Inventory
from .store import Store

STATIC = BASE / "static"
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logging.getLogger("aiohttp.access").setLevel(logging.WARNING)
log = logging.getLogger("server")

PUBLIC = {"/manifest.webmanifest", "/icon-192.png", "/icon-512.png", "/apple-touch-icon.png", "/healthz"}


@web.middleware
async def security(request: web.Request, handler):
    pw = CFG["app_password"]
    if pw and request.path not in PUBLIC:
        ok = False
        h = request.headers.get("Authorization", "")
        if h.startswith("Basic "):
            try:
                _, given = base64.b64decode(h[6:]).decode().split(":", 1)
                ok = hmac.compare_digest(given.encode(), pw.encode())
            except Exception:  # noqa: BLE001
                ok = False
        if not ok:
            return web.Response(status=401, headers={"WWW-Authenticate": 'Basic realm="Network Inventory"'})
    if request.method not in ("GET", "HEAD"):
        # Cross-site request protection: browsers can't add this header to a cross-site form post
        # without a CORS preflight, which this server never approves.
        if request.headers.get("X-Requested-With") != "inventory":
            return web.json_response({"error": "Missing X-Requested-With header"}, status=403)
        origin = request.headers.get("Origin")
        if origin and origin.split("://", 1)[-1] != request.host:
            return web.json_response({"error": "Cross-origin request refused"}, status=403)
    resp = await handler(request)
    resp.headers.update({
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "X-Frame-Options": "DENY",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; "
                                   "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
                                   "form-action 'self'; base-uri 'none'",
    })
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


def inv(request: web.Request) -> Inventory:
    return request.app["inv"]


PUBLIC_FIELDS = ("mac", "ip", "online", "first_seen", "last_seen", "vendor", "random_mac", "conn", "label",
                 "notes", "approved", "group_manual", "auto", "model", "name", "mesh_parent", "mesh_node",
                 "is_router", "is_self", "maybe_same")


def device_json(i: Inventory, d: dict, full: bool = False) -> dict:
    out = {k: d.get(k) for k in PUBLIC_FIELDS}
    out["group"] = i.group_of(d)
    r = (d.get("signals") or {}).get("router") or {}
    out.update(rssi=r.get("rssi"), link_tx=r.get("link_tx"), link_rx=r.get("link_rx"),
               seen=d.get("seen") or {})
    if full:
        out["signals"] = d.get("signals") or {}
        out["ips"] = i.store.ip_history(d["mac"])
        out["events"] = i.store.events(30, d["mac"])
    return out


def router_json(i: Inventory) -> dict:
    r = dict(i.rstate)
    r["url"] = CFG["router_url"]
    r["model"] = i.info.get("productid")
    fw = ".".join(x for x in (i.info.get("firmver"), i.info.get("buildno")) if x)
    r["firmware"] = (fw + ("_" + i.info["extendno"] if i.info.get("extendno") else "")) or None
    r["cert"] = fmt_fp(i.router.pin) if i.router.pin else None
    r["cert_pending"] = fmt_fp(r["cert_pending"]) if r["cert_pending"] else None
    r["cert_fixed"] = bool(i.router.pin_fixed)
    r["paused"] = time.time() < r["paused_until"]
    return r


async def h_state(request: web.Request):
    i = inv(request)
    since = request.query.get("v")
    if since and since == str(i.version):
        return web.json_response({"version": i.version, "unchanged": True,
                                  "router": router_json(i), "scan": i.sstate})
    devs = [device_json(i, d) for d in i.devices.values()]
    return web.json_response({
        "version": i.version,
        "now": time.time(),
        "groups": [{"id": g, "label": l, "color": c, "icon": ic} for g, l, c, ic in GROUPS],
        "devices": devs,
        "router": router_json(i),
        "scan": i.sstate,
        "baseline": i.baseline,
        "events": i.store.events(150),
        "settings": {k: CFG[k] for k in ("scan_seconds", "clients_seconds", "offline_after", "port_probe",
                                         "mdns", "ssdp", "netbios", "device_traffic", "live_seconds")}
                    | {"alerts": bool(CFG["alert_webhook"])},
    })


async def h_device(request: web.Request):
    i = inv(request)
    d = i.devices.get(request.match_info["mac"].upper())
    if not d:
        raise web.HTTPNotFound()
    return web.json_response(device_json(i, d, full=True))


async def _body(request: web.Request) -> dict:
    try:
        b = await request.json()
        return b if isinstance(b, dict) else {}
    except (ValueError, UnicodeDecodeError):
        return {}


async def h_update(request: web.Request):
    i = inv(request)
    mac = request.match_info["mac"].upper()
    if mac not in i.devices:
        raise web.HTTPNotFound()
    body = await _body(request)
    if "group" in body and body["group"] not in GROUP_IDS + [None, "", "auto"]:
        return web.json_response({"error": "Unknown group"}, status=400)
    d = i.update_device(mac, {k: v for k, v in body.items() if k in ("label", "group", "notes", "approved")})
    return web.json_response(device_json(i, d, full=True))


async def h_forget(request: web.Request):
    i = inv(request)
    i.forget(request.match_info["mac"].upper())
    i.notify()
    return web.json_response({"ok": True})


async def h_probe(request: web.Request):
    i = inv(request)
    mac = request.match_info["mac"].upper()
    if mac not in i.devices:
        raise web.HTTPNotFound()
    ports = await i.probe_now(mac)
    i.notify()
    return web.json_response({"ports": ports})


async def h_approve_all(request: web.Request):
    i = inv(request)
    n = i.approve_all()
    i.notify()
    return web.json_response({"approved": n})


async def h_live(request: web.Request):
    i = inv(request)
    i.viewer_ts = time.time()
    return web.json_response({**i.live, "router_ok": i.rstate["ok"], "paused": time.time() < i.rstate["paused_until"]})


async def h_router(request: web.Request):
    i = inv(request)
    body = await _body(request)
    action = body.get("action")
    if action == "pause":
        i.pause_router(max(1, min(int(body.get("minutes") or 15), 240)))
    elif action == "resume":
        i.resume_router()
    elif action == "trust_cert":
        if not i.trust_cert():
            return web.json_response({"error": "No new certificate to trust (or it is fixed in .env)."}, status=400)
    elif action == "scan":
        if i.sstate["enabled"] and not i.sstate["running"]:
            asyncio.get_event_loop().create_task(_scan_now(i))
    else:
        return web.json_response({"error": "Unknown action"}, status=400)
    return web.json_response({"router": router_json(i), "scan": i.sstate})


async def _scan_now(i: Inventory) -> None:
    try:
        await i.scan_once()
        i.sstate["last_enrich"] = 0
        await i.enrich()
    finally:
        i.notify()


CSV_COLS = ["name", "group", "kind", "model", "ip", "mac", "random_mac", "vendor", "conn", "online",
            "approved", "first_seen", "last_seen", "notes"]


async def h_export(request: web.Request):
    i = inv(request)
    fmt = request.match_info["fmt"]
    devs = [device_json(i, d) for d in sorted(i.devices.values(), key=lambda d: (i.group_of(d), d.get("name") or ""))]
    if fmt == "json":
        return web.Response(text=json.dumps(devs, indent=2), content_type="application/json",
                            headers={"Content-Disposition": 'attachment; filename="network-inventory.json"'})
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_COLS)
    for d in devs:
        row = []
        for c in CSV_COLS:
            v = (d.get("auto") or {}).get("kind") if c == "kind" else d.get(c)
            if c in ("first_seen", "last_seen") and v:
                v = time.strftime("%Y-%m-%d %H:%M", time.localtime(v))
            s = "" if v is None else str(v)
            if s[:1] in ("=", "+", "-", "@"):
                s = "'" + s  # stop spreadsheet formula injection from device-supplied names
            row.append(s)
        w.writerow(row)
    return web.Response(text=buf.getvalue(), content_type="text/csv",
                        headers={"Content-Disposition": 'attachment; filename="network-inventory.csv"'})


async def h_debug(request: web.Request):
    if not CFG["debug"]:
        raise web.HTTPNotFound()
    i = inv(request)
    what = request.query.get("hook", "get_clientlist()")
    try:
        text = await i.router.raw(what)
    except RouterError as e:
        return web.Response(text=str(e), status=502)
    return web.Response(text=text, content_type="text/plain")


async def h_index(_):
    return web.FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})


async def h_health(_):
    return web.Response(text="ok")


async def on_start(app: web.Application):
    app["task"] = asyncio.create_task(app["inv"].run())


async def on_stop(app: web.Application):
    app["task"].cancel()
    await app["inv"].close()  # log out of the router so the admin session is free


def make_app() -> web.Application:
    if not CFG["router_password"]:
        log.warning("ROUTER_PASSWORD is not set; the router's client list and traffic won't be read.")
    app = web.Application(middlewares=[security], client_max_size=64 * 1024)
    app["inv"] = Inventory(Store(CFG["data"] / "inventory.db"), CFG)
    r = app.router
    r.add_get("/", h_index)
    r.add_get("/healthz", h_health)
    r.add_get("/api/state", h_state)
    r.add_get("/api/live", h_live)
    r.add_get("/api/device/{mac}", h_device)
    r.add_post("/api/device/{mac}", h_update)
    r.add_post("/api/device/{mac}/forget", h_forget)
    r.add_post("/api/device/{mac}/probe", h_probe)
    r.add_post("/api/approve-all", h_approve_all)
    r.add_post("/api/router", h_router)
    r.add_get("/api/export.{fmt:csv|json}", h_export)
    r.add_get("/api/debug/router", h_debug)
    r.add_static("/", STATIC, show_index=False, append_version=False)
    return app


if __name__ == "__main__":
    log.info("Network Inventory on port %s, router %s", CFG["port"], CFG["router_url"])
    app = make_app()
    app.on_startup.append(on_start)
    app.on_cleanup.append(on_stop)
    web.run_app(app, port=CFG["port"], access_log=None)
