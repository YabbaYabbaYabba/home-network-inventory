"""Checks for parsing, classification and the router client (against the fake router).

    python -m pytest tests          # or: python tests/test_inventory.py
"""

import asyncio
import os
import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from aiohttp import web  # noqa: E402

from app import asus, dnsmsg  # noqa: E402
from app.classify import classify  # noqa: E402
from app.discovery import is_random_mac, norm_mac  # noqa: E402


# ---------------------------------------------------------------- parsing

def test_trailing_comma_json():
    assert asus.parse_json('{"productid":"RT-AXDEMO",}') == {"productid": "RT-AXDEMO"}


def test_clientlist():
    data = {"get_clientlist": {
        "AA:BB:CC:00:11:22": {"mac": "AA:BB:CC:00:11:22", "name": "iPhone", "nickName": "My phone",
                              "ip": "192.168.50.10", "isWL": "2", "isOnline": "1", "rssi": "-51",
                              "curTx": "866", "curRx": "", "vendor": "Apple", "amesh_papMac": ""},
        "maclist": ["AA:BB:CC:00:11:22"], "ClientAPILevel": "2"}}
    (c,) = asus.parse_clientlist(data)
    assert c["name"] == "My phone" and c["router_name"] == "iPhone"
    assert c["conn"] == "5 GHz" and c["online"] and c["rssi"] == -51 and c["link_tx"] == 866.0
    assert c["link_rx"] is None


def test_band_names():
    assert asus.band_name("0") == "wired"
    assert asus.band_name("3", "RT-AXDEMO") == "5 GHz-2"
    assert asus.band_name("3", "GT-AXE11000") == "6 GHz"


def test_netdev_and_traffic():
    nd = asus.parse_netdev({"netdev": {"INTERNET_rx": "0x10", "INTERNET_tx": "0x20", "WIRED_rx": "5", "junk": "x"}})
    assert nd == {"INTERNET": {"rx": 16, "tx": 32}, "WIRED": {"rx": 5}}
    tr = asus.parse_traffic('array_statistics = [["aa:bb:cc:dd:ee:ff", "100", "200"], [\'11:22:33:44:55:66\', 1, 2]];')
    assert tr == {"AA:BB:CC:DD:EE:FF": (100, 200), "11:22:33:44:55:66": (1, 2)}


def test_counter_delta():
    from app.inventory import _delta
    assert _delta(100, 150) == 50
    assert _delta(2 ** 32 - 10, 5) == 15          # 32-bit wrap
    assert _delta(10 ** 12, 100) == 0             # reset after a reboot


def test_macs():
    assert norm_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"
    assert norm_mac("00:00:00:00:00:00") is None
    assert is_random_mac("DA:A1:19:5C:3E:01") and not is_random_mac("3C:22:FB:10:20:30")


# ---------------------------------------------------------------- DNS / NetBIOS

def _answer(qname: str, rtype: int, rdata: bytes) -> bytes:
    hdr = struct.pack("!HHHHHH", 7, 0x8400, 0, 1, 0, 0)
    return hdr + dnsmsg.encode_name(qname) + struct.pack("!HHIH", rtype, 1, 120, len(rdata)) + rdata


def test_dns_parse():
    pkt = _answer("10.50.168.192.in-addr.arpa", dnsmsg.PTR, dnsmsg.encode_name("nas.lan"))
    rec = dnsmsg.parse(pkt)["records"][0]
    assert rec["data"] == "nas.lan"
    txt = bytes([7]) + b"md=Echo" + bytes([4]) + b"flag"
    rec = dnsmsg.parse(_answer("x._googlecast._tcp.local", dnsmsg.TXT, txt))["records"][0]
    assert rec["data"] == {"md": "Echo", "flag": ""}


def test_dns_pointer_loop_is_rejected():
    hdr = struct.pack("!HHHHHH", 1, 0, 0, 1, 0, 0)
    try:
        dnsmsg.parse(hdr + b"\xc0\x0c")  # pointer to itself
    except ValueError:
        return
    raise AssertionError("loop not detected")


def test_nbstat():
    name = b"DESKTOP-7K2Q9LP".ljust(15) + b"\x00" + struct.pack("!H", 0x0400)
    group = b"WORKGROUP".ljust(15) + b"\x00" + struct.pack("!H", 0x8400)
    rdata = bytes([2]) + group + name + b"\0" * 6
    pkt = struct.pack("!HHHHHH", 5, 0x8400, 0, 1, 0, 0) + dnsmsg.NBSTAT_NAME + \
        struct.pack("!HHIH", 0x21, 1, 0, len(rdata)) + rdata
    assert dnsmsg.parse_nbstat(pkt) == "DESKTOP-7K2Q9LP"


# ---------------------------------------------------------------- classification

def dev(name="", vendor="", conn="wired", mac="00:11:22:33:44:55", **signals):
    return {"mac": mac, "vendor": vendor, "conn": conn, "random_mac": is_random_mac(mac),
            "signals": {"router": {"name": name, "conn": conn}, **signals}}


def test_classify_examples():
    cases = [
        (dev("NAS-1", "Synology Incorporated"), "servers"),
        (dev("MacBook-Pro", "Apple, Inc.", "5 GHz"), "computers"),
        (dev("iPhone", "", "5 GHz", mac="DA:A1:19:5C:3E:01"), "phones"),
        (dev("", "", "5 GHz", mac="DA:A1:19:5C:3E:01"), "phones"),
        (dev("", "Espressif Inc.", "2.4 GHz"), "smarthome"),
        (dev("BRW008077112233", "Brother industries, LTD.", "5 GHz"), "printers"),
        (dev("Reolink-Garden", "Reolink Innovation Limited", "2.4 GHz"), "cameras"),
        (dev("", "Google, Inc.", "5 GHz", mdns={"services": ["_googlecast._tcp"], "txt": {"md": "Chromecast"}}), "media"),
        (dev("", "Google, Inc.", "5 GHz", mdns={"services": ["_googlecast._tcp"], "txt": {"md": "Google Nest Mini"}},
             ), "media"),
        (dev("", "", "wired", mdns={"services": ["_ipp._tcp"]}), "printers"),
        (dev("", "", "5 GHz", mdns={"services": ["_hap._tcp"]}), "smarthome"),
        (dev("", "Apple, Inc.", "wired", mdns={"services": ["_airplay._tcp"], "txt": {"model": "AppleTV14,1"}}), "media"),
        (dev("mystery"), "unknown"),
    ]
    for d, want in cases:
        got = classify(d)
        assert got["group"] == want, (d["signals"]["router"]["name"], d["vendor"], got)
    assert classify(cases[11][0])["kind"] == "Apple TV"


# ---------------------------------------------------------------- router client vs. fake router

async def _with_fake(fn, tls=False):
    import fake_asus
    fake_asus.STATS.update(logins=0, bad_logins=0, requests=0)
    fake_asus.TOKENS.clear()
    runner = web.AppRunner(fake_asus.make_app())
    await runner.setup()
    ctx = fake_asus.self_signed() if tls else None
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=ctx)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        await fn(f"{'https' if tls else 'http'}://127.0.0.1:{port}", fake_asus)
    finally:
        await runner.cleanup()


def test_router_session_reuse_and_relogin():
    async def body(url, fake):
        r = asus.AsusRouter(url, "admin", "pw")
        info = await r.info()
        assert info["productid"] == "RT-AXDEMO"
        clients = await r.clients()
        assert len(clients) >= 20
        await r.netdev()
        assert len(await r.traffic()) >= 20
        assert fake.STATS["logins"] == 1               # one login, token reused
        fake.TOKENS.clear()                            # router drops the session
        await r.clients()
        assert fake.STATS["logins"] == 2               # logged in again once
        await r.logout()
    asyncio.run(_with_fake(body))


def test_wrong_password_is_not_retried():
    async def body(url, fake):
        r = asus.AsusRouter(url, "admin", "wrong")
        try:
            await r.clients()
        except asus.AuthError as e:
            assert "Wrong router username or password" in str(e)
        else:
            raise AssertionError("expected AuthError")
        assert fake.STATS["logins"] == 1
        await r.logout()
    asyncio.run(_with_fake(body))


def test_certificate_pinning():
    async def body(url, fake):
        saved = {}
        r = asus.AsusRouter(url, "admin", "pw", on_pin=lambda p: saved.setdefault("pin", p))
        await r.info()
        assert len(saved["pin"]) == 64                  # trusted on first use
        await r.logout()
        bad = asus.AsusRouter(url, "admin", "pw", saved_pin="00" * 32)
        try:
            await bad.info()
        except asus.CertChanged as e:
            assert e.got == saved["pin"]
        else:
            raise AssertionError("a changed certificate must be refused")
        await bad.logout()
    asyncio.run(_with_fake(body, tls=True))


def test_inventory_end_to_end():
    async def body(url, fake):
        from app.inventory import Inventory
        from app.store import Store
        cfg = {"router_url": url, "router_user": "admin", "router_password": "pw", "router_cert_sha256": "",
               "device_traffic": "auto", "scan": False, "netbios": False, "mdns": False, "ssdp": False,
               "port_probe": False, "subnet": "", "alert_webhook": "", "offline_after": 600, "keep_days": 30,
               "clients_seconds": 60, "scan_seconds": 120, "live_seconds": 3, "idle_traffic_seconds": 60}
        with tempfile.TemporaryDirectory() as d:
            inv = Inventory(Store(Path(d) / "t.db"), cfg)
            await inv.router_clients()
            assert any(x.get("is_router") for x in inv.devices.values())
            mesh = inv.devices[fake.MESH_MAC]
            assert mesh["mesh_node"] and inv.group_of(mesh) == "network"
            assert inv.devices["6E:4B:7C:21:90:AA"]["mesh_parent"] == fake.MESH_MAC
            await inv.sample_traffic()
            await asyncio.sleep(1.1)
            await inv.sample_traffic()
            assert inv.live["ifaces"]["wan"]["down"] > 0
            assert inv.live["device_traffic"] == "on" and inv.live["devices"]
            # manual group wins, and survives a reload
            inv.update_device(fake.P + "10", {"group": "computers", "label": "Backup box"})
            again = Inventory(Store(Path(d) / "t.db"), cfg)
            dd = again.devices[fake.P + "10"]
            assert again.group_of(dd) == "computers" and dd["label"] == "Backup box"
            await inv.close()
            await again.close()
    asyncio.run(_with_fake(body))


if __name__ == "__main__":
    fails = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("ok  ", name)
            except Exception as e:  # noqa: BLE001
                fails += 1
                print("FAIL", name, repr(e))
    sys.exit(1 if fails else 0)
