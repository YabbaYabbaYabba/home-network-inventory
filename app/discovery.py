"""Finding devices on the LAN, and learning what they are.

Everything here runs as an ordinary user with no extra privileges:

* Presence: a tiny UDP datagram to every address makes the NAS's kernel resolve it with ARP.
  The kernel's neighbour table then lists every address that answered, with its MAC.
  (No raw sockets, so the container needs no NET_RAW / NET_ADMIN capability.)
* Names and types: reverse DNS on the router, mDNS/Bonjour, SSDP/UPnP and NetBIOS replies.
* Optional: a short TCP connect check of a few well-known ports (off by default).

All replies are treated as untrusted input: sizes are capped and parsing never executes anything.
"""

from __future__ import annotations

import asyncio
import fcntl
import ipaddress
import json
import logging
import random
import re
import select
import shutil
import socket
import struct
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit

import aiohttp

from . import dnsmsg

log = logging.getLogger("discovery")

MAX_HOSTS = 1024
LIVE_STATES = {"REACHABLE", "DELAY", "PROBE", "PERMANENT", "NOARP"}
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", re.I)


def norm_mac(mac: str) -> str | None:
    mac = (mac or "").strip().upper().replace("-", ":")
    if not MAC_RE.match(mac) or mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
        return None
    return mac


def is_random_mac(mac: str) -> bool:
    """Locally administered address: phones and laptops use these for "private Wi-Fi address"."""
    try:
        return bool(int(mac[1], 16) & 0x2)
    except (ValueError, IndexError):
        return False


# ---------------------------------------------------------------- local interface

def local_ip_towards(ip: str) -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((ip, 9))
            return s.getsockname()[0]
    except OSError:
        return None


def iface_for_ip(ip: str) -> tuple[str | None, str | None]:
    """(interface name, MAC) that owns `ip`, read from /sys and SIOCGIFADDR."""
    for p in Path("/sys/class/net").glob("*"):
        name = p.name
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                res = fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", name[:15].encode()))
            if socket.inet_ntoa(res[20:24]) == ip:
                mac = (p / "address").read_text().strip()
                return name, norm_mac(mac)
        except OSError:
            continue
    return None, None


# ---------------------------------------------------------------- presence sweep

def _send_probes(hosts: list[str]) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setblocking(False)
        for i, ip in enumerate(hosts):
            try:
                s.sendto(b"", (ip, 9))  # discard port; the point is the ARP lookup it causes
            except OSError:
                pass
            if i % 32 == 31:
                time.sleep(0.02)  # about 1,500 packets a second at most


def read_neighbours(iface: str | None = None) -> dict[str, str]:
    """{ip: MAC} for live entries in the kernel's neighbour (ARP) table."""
    out: dict[str, str] = {}
    if shutil.which("ip"):
        try:
            cmd = ["ip", "-4", "-j", "neigh", "show"] + (["dev", iface] if iface else [])
            rows = json.loads(subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout or "[]")
            for r in rows:
                mac = norm_mac(r.get("lladdr", ""))
                if mac and set(r.get("state", [])) & LIVE_STATES:
                    out[r["dst"]] = mac
            return out
        except (OSError, ValueError, subprocess.SubprocessError) as e:
            log.debug("ip neigh failed: %s", e)
    try:
        for line in Path("/proc/net/arp").read_text().splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 6 and parts[2] == "0x2" and (not iface or parts[5] == iface):
                mac = norm_mac(parts[3])
                if mac:
                    out[parts[0]] = mac
    except OSError:
        pass
    return out


async def sweep(subnet: ipaddress.IPv4Network, iface: str | None, skip: set[str]) -> dict[str, str]:
    hosts = [str(h) for h in subnet.hosts()][:MAX_HOSTS]
    hosts = [h for h in hosts if h not in skip]
    await asyncio.to_thread(_send_probes, hosts)
    await asyncio.sleep(3)
    await asyncio.to_thread(_send_probes, hosts)  # second pass for slow sleepers (phones, IoT)
    # Entries that went quiet move DELAY -> PROBE -> FAILED within about 8 seconds.
    await asyncio.sleep(9)
    found = await asyncio.to_thread(read_neighbours, iface)
    return {ip: mac for ip, mac in found.items() if ipaddress.ip_address(ip) in subnet}


# ---------------------------------------------------------------- UDP request/response helper

def _udp_exchange(sends: list[tuple[bytes, tuple[str, int]]], wait: float, multicast: bool = False,
                  max_packets: int = 2000) -> list[tuple[bytes, str]]:
    replies = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("", 0))
        if multicast:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        for data, addr in sends:
            try:
                s.sendto(data, addr)
            except OSError:
                pass
        end = time.monotonic() + wait
        while len(replies) < max_packets:
            left = end - time.monotonic()
            if left <= 0:
                break
            r, _, _ = select.select([s], [], [], left)
            if not r:
                break
            try:
                data, addr = s.recvfrom(9000)
            except OSError:
                break
            replies.append((data, addr[0]))
    return replies


# ---------------------------------------------------------------- reverse DNS (via the router)

async def reverse_dns(ips: list[str], server: str) -> dict[str, str]:
    """Names the router's DHCP/DNS server knows for these addresses."""
    ids = {}
    sends = []
    for ip in ips:
        qid = random.randint(1, 65535)
        ids[qid] = ip
        sends.append((dnsmsg.query(qid, [(dnsmsg.reverse_name(ip), dnsmsg.PTR)]), (server, 53)))
    out = {}
    for data, src in await asyncio.to_thread(_udp_exchange, sends, 2.0):
        if src != server:
            continue
        try:
            msg = dnsmsg.parse(data)
        except ValueError:
            continue
        ip = ids.get(msg["id"])
        for rec in msg["records"]:
            if ip and rec["type"] == dnsmsg.PTR and isinstance(rec["data"], str):
                out[ip] = clean_host(rec["data"])
    return {k: v for k, v in out.items() if v}


def clean_host(name: str) -> str:
    name = name.rstrip(".")
    for suf in (".local", ".lan", ".home", ".router.asus.com", ".asus.com", ".localdomain", ".home.arpa"):
        if name.lower().endswith(suf):
            name = name[: -len(suf)]
    return name[:80]


# ---------------------------------------------------------------- mDNS / Bonjour

MDNS = ("224.0.0.251", 5353)
INTERESTING_TXT = ("md", "model", "am", "fn", "ty", "usb_mfg", "usb_mdl", "mfg", "manufacturer",
                   "product", "rpmd", "deviceid", "id", "vs", "osxvers", "integrator", "ver", "name")


async def mdns(ips_without_names: list[str]) -> dict[str, dict]:
    """{ip: {"services": [...], "instances": [...], "hostname": str, "txt": {...}}}.

    Uses "legacy unicast" queries (from a random port, RFC 6762 6.7) so it never binds port 5353
    and doesn't fight the NAS's own Bonjour service.
    """
    out: dict[str, dict] = {}

    def add(src: str, msg: dict):
        d = out.setdefault(src, {"services": set(), "instances": set(), "hostname": None, "txt": {}})
        for r in msg["records"]:
            name, t, data = r["name"], r["type"], r["data"]
            if t == dnsmsg.PTR and isinstance(data, str):
                if name == "_services._dns-sd._udp.local":
                    d["services"].add(_svc(data))
                elif name.endswith(".in-addr.arpa"):
                    d["hostname"] = d["hostname"] or clean_host(data)
                elif name.startswith("_"):
                    d["services"].add(_svc(name))
                    inst = data.split("._", 1)[0]
                    if inst:
                        d["instances"].add(inst[:80])
            elif t == dnsmsg.SRV and isinstance(data, dict):
                d["services"].add(_svc(name.split(".", 1)[1] if "." in name else name))
                d["hostname"] = d["hostname"] or clean_host(data["target"])
            elif t == dnsmsg.A and name.endswith(".local"):
                d["hostname"] = d["hostname"] or clean_host(name)
            elif t == dnsmsg.TXT and isinstance(data, dict):
                for k in INTERESTING_TXT:
                    if data.get(k) and k not in d["txt"]:
                        d["txt"][k] = data[k][:80]

    # Round 1: which service types are out there?
    q = dnsmsg.query(0, [("_services._dns-sd._udp.local", dnsmsg.PTR)], unicast_response=True)
    sends = [(q, MDNS)]
    # Unicast reverse lookups straight to devices we have no name for (Apple and Linux answer these)
    for ip in ips_without_names[:256]:
        sends.append((dnsmsg.query(0, [(dnsmsg.reverse_name(ip), dnsmsg.PTR)]), (ip, 5353)))
    types: set[str] = set()
    for data, src in await asyncio.to_thread(_udp_exchange, sends, 2.5, True):
        try:
            msg = dnsmsg.parse(data)
        except ValueError:
            continue
        add(src, msg)
        types |= out[src]["services"]

    # Round 2: ask for the instances of each type (in a few packets, to stay under the MTU)
    types = {t for t in types if t and len(t) < 60}
    tl = sorted(types)
    sends = []
    for i in range(0, len(tl), 12):
        sends.append((dnsmsg.query(0, [(f"{t}.local", dnsmsg.PTR) for t in tl[i:i + 12]], True), MDNS))
    if sends:
        for data, src in await asyncio.to_thread(_udp_exchange, sends, 3.0, True):
            try:
                add(src, dnsmsg.parse(data))
            except ValueError:
                continue

    for d in out.values():
        d["services"] = sorted(s for s in d["services"] if s and s != "_services")
        d["instances"] = sorted(d["instances"])[:10]
    return out


def _svc(name: str) -> str:
    """'_airplay._tcp.local' -> '_airplay._tcp'"""
    parts = [p for p in name.split(".") if p.startswith("_")]
    return ".".join(parts[-2:]) if len(parts) >= 2 else (parts[0] if parts else "")


# ---------------------------------------------------------------- SSDP / UPnP

SSDP_ADDR = ("239.255.255.250", 1900)
SSDP_Q = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
          "MX: 2\r\nST: ssdp:all\r\n\r\n").encode()


async def ssdp(subnet: ipaddress.IPv4Network) -> dict[str, dict]:
    raw = await asyncio.to_thread(_udp_exchange, [(SSDP_Q, SSDP_ADDR), (SSDP_Q, SSDP_ADDR)], 3.5, True)
    found: dict[str, dict] = {}
    for data, src in raw:
        if ipaddress.ip_address(src) not in subnet:
            continue
        hdr = {}
        for line in data.decode("utf-8", "replace").split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                hdr[k.strip().lower()] = v.strip()[:200]
        d = found.setdefault(src, {"server": None, "types": set(), "location": None})
        d["server"] = d["server"] or hdr.get("server")
        st = hdr.get("st") or hdr.get("nt") or ""
        if st.startswith("urn:"):
            d["types"].add(st)
        loc = hdr.get("location")
        if loc and not d["location"] and urlsplit(loc).hostname == src:
            d["location"] = loc  # only fetch descriptions from the device that sent them

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=4)) as s:
        await asyncio.gather(*(_ssdp_desc(s, d) for d in found.values()))
    for d in found.values():
        d["types"] = sorted(d["types"])[:12]
        d.pop("location", None)
    return found


XML_FIELDS = ("friendlyName", "manufacturer", "modelName", "modelDescription", "deviceType", "modelNumber")


async def _ssdp_desc(s: aiohttp.ClientSession, d: dict) -> None:
    if not d.get("location") or urlsplit(d["location"]).scheme not in ("http", "https"):
        return
    try:
        async with s.get(d["location"], ssl=False, allow_redirects=False) as r:
            body = (await r.content.read(64 * 1024)).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - devices answer in all sorts of broken ways
        return
    for f in XML_FIELDS:
        m = re.search(rf"<{f}>\s*([^<]{{1,120}}?)\s*</{f}>", body)
        if m:
            d[f] = _xml_unescape(m.group(1))


def _xml_unescape(s: str) -> str:
    return (s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"')
             .replace("&apos;", "'").replace("&amp;", "&"))


# ---------------------------------------------------------------- NetBIOS

async def netbios(ips: list[str]) -> dict[str, str]:
    ids, sends = {}, []
    for ip in ips[:512]:
        qid = random.randint(1, 65535)
        ids[ip] = qid
        sends.append((dnsmsg.nbstat_query(qid), (ip, 137)))
    out = {}
    for data, src in await asyncio.to_thread(_udp_exchange, sends, 2.0):
        if src in ids:
            name = dnsmsg.parse_nbstat(data)
            if name:
                out[src] = name[:40]
    return out


# ---------------------------------------------------------------- optional port check

PROBE_PORTS = {
    22: "ssh", 23: "telnet", 80: "http", 443: "https", 445: "smb", 548: "afp", 554: "rtsp",
    631: "ipp", 1883: "mqtt", 3389: "rdp", 5000: "upnp/nas", 5001: "nas-https", 7000: "airplay",
    8008: "cast", 8009: "cast", 8080: "http-alt", 8443: "https-alt", 9100: "jetdirect", 62078: "iphone-sync",
}


async def port_probe(ip: str) -> list[int]:
    sem = asyncio.Semaphore(6)

    async def one(port: int) -> int | None:
        async with sem:
            try:
                _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), 0.8)
                w.close()
                return port
            except (OSError, asyncio.TimeoutError):
                return None

    res = await asyncio.gather(*(one(p) for p in PROBE_PORTS))
    return sorted(p for p in res if p)
