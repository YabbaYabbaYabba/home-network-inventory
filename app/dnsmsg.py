"""Just enough DNS wire format for reverse lookups, mDNS and NetBIOS name queries."""

from __future__ import annotations

import struct

A, PTR, TXT, AAAA, SRV, ANY = 1, 12, 16, 28, 33, 255


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        b = label.encode("utf-8")[:63]
        out += bytes([len(b)]) + b
    return out + b"\0"


def query(qid: int, questions: list[tuple[str, int]], unicast_response: bool = False) -> bytes:
    """A standard query. unicast_response sets the mDNS QU bit."""
    out = struct.pack("!HHHHHH", qid, 0, len(questions), 0, 0, 0)
    cls = 0x8001 if unicast_response else 1
    for name, qtype in questions:
        out += encode_name(name) + struct.pack("!HH", qtype, cls)
    return out


def reverse_name(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def _read_name(buf: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    labels = []
    jumped_end = None
    hops = 0
    while True:
        if off >= len(buf):
            raise ValueError("name runs past end")
        n = buf[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                raise ValueError("bad pointer")
            ptr = ((n & 0x3F) << 8) | buf[off + 1]
            if jumped_end is None:
                jumped_end = off + 2
            hops += 1
            if hops > 20 or ptr >= len(buf):
                raise ValueError("pointer loop")
            off = ptr
            continue
        off += 1
        labels.append(buf[off:off + n].decode("utf-8", "replace"))
        off += n
        if len(labels) > 64:
            raise ValueError("too many labels")
    return ".".join(labels), (jumped_end if jumped_end is not None else off)


def parse(buf: bytes) -> dict:
    """Returns {"id", "flags", "records": [{"name","type","data"}]} for answers + authority + additional."""
    if len(buf) < 12:
        raise ValueError("short packet")
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", buf[:12])
    off = 12
    for _ in range(qd):
        _, off = _read_name(buf, off)
        off += 4
    recs = []
    for _ in range(min(an + ns + ar, 400)):
        name, off = _read_name(buf, off)
        if off + 10 > len(buf):
            break
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", buf[off:off + 10])
        off += 10
        rd = buf[off:off + rdlen]
        start = off
        off += rdlen
        data: object = rd
        try:
            if rtype == A and rdlen == 4:
                data = ".".join(str(b) for b in rd)
            elif rtype == PTR:
                data, _ = _read_name(buf, start)
            elif rtype == SRV and rdlen >= 7:
                prio, weight, port = struct.unpack("!HHH", rd[:6])
                target, _ = _read_name(buf, start + 6)
                data = {"port": port, "target": target}
            elif rtype == TXT:
                kv, i = {}, 0
                while i < len(rd):
                    ln = rd[i]
                    s = rd[i + 1:i + 1 + ln].decode("utf-8", "replace")
                    i += 1 + ln
                    if "=" in s:
                        k, v = s.split("=", 1)
                        kv[k.lower()] = v
                    elif s:
                        kv[s.lower()] = ""
                data = kv
        except ValueError:
            continue
        recs.append({"name": name, "type": rtype, "data": data})
    return {"id": qid, "flags": flags, "records": recs}


# ---------------------------------------------------------------- NetBIOS

NBSTAT_NAME = b"\x20" + b"CK" + b"A" * 30 + b"\x00"  # "*" encoded


def nbstat_query(qid: int) -> bytes:
    return struct.pack("!HHHHHH", qid, 0, 1, 0, 0, 0) + NBSTAT_NAME + struct.pack("!HH", 0x21, 1)


def parse_nbstat(buf: bytes) -> str | None:
    """First unique (not group) workstation name from a NetBIOS node status reply."""
    try:
        qd, an = struct.unpack("!HH", buf[4:8])
        if not an:
            return None
        off = 12
        for _ in range(qd):
            _, off = _read_name(buf, off)
            off += 4
        _, off = _read_name(buf, off)
        off += 2 + 2 + 4 + 2  # type, class, ttl, rdlength
        count = buf[off]
        off += 1
        names = []
        for _ in range(count):
            raw = buf[off:off + 15].decode("ascii", "replace").rstrip(" \x00")
            suffix = buf[off + 15]
            nflags = struct.unpack("!H", buf[off + 16:off + 18])[0]
            off += 18
            names.append((raw, suffix, bool(nflags & 0x8000)))
        for raw, suffix, group in names:
            if suffix == 0 and not group and raw:
                return raw
        return names[0][0] if names else None
    except (IndexError, struct.error, ValueError):
        return None
