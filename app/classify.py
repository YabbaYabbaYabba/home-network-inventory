"""Sorting devices into groups.

Every clue about a device (MAC vendor, names, Bonjour services, UPnP description, open ports,
how it connects) is checked against the rules below. Each matching rule adds points to a group,
and the group with the most points wins. The matching rules are kept as the "why", so every
decision can be checked, and a group set by hand always wins.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

GROUPS = [
    # id, label, colour (map + chips), icon key
    ("network", "Network gear", "#38bdf8", "router"),
    ("servers", "NAS & servers", "#a78bfa", "server"),
    ("computers", "Computers", "#60a5fa", "laptop"),
    ("phones", "Phones & tablets", "#34d399", "phone"),
    ("media", "TV & media", "#f472b6", "tv"),
    ("smarthome", "Smart home & IoT", "#fbbf24", "bulb"),
    ("cameras", "Cameras", "#f87171", "camera"),
    ("printers", "Printers", "#2dd4bf", "printer"),
    ("unknown", "Unknown", "#94a3b8", "question"),
]
GROUP_IDS = [g[0] for g in GROUPS]


@dataclass
class Ctx:
    vendor: str
    names: str
    svc: set
    txt: str
    ssdp: str
    ports: set
    wireless: bool
    band: str
    random_mac: bool
    gateway: bool
    mesh_node: bool
    printer_flag: bool
    netbios: bool


def _has(pattern: str, text: str) -> bool:
    return bool(text) and re.search(pattern, text, re.I) is not None


def _svc(c: Ctx, *names: str) -> bool:
    return any(n in c.svc for n in names)


CHIP_VENDORS = (r"espressif|tuya|hangzhou tuya|bouffalo|beken|winner ?micro|silicon labs|texas instruments|"
                r"shanghai high-flying|realtek semiconductor|azurewave|murata|hon hai|universal global|"
                r"chongqing fugui|lumi united|qingdao intelligent|amlogic")

# (group, points, test, why, kind)
RULES = [
    # --- network gear
    ("network", 100, lambda c: c.gateway, "The router itself", "Router"),
    ("network", 90, lambda c: c.mesh_node, "Other devices connect through it (AiMesh node)", "Mesh node"),
    ("network", 30, lambda c: _has(r"ubiquiti|mikrotik|cisco|aruba|ruckus|juniper|zyxel|draytek|netgear|"
                                   r"d-link|tp-link|eero|cambium|engenius|meraki", c.vendor),
     "Networking vendor", None),
    ("network", 45, lambda c: _has(r"\b(switch|router|access[- ]?point|unifi|udm|usw|uap|u6|u7|eap\d*|mesh|"
                                   r"extender|repeater|deco|orbi|zenwifi|rt-[a-z]{2}\d+|gt-[a-z]{2}\d+|"
                                   r"powerline|devolo)\b", c.names),
     "Name suggests network equipment", None),
    ("network", 50, lambda c: _has(r"internetgatewaydevice|wlanaccesspoint|wfadevice", c.ssdp),
     "Announces itself as a gateway / access point (UPnP)", None),

    # --- NAS & servers
    ("servers", 70, lambda c: _has(r"qnap|synology|ugreen|asustor|terramaster|buffalo|western digital|"
                                   r"seagate|netgear.*readynas|drobo", c.vendor),
     "NAS manufacturer", "NAS"),
    ("servers", 50, lambda c: _has(r"\b(nas|server|srv|proxmox|pve\d*|unraid|truenas|freenas|esxi|"
                                   r"home-?assistant|hassio|hass|pi-?hole|adguard|docker|k8s|plex(server)?|"
                                   r"jellyfin|emby|nextcloud|homebridge|openmediavault|omv)\b", c.names),
     "Name suggests a server", None),
    ("servers", 60, lambda c: _svc(c, "_home-assistant._tcp"), "Runs Home Assistant", "Home Assistant"),
    ("servers", 35, lambda c: _has(r"raspberry pi", c.vendor), "Raspberry Pi", "Raspberry Pi"),
    ("servers", 40, lambda c: _has(r"vmware|xensource|proxmox|parallels|qemu|virtualbox|oracle", c.vendor),
     "Virtual machine network card", "Virtual machine"),
    ("servers", 25, lambda c: _svc(c, "_adisk._tcp") or (_svc(c, "_smb._tcp") and _svc(c, "_afpovertcp._tcp")),
     "Offers network file shares / Time Machine", None),
    ("servers", 15, lambda c: _svc(c, "_plexmediasvr._tcp", "_daap._tcp", "_nfs._tcp", "_webdav._tcp"),
     "Offers media or file services", None),
    ("servers", 10, lambda c: _svc(c, "_ssh._tcp", "_sftp-ssh._tcp") or 22 in c.ports, "Accepts SSH", None),

    # --- computers
    ("computers", 80, lambda c: _has(r"\b(macbook|imac|macmini|mac\d+,\d|macpro|mac ?studio)", c.txt),
     "Reports a Mac model", "Mac"),
    ("computers", 65, lambda c: _has(r"macbook|imac|mac-?mini|mac-?studio|mac-?pro", c.names),
     "Name says it's a Mac", "Mac"),
    ("computers", 55, lambda c: _has(r"^desktop-|^laptop-|\bdesktop\b|\blaptop\b|-pc\b|\bpc\b|workstation|"
                                     r"thinkpad|thinkcentre|surface|chromebook|\bxps\b|latitude|optiplex|"
                                     r"probook|elitebook|zenbook|vivobook|ideapad|legion|\bmsi\b|predator|"
                                     r"aspire|framework|ubuntu|fedora|debian", c.names),
     "Name looks like a computer", "PC"),
    ("computers", 30, lambda c: c.netbios, "Answers Windows network-name queries (NetBIOS)", "PC"),
    ("computers", 30, lambda c: 3389 in c.ports, "Remote Desktop is open", "PC"),
    ("computers", 20, lambda c: _has(r"intel corporate|liteon|dell|lenovo|micro-star|giga-byte|asrock|"
                                     r"framework|microsoft|asustek|clevo|quanta|compal|wistron|pegatron", c.vendor),
     "Vendor mostly makes computers / laptop Wi-Fi cards", None),
    ("computers", 15, lambda c: _svc(c, "_rfb._tcp", "_workstation._tcp", "_sftp-ssh._tcp", "_smb._tcp"),
     "Offers screen sharing or file sharing", None),
    ("computers", 15, lambda c: _has(r"apple", c.vendor) and not c.wireless,
     "Wired Apple device", None),

    # --- phones & tablets
    ("phones", 85, lambda c: _has(r"\b(iphone|ipad|ipod)", c.txt), "Reports an iPhone/iPad model", "iPhone/iPad"),
    ("phones", 65, lambda c: _has(r"iphone|ipad|galaxy|pixel|android|oneplus|redmi|xiaomi|huawei|honor|oppo|"
                                  r"vivo|realme|nokia|motorola|moto[- ]?[a-z]|sm-[a-z]\d|\bphone\b|tablet|"
                                  r"kindle|fire-?hd|nothing-phone|fairphone", c.names),
     "Name looks like a phone or tablet", "Phone/Tablet"),
    ("phones", 70, lambda c: 62078 in c.ports, "iPhone/iPad sync port is open", "iPhone/iPad"),
    ("phones", 45, lambda c: _svc(c, "_apple-mobdev2._tcp"), "Advertises iOS device pairing", "iPhone/iPad"),
    ("phones", 30, lambda c: _has(r"watch", c.names), "Name mentions a watch", "Watch"),
    ("phones", 25, lambda c: c.random_mac and c.wireless,
     "Wi-Fi with a private (random) MAC, as phones use by default", None),
    ("phones", 12, lambda c: _has(r"apple|samsung|google|oneplus|xiaomi|huawei|motorola|oppo|vivo", c.vendor)
     and c.wireless, "Wi-Fi device from a phone maker", None),

    # --- TV & media
    ("media", 90, lambda c: _has(r"appletv|apple ?tv", c.txt + " " + c.names), "Apple TV", "Apple TV"),
    ("media", 60, lambda c: _svc(c, "_googlecast._tcp"), "Accepts Google Cast", "Chromecast / Google TV"),
    ("media", 80, lambda c: _svc(c, "_sonos._tcp") or _has(r"sonos", c.vendor), "Sonos", "Sonos speaker"),
    ("media", 55, lambda c: _has(r"\b(tv|roku|fire-?tv|firestick|aft[a-z]+|chromecast|shield|bravia|webos|"
                                 r"tizen|androidtv|google-?tv|soundbar|sonos|bose|denon|marantz|yamaha|"
                                 r"heos|bluesound|kodi|libreelec|osmc|sky ?q|skyq|now ?tv|tivo|"
                                 r"freesat|saorview)\b", c.names),
     "Name looks like a TV or media player", "TV / Media"),
    ("media", 55, lambda c: _has(r"playstation|\bps[345]\b|xbox|nintendo|steam ?deck|\bswitch-?\w{4}|\bconsole\b", c.names)
     or _has(r"nintendo|sony interactive", c.vendor), "Games console", "Games console"),
    ("media", 35, lambda c: _has(r"roku|sonos|bose|denon|marantz|yamaha|harman|bang & olufsen|vizio|tcl|"
                                 r"hisense|tp vision|sky uk|nvidia|lg electronics|sony|panasonic|sharp|"
                                 r"loewe|philips|devialet|bluesound|amazon", c.vendor),
     "TV / audio vendor", None),
    ("media", 45, lambda c: _has(r"mediarenderer|dial-multiscreen|tvdevice|roku|webos|samsung.*tv|"
                                 r"remotecontrolreceiver", c.ssdp),
     "Announces itself as a TV or media renderer (UPnP)", "TV / Media"),
    ("media", 30, lambda c: _svc(c, "_amzn-wplay._tcp", "_spotify-connect._tcp", "_raop._tcp", "_airplay._tcp")
     and not _has(r"mac|iphone|ipad", c.txt + c.names),
     "Accepts AirPlay / Spotify Connect / Fire TV casting", None),

    # --- printers
    ("printers", 80, lambda c: _svc(c, "_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp",
                                    "_uscan._tcp", "_scanner._tcp"), "Offers printing/scanning", "Printer"),
    ("printers", 70, lambda c: c.printer_flag, "The router identified it as a printer", "Printer"),
    ("printers", 50, lambda c: 9100 in c.ports or 631 in c.ports, "Printer ports are open", "Printer"),
    ("printers", 40, lambda c: _has(r"brother|canon|seiko epson|epson|lexmark|kyocera|xerox|ricoh|konica|"
                                    r"zebra|oki data|sharp corp|hp inc|hewlett", c.vendor),
     "Printer manufacturer", None),
    ("printers", 55, lambda c: _has(r"printer|laserjet|officejet|deskjet|envy-?\d|mfc-|\bbrn[0-9a-f]+|"
                                    r"\bepson|\bcanon|\bhp[0-9a-f]{6}\b|\bnpi[0-9a-f]+", c.names),
     "Name looks like a printer", "Printer"),
    ("printers", 50, lambda c: _has(r"printer|print", c.ssdp), "Announces itself as a printer (UPnP)", "Printer"),

    # --- cameras
    ("cameras", 65, lambda c: _has(r"hikvision|hangzhou hikvision|dahua|zhejiang dahua|reolink|amcrest|axis comm|"
                                   r"foscam|wyze|arlo|netgear.*arlo|ring llc|eufy|anker|ezviz|uniview|"
                                   r"lorex|swann|imou|yi technology|blink|mobotix|hanwha|vivotek", c.vendor),
     "Camera manufacturer", "Camera"),
    ("cameras", 55, lambda c: _has(r"\b(cam|camera|ipcam|doorbell|nvr|dvr|reolink|ring-|arlo|tapo-?c\d+|"
                                   r"wyze|eufy|blink|hikvision|dahua|g\d-?(instant|bullet|flex|dome))", c.names),
     "Name looks like a camera", "Camera"),
    ("cameras", 35, lambda c: 554 in c.ports or _svc(c, "_rtsp._tcp"), "Video stream port (RTSP) is open", None),
    ("cameras", 50, lambda c: _has(r"\b(nvr|ipcamera|networkcamera|camera)\b", c.ssdp),
     "Announces itself as a camera (UPnP)", "Camera"),

    # --- smart home & IoT
    ("smarthome", 80, lambda c: _svc(c, "_hue._tcp") or _has(r"signify|philips lighting", c.vendor),
     "Philips Hue", "Hue bridge"),
    ("smarthome", 80, lambda c: _svc(c, "_esphomelib._tcp"), "Runs ESPHome", "ESPHome device"),
    ("smarthome", 70, lambda c: _svc(c, "_hap._tcp", "_hap._udp"), "HomeKit accessory", "HomeKit accessory"),
    ("smarthome", 80, lambda c: _has(r"audioaccessory|homepod", c.txt + " " + c.names), "HomePod", "HomePod"),
    ("smarthome", 60, lambda c: _svc(c, "_matter._tcp", "_matterc._udp", "_meshcop._udp", "_shelly._tcp",
                                     "_miio._udp", "_wled._tcp", "_mqtt._tcp"),
     "Smart-home protocol (Matter / Thread / Shelly / WLED)", "Smart device"),
    ("smarthome", 70, lambda c: _has(r"\b(echo|alexa|google-?home|nest-?(mini|hub|audio)|home-?mini)\b", c.names),
     "Voice assistant / smart speaker", "Smart speaker"),
    ("smarthome", 50, lambda c: _has(r"espressif", c.vendor), "Espressif Wi-Fi chip (smart plugs, sensors, ESP32)",
     "Smart device"),
    ("smarthome", 45, lambda c: _has(r"tuya|shelly|allterco|sonoff|itead|lifx|nanoleaf|tado|netatmo|ecobee|"
                                     r"nest labs|meross|wiz connected|ikea|broadlink|irobot|roborock|ecovacs|"
                                     r"dreame|myenergi|wallbox|easee|solaredge|fronius|growatt|honeywell|"
                                     r"resideo|somfy|velux|lutron|lumi united|aqara|switchbot|wonderlabs|"
                                     r"miele|bsh|vorwerk|daikin|mitsubishi electric|gree|hive|centrica|"
                                     r"govee|kasa|tp-link systems|withings|eve systems|belkin", c.vendor),
     "Smart-home manufacturer", "Smart device"),
    ("smarthome", 45, lambda c: _has(r"\b(shelly|tasmota|esp[-_]?\w*|espressif|sonoff|tuya|smart-?plug|plug|"
                                     r"bulb|light|lamp|led|thermostat|tado|ecobee|hive|roomba|roborock|vacuum|"
                                     r"tradfri|dirigera|wled|washer|dryer|fridge|oven|dishwasher|charger|"
                                     r"zappi|eddi|inverter|solar|meter|sensor|bridge|hub|kasa|tapo-?p\d+|"
                                     r"wiz|govee|switchbot|myq|doorlock|lock)\b", c.names),
     "Name looks like a smart-home device", "Smart device"),
    ("smarthome", 25, lambda c: _has(r"amazon technologies|google", c.vendor) and not c.svc,
     "Amazon/Google device without other services (often Echo / Nest)", None),
    ("smarthome", 20, lambda c: c.band == "2.4 GHz" and _has(CHIP_VENDORS, c.vendor),
     "2.4 GHz-only Wi-Fi with a generic chip, typical of plugs and bulbs", None),
    ("smarthome", 8, lambda c: c.band == "2.4 GHz" and not c.random_mac, "Uses 2.4 GHz Wi-Fi only", None),
]


def make_ctx(dev: dict) -> Ctx:
    sig = dev.get("signals") or {}
    r = sig.get("router") or {}
    md = sig.get("mdns") or {}
    sd = sig.get("ssdp") or {}
    names = [r.get("name"), r.get("router_name"), sig.get("ptr"), md.get("hostname"), sig.get("netbios"),
             sd.get("friendlyName")] + list(md.get("instances") or [])
    txt = " ".join(f"{k}={v}" for k, v in (md.get("txt") or {}).items())
    ssdp = " ".join(str(v) for k, v in sd.items() if v and k != "types") + " " + " ".join(sd.get("types") or [])
    conn = dev.get("conn") or r.get("conn") or ""
    return Ctx(
        vendor=" ".join(x for x in (dev.get("vendor"), r.get("vendor")) if x).lower(),
        names=" ".join(n for n in names if n).lower(),
        svc=set(md.get("services") or []),
        txt=txt.lower(),
        ssdp=ssdp.lower(),
        ports=set(sig.get("ports") or []),
        wireless=bool(conn) and conn != "wired",
        band=conn,
        random_mac=bool(dev.get("random_mac")),
        gateway=bool(r.get("is_gateway")) or bool(dev.get("is_router")),
        mesh_node=bool(dev.get("mesh_node")),
        printer_flag=bool(r.get("is_printer")),
        netbios=bool(sig.get("netbios")),
    )


def classify(dev: dict) -> dict:
    """{"group", "confidence", "kind", "why": [...], "scores": {...}}"""
    c = make_ctx(dev)
    scores: dict[str, int] = {}
    hits: dict[str, list] = {}
    for group, pts, test, why, kind in RULES:
        try:
            ok = test(c)
        except Exception:  # noqa: BLE001 - a bad clue must never stop the scan
            ok = False
        if ok:
            scores[group] = scores.get(group, 0) + pts
            hits.setdefault(group, []).append((pts, why, kind))
    if not scores or max(scores.values()) < 20:
        return {"group": "unknown", "confidence": "low", "kind": None,
                "why": [w for g in hits.values() for _, w, _ in g][:4] or ["Not enough clues yet"],
                "scores": scores}
    ranked = sorted(scores.items(), key=lambda kv: -kv[1])
    group, top = ranked[0]
    second = ranked[1][1] if len(ranked) > 1 else 0
    conf = "high" if top >= 60 and top >= second * 1.5 else "medium" if top >= 35 else "low"
    gh = sorted(hits[group], key=lambda h: -h[0])
    kind = next((k for _, _, k in gh if k), None)
    return {"group": group, "confidence": conf, "kind": model_kind(dev) or kind,
            "why": [w for _, w, _ in gh][:5], "scores": scores}


APPLE_MODELS = [
    (r"^iphone", "iPhone"), (r"^ipad", "iPad"), (r"^appletv", "Apple TV"), (r"^audioaccessory", "HomePod"),
    (r"^macbookpro", "MacBook Pro"), (r"^macbookair", "MacBook Air"), (r"^macbook", "MacBook"),
    (r"^imac", "iMac"), (r"^macmini", "Mac mini"), (r"^mac1[3-9],|^macstudio", "Mac Studio"),
    (r"^macpro", "Mac Pro"), (r"^mac\d", "Mac"), (r"^watch", "Apple Watch"),
]


def model_kind(dev: dict) -> str | None:
    sig = dev.get("signals") or {}
    txt = (sig.get("mdns") or {}).get("txt") or {}
    for key in ("model", "md", "am", "rpmd"):
        v = (txt.get(key) or "").strip()
        if not v:
            continue
        for pat, label in APPLE_MODELS:
            if re.search(pat, v, re.I):
                return label
        if key == "md" and len(v) < 40:  # Chromecast "md=Chromecast Ultra", "md=Google Nest Mini"
            return v
    return None


def model_text(dev: dict) -> str | None:
    """Best human-readable model string, if any device told us one."""
    sig = dev.get("signals") or {}
    txt = (sig.get("mdns") or {}).get("txt") or {}
    sd = sig.get("ssdp") or {}
    for v in (txt.get("md"), txt.get("model"), txt.get("am"), txt.get("usb_mdl") and
              f"{txt.get('usb_mfg', '')} {txt.get('usb_mdl')}".strip(), txt.get("ty"),
              sd.get("modelName") and f"{sd.get('manufacturer', '')} {sd.get('modelName')}".strip()):
        if v:
            return v[:80]
    return None
