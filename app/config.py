"""Settings, read from environment variables (and ./.env when run without Docker)."""

from __future__ import annotations

import os
from pathlib import Path

BASE = Path(__file__).resolve().parent


def _load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_env_file(BASE.parent / ".env")


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def flag(name: str, default: bool) -> bool:
    return env(name, "1" if default else "0").lower() in ("1", "true", "yes", "on")


CFG = {
    "router_url": env("ROUTER_URL", "https://192.168.50.1:8443").rstrip("/"),
    "router_user": env("ROUTER_USER", "admin"),
    "router_password": env("ROUTER_PASSWORD"),
    "router_cert_sha256": env("ROUTER_CERT_SHA256").replace(":", "").lower(),
    "clients_seconds": max(30, int(env("CLIENTS_SECONDS", "60"))),
    "live_seconds": max(2, int(env("LIVE_SECONDS", "3"))),
    "idle_traffic_seconds": max(15, int(env("IDLE_TRAFFIC_SECONDS", "60"))),
    "device_traffic": env("DEVICE_TRAFFIC", "auto").lower(),  # auto | on | off
    "subnet": env("SCAN_SUBNET"),  # blank = take it from the router
    "scan": flag("SCAN", True),
    "scan_seconds": max(60, int(env("SCAN_SECONDS", "120"))),
    "mdns": flag("MDNS", True),
    "ssdp": flag("SSDP", True),
    "netbios": flag("NETBIOS", True),
    "port_probe": flag("PORT_PROBE", False),
    "offline_after": max(120, int(env("OFFLINE_AFTER_SECONDS", "600"))),
    "alert_webhook": env("ALERT_WEBHOOK_URL"),
    "app_password": env("APP_PASSWORD"),
    "tz": env("TZ", "UTC"),
    "port": int(env("PORT", "8089")),
    "data": Path(env("DATA_DIR", str(BASE.parent / "data"))),
    "keep_days": int(env("KEEP_DAYS", "365")),
    "debug": flag("DEBUG_ENDPOINTS", False),
}
