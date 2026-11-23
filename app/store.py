"""SQLite inventory: devices, the addresses they have used, and an activity log."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
  mac TEXT PRIMARY KEY,
  first_seen REAL NOT NULL,
  last_seen REAL NOT NULL,
  data TEXT NOT NULL            -- JSON: everything else (see Inventory in server.py)
);
CREATE TABLE IF NOT EXISTS ips (
  mac TEXT NOT NULL, ip TEXT NOT NULL, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
  PRIMARY KEY (mac, ip)
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL, kind TEXT NOT NULL, mac TEXT, text TEXT
);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
"""


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.executescript(SCHEMA)

    # devices
    def load_devices(self) -> dict[str, dict]:
        out = {}
        for r in self.db.execute("SELECT * FROM devices"):
            d = json.loads(r["data"])
            d.update(mac=r["mac"], first_seen=r["first_seen"], last_seen=r["last_seen"])
            out[r["mac"]] = d
        return out

    def save_device(self, d: dict) -> None:
        data = {k: v for k, v in d.items() if k not in ("mac", "first_seen", "last_seen")}
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO devices VALUES (?,?,?,?)",
                            (d["mac"], d["first_seen"], d["last_seen"], json.dumps(data, default=list)))

    def delete_device(self, mac: str) -> None:
        with self.lock, self.db:
            self.db.execute("DELETE FROM devices WHERE mac=?", (mac,))
            self.db.execute("DELETE FROM ips WHERE mac=?", (mac,))

    # IP history
    def seen_ip(self, mac: str, ip: str, ts: float) -> None:
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO ips VALUES (?,?,?,?) ON CONFLICT(mac, ip) DO UPDATE SET last_seen=excluded.last_seen",
                (mac, ip, ts, ts))

    def ip_history(self, mac: str) -> list[dict]:
        return [dict(r) for r in self.db.execute(
            "SELECT ip, first_seen, last_seen FROM ips WHERE mac=? ORDER BY last_seen DESC LIMIT 20", (mac,))]

    # events
    def add_event(self, kind: str, mac: str | None, text: str, ts: float | None = None) -> dict:
        ts = ts or time.time()
        with self.lock, self.db:
            cur = self.db.execute("INSERT INTO events (ts, kind, mac, text) VALUES (?,?,?,?)", (ts, kind, mac, text))
        return {"id": cur.lastrowid, "ts": ts, "kind": kind, "mac": mac, "text": text}

    def events(self, limit: int = 200, mac: str | None = None) -> list[dict]:
        if mac:
            q = self.db.execute("SELECT * FROM events WHERE mac=? ORDER BY id DESC LIMIT ?", (mac, limit))
        else:
            q = self.db.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in q]

    # meta
    def get_meta(self, k: str) -> str | None:
        r = self.db.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return r[0] if r else None

    def set_meta(self, k: str, v: str | None) -> None:
        with self.lock, self.db:
            if v is None:
                self.db.execute("DELETE FROM meta WHERE k=?", (k,))
            else:
                self.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (k, v))

    def prune(self, keep_days: int) -> None:
        cutoff = time.time() - keep_days * 86400
        with self.lock, self.db:
            self.db.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
            self.db.execute("DELETE FROM ips WHERE last_seen < ?", (cutoff,))
