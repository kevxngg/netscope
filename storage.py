"""
storage.py - Base de datos local (SQLite) de NetScope.

Guarda:
  - devices : cada equipo visto (mac, ip, fabricante, nombre personalizado,
              primera/ultima vez, veces visto, confiable si/no)
  - events  : historial (equipo nuevo, bloqueo, etc.)
  - settings: ajustes (token de Telegram, alertas on/off, ...)
"""

import os
import time
import sqlite3
import threading

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "netscope.db")
_lock = threading.Lock()


def _conn():
    c = sqlite3.connect(DB, timeout=5)
    c.row_factory = sqlite3.Row
    return c


def init():
    with _lock, _conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS devices(
            mac TEXT PRIMARY KEY, ip TEXT, vendor TEXT, auto_name TEXT,
            custom_name TEXT, first_seen REAL, last_seen REAL,
            seen_count INTEGER DEFAULT 1, trusted INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, type TEXT,
            mac TEXT, ip TEXT, detail TEXT);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
        """)


def device_count():
    with _lock, _conn() as c:
        return c.execute("SELECT COUNT(*) FROM devices").fetchone()[0]


def upsert_device(mac, ip, vendor, auto_name):
    """Registra/actualiza un equipo. Devuelve True si es NUEVO (nunca visto)."""
    now = time.time()
    with _lock, _conn() as c:
        row = c.execute("SELECT mac FROM devices WHERE mac=?", (mac,)).fetchone()
        if row:
            c.execute("UPDATE devices SET ip=?, vendor=?, auto_name=?, last_seen=?, "
                      "seen_count=seen_count+1 WHERE mac=?",
                      (ip, vendor, auto_name, now, mac))
            return False
        c.execute("INSERT INTO devices(mac,ip,vendor,auto_name,first_seen,last_seen) "
                  "VALUES(?,?,?,?,?,?)", (mac, ip, vendor, auto_name, now, now))
        return True


def get_custom_name(mac):
    with _lock, _conn() as c:
        row = c.execute("SELECT custom_name FROM devices WHERE mac=?", (mac,)).fetchone()
        return (row["custom_name"] if row else "") or ""


def set_custom_name(mac, name):
    with _lock, _conn() as c:
        c.execute("UPDATE devices SET custom_name=? WHERE mac=?", (name, mac))


def set_trusted(mac, trusted):
    with _lock, _conn() as c:
        c.execute("UPDATE devices SET trusted=? WHERE mac=?", (1 if trusted else 0, mac))


def get_device(mac):
    with _lock, _conn() as c:
        row = c.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
        return dict(row) if row else None


def all_devices():
    with _lock, _conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM devices ORDER BY last_seen DESC")]


def record_event(type_, mac, ip, detail=""):
    with _lock, _conn() as c:
        c.execute("INSERT INTO events(ts,type,mac,ip,detail) VALUES(?,?,?,?,?)",
                  (time.time(), type_, mac, ip, detail))


def list_events(limit=200):
    with _lock, _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))]


def get_setting(key, default=""):
    with _lock, _conn() as c:
        row = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default


def set_setting(key, value):
    with _lock, _conn() as c:
        c.execute("INSERT INTO settings(key,value) VALUES(?,?) "
                  "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))


init()
