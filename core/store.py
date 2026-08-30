"""
core/store.py — Capa de datos de NetScope (SQLite).

Decisiones de fondo del esquema:

  - La MAC NO es la identidad del equipo. Un telefono moderno rota su MAC por
    red, asi que usarla como clave primaria convertiria cada reconexion en un
    "equipo nuevo". La verdad persistente es la tabla `identities`, y la MAC es
    solo UNA senal mas (ver core/identity.py).

  - Todo lleva `site_id`. Cada instalacion administra un sitio (casa O empresa),
    pero el esquema distingue sitios desde el dia uno: unificar dos sitios el dia
    de manana es una migracion de datos, no una reescritura.

  - El trafico se guarda AGREGADO POR VENTANA, nunca paquete por paquete. Esa es
    la diferencia entre una BD de decenas de MB al ano y una de cientos de GB en
    semanas.

  - `observations` es un log crudo, efimero (se purga). `identities` no se borra
    sola nunca.

Disciplina de concurrencia: SQLite en modo WAL admite un escritor y varios
lectores sin bloquearse. Para un usuario y dos redes, sobra. No metas Postgres.
"""

import os
import time
import sqlite3
import threading

DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "netscope.db")
_lock = threading.Lock()


def _conn():
    c = sqlite3.connect(DB, timeout=5)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    return c


# --------------------------------------------------------------------------- #
#  Esquema
# --------------------------------------------------------------------------- #
SCHEMA = """
CREATE TABLE IF NOT EXISTS sites(
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    name     TEXT NOT NULL,
    cidr     TEXT,
    notes    TEXT,
    created  REAL
);

-- La verdad persistente. Un equipo fisico = una identidad, aunque cambie de MAC.
CREATE TABLE IF NOT EXISTS identities(
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id       INTEGER NOT NULL REFERENCES sites(id),
    label         TEXT,               -- etiqueta automatica (mejor nombre visto)
    label_manual  TEXT,               -- etiqueta puesta a mano: CONGELA la identidad
    vendor        TEXT,               -- ultimo fabricante (OUI) conocido
    confidence    REAL DEFAULT 0,     -- suma normalizada de pesos de sus senales
    trusted       INTEGER DEFAULT 0,
    first_seen    REAL,
    last_seen     REAL,
    notes         TEXT
);

-- Las senales que enlazan observaciones con identidades.
-- kind: mac | mac_random | hostname | dhcp_fp | os | port_set | schedule
CREATE TABLE IF NOT EXISTS identity_signals(
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_id  INTEGER NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,
    value        TEXT NOT NULL,
    weight       REAL NOT NULL,
    first_seen   REAL,
    last_seen    REAL,
    UNIQUE(identity_id, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_signals_lookup ON identity_signals(kind, value);

-- Log crudo append-only. Efimero: se purga a los pocos dias (retencion).
CREATE TABLE IF NOT EXISTS observations(
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id      INTEGER NOT NULL,
    ts           REAL,
    source       TEXT,               -- arp | dhcp | mdns | nmap | traffic
    identity_id  INTEGER,            -- se rellena al resolver
    mac          TEXT,
    ip           TEXT,
    hostname     TEXT,
    vendor       TEXT,
    dhcp_fp      TEXT,
    os_guess     TEXT,
    raw_json     TEXT
);
CREATE INDEX IF NOT EXISTS idx_obs_ts ON observations(ts);
CREATE INDEX IF NOT EXISTS idx_obs_identity ON observations(identity_id);

-- Trafico AGREGADO por ventana (una fila por identidad+peer+proto+puerto+ventana).
CREATE TABLE IF NOT EXISTS traffic_samples(
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id       INTEGER NOT NULL,
    window_start  REAL,
    identity_id   INTEGER,
    peer_ip       TEXT,
    peer_host     TEXT,
    proto         TEXT,
    port          INTEGER,
    bytes_in      INTEGER DEFAULT 0,
    bytes_out     INTEGER DEFAULT 0,
    packets       INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_traffic_window ON traffic_samples(window_start);
CREATE INDEX IF NOT EXISTS idx_traffic_identity
    ON traffic_samples(identity_id, window_start);

CREATE TABLE IF NOT EXISTS ports(
    identity_id  INTEGER NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    port         INTEGER,
    proto        TEXT,
    service      TEXT,
    product      TEXT,
    version      TEXT,
    ts           REAL,
    PRIMARY KEY(identity_id, port, proto)
);

CREATE TABLE IF NOT EXISTS events(
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           REAL,
    site_id      INTEGER,
    identity_id  INTEGER,
    type         TEXT,
    severity     TEXT DEFAULT 'info',
    detail       TEXT,
    seen         INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);

CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);

-- Datos descriptivos del equipo (modelo, SO, fabricante real, nombre UPnP...).
-- Van APARTE de las senales de identidad a proposito: son informativos y NO
-- deben influir en la fusion (dos moviles del mismo modelo no son el mismo).
CREATE TABLE IF NOT EXISTS identity_facts(
    identity_id  INTEGER NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    key          TEXT NOT NULL,
    value        TEXT,
    ts           REAL,
    PRIMARY KEY(identity_id, key)
);
"""


def _aside_legacy_db():
    """Aparta un netscope.db con el esquema viejo (basado en MAC).

    El esquema v2 reusa el nombre de tabla `events` con columnas distintas, asi
    que `CREATE TABLE IF NOT EXISTS` no basta: hay que empezar con BD limpia.
    No se borra nada; el fichero viejo queda como `netscope.db.old-<ts>`.
    """
    if not os.path.exists(DB):
        return
    try:
        c = sqlite3.connect(DB, timeout=5)
        try:
            has_identities = c.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='identities'"
            ).fetchone() is not None
            has_devices = c.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='devices'"
            ).fetchone() is not None
        finally:
            c.close()
        if has_identities or not has_devices:
            return  # ya es v2, o BD vacia/ajena: no tocar
        backup = f"{DB}.old-{int(time.time())}"
        os.replace(DB, backup)
        for suffix in ("-wal", "-shm"):
            side = DB + suffix
            if os.path.exists(side):
                os.replace(side, backup + suffix)
        print(f"  NetScope: BD anterior (esquema viejo) apartada en {backup}")
    except Exception as e:
        print(f"  NetScope: no pude apartar la BD anterior: {e}")


def init():
    _aside_legacy_db()
    with _lock, _conn() as c:
        c.executescript(SCHEMA)


# --------------------------------------------------------------------------- #
#  Sitios
# --------------------------------------------------------------------------- #
def ensure_site(name, cidr="", notes=""):
    """Devuelve el id del sitio con ese nombre; lo crea si no existe."""
    with _lock, _conn() as c:
        row = c.execute("SELECT id FROM sites WHERE name=?", (name,)).fetchone()
        if row:
            return row["id"]
        cur = c.execute(
            "INSERT INTO sites(name,cidr,notes,created) VALUES(?,?,?,?)",
            (name, cidr, notes, time.time()))
        return cur.lastrowid


def list_sites():
    with _lock, _conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM sites ORDER BY id")]


# --------------------------------------------------------------------------- #
#  Identidades y senales
#  (la LOGICA de fusion vive en core/identity.py; aqui solo persistimos)
# --------------------------------------------------------------------------- #
def create_identity(site_id, label=""):
    now = time.time()
    with _lock, _conn() as c:
        cur = c.execute(
            "INSERT INTO identities(site_id,label,first_seen,last_seen) "
            "VALUES(?,?,?,?)", (site_id, label, now, now))
        return cur.lastrowid


def touch_identity(identity_id, ts=None):
    ts = ts or time.time()
    with _lock, _conn() as c:
        c.execute("UPDATE identities SET last_seen=? WHERE id=?", (ts, identity_id))


def set_identity_label_auto(identity_id, label):
    with _lock, _conn() as c:
        c.execute("UPDATE identities SET label=? WHERE id=? AND "
                  "(label_manual IS NULL OR label_manual='')", (label, identity_id))


def set_identity_label_manual(identity_id, label):
    """Etiqueta a mano: CONGELA la identidad y fija confianza al maximo.

    Con label vacio se descongela (vuelve a re-evaluarse por fusion); no forzamos
    la confianza en ese caso.
    """
    label = (label or "").strip()
    with _lock, _conn() as c:
        if label:
            c.execute("UPDATE identities SET label_manual=?, confidence=1.0 WHERE id=?",
                      (label, identity_id))
        else:
            c.execute("UPDATE identities SET label_manual='' WHERE id=?",
                      (identity_id,))


def set_identity_vendor(identity_id, vendor):
    vendor = (vendor or "").strip()
    if not vendor:
        return
    with _lock, _conn() as c:
        c.execute("UPDATE identities SET vendor=? WHERE id=?", (vendor, identity_id))


def set_identity_confidence(identity_id, conf):
    with _lock, _conn() as c:
        c.execute("UPDATE identities SET confidence=? WHERE id=? AND "
                  "(label_manual IS NULL OR label_manual='')", (conf, identity_id))


def set_identity_trusted(identity_id, trusted):
    with _lock, _conn() as c:
        c.execute("UPDATE identities SET trusted=? WHERE id=?",
                  (1 if trusted else 0, identity_id))


def is_frozen(identity_id):
    """True si la identidad tiene etiqueta manual (no se re-evalua por fusion)."""
    with _lock, _conn() as c:
        row = c.execute("SELECT label_manual FROM identities WHERE id=?",
                        (identity_id,)).fetchone()
        return bool(row and (row["label_manual"] or "").strip())


def upsert_signal(identity_id, kind, value, weight):
    """Agrega o refresca una senal de una identidad."""
    now = time.time()
    with _lock, _conn() as c:
        row = c.execute(
            "SELECT id FROM identity_signals WHERE identity_id=? AND kind=? AND value=?",
            (identity_id, kind, value)).fetchone()
        if row:
            c.execute("UPDATE identity_signals SET last_seen=?, weight=? WHERE id=?",
                      (now, weight, row["id"]))
        else:
            c.execute("INSERT INTO identity_signals"
                      "(identity_id,kind,value,weight,first_seen,last_seen) "
                      "VALUES(?,?,?,?,?,?)",
                      (identity_id, kind, value, weight, now, now))


def signals_of(identity_id):
    with _lock, _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT kind,value,weight,first_seen,last_seen FROM identity_signals "
            "WHERE identity_id=?", (identity_id,))]


def identities_matching_signal(site_id, kind, value):
    """Ids de identidades del sitio que ya tienen esta senal exacta."""
    with _lock, _conn() as c:
        return [r["identity_id"] for r in c.execute(
            "SELECT s.identity_id FROM identity_signals s "
            "JOIN identities i ON i.id = s.identity_id "
            "WHERE i.site_id=? AND s.kind=? AND s.value=?",
            (site_id, kind, value))]


def get_identity(identity_id):
    with _lock, _conn() as c:
        row = c.execute("SELECT * FROM identities WHERE id=?",
                        (identity_id,)).fetchone()
        return dict(row) if row else None


def all_identities(site_id=None):
    with _lock, _conn() as c:
        if site_id is None:
            rows = c.execute("SELECT * FROM identities ORDER BY last_seen DESC")
        else:
            rows = c.execute(
                "SELECT * FROM identities WHERE site_id=? ORDER BY last_seen DESC",
                (site_id,))
        return [dict(r) for r in rows]


def merge_identities(keep_id, drop_id):
    """Fusiona a mano dos identidades: mueve las senales de drop -> keep y borra drop."""
    with _lock, _conn() as c:
        sigs = c.execute("SELECT kind,value,weight FROM identity_signals "
                         "WHERE identity_id=?", (drop_id,)).fetchall()
        for s in sigs:
            c.execute("INSERT OR IGNORE INTO identity_signals"
                      "(identity_id,kind,value,weight,first_seen,last_seen) "
                      "VALUES(?,?,?,?,?,?)",
                      (keep_id, s["kind"], s["value"], s["weight"],
                       time.time(), time.time()))
        c.execute("UPDATE observations SET identity_id=? WHERE identity_id=?",
                  (keep_id, drop_id))
        c.execute("UPDATE traffic_samples SET identity_id=? WHERE identity_id=?",
                  (keep_id, drop_id))
        c.execute("DELETE FROM identities WHERE id=?", (drop_id,))


# --------------------------------------------------------------------------- #
#  Observaciones (log crudo, efimero)
# --------------------------------------------------------------------------- #
def record_observation(site_id, source, identity_id=None, mac="", ip="",
                       hostname="", vendor="", dhcp_fp="", os_guess="",
                       raw_json="", dedupe_secs=3600):
    """Registra una observacion cruda.

    `dedupe_secs`: si la ultima observacion de esta identidad es identica
    (misma fuente/mac/ip/hostname) y de hace menos de ese tiempo, NO se inserta
    otra fila. Sin esto, un re-escaneo cada 15 s multiplicaria la tabla por
    ~5.000 filas/dia por equipo. Pasa 0 para forzar siempre la insercion.
    """
    now = time.time()
    with _lock, _conn() as c:
        if dedupe_secs and identity_id is not None:
            prev = c.execute(
                "SELECT ts,source,mac,ip,hostname FROM observations "
                "WHERE identity_id=? ORDER BY ts DESC LIMIT 1",
                (identity_id,)).fetchone()
            if (prev and now - (prev["ts"] or 0) < dedupe_secs
                    and prev["source"] == source and (prev["mac"] or "") == mac
                    and (prev["ip"] or "") == ip
                    and (prev["hostname"] or "") == hostname):
                return
        c.execute(
            "INSERT INTO observations"
            "(site_id,ts,source,identity_id,mac,ip,hostname,vendor,dhcp_fp,"
            " os_guess,raw_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (site_id, now, source, identity_id, mac, ip, hostname,
             vendor, dhcp_fp, os_guess, raw_json))


def purge_observations(older_than_secs=30 * 86400):
    cutoff = time.time() - older_than_secs
    with _lock, _conn() as c:
        c.execute("DELETE FROM observations WHERE ts < ?", (cutoff,))


def last_observation(identity_id):
    """Ultima observacion cruda de una identidad (mac/ip/vendor conocidos)."""
    with _lock, _conn() as c:
        row = c.execute(
            "SELECT * FROM observations WHERE identity_id=? ORDER BY ts DESC LIMIT 1",
            (identity_id,)).fetchone()
        return dict(row) if row else None


def seed_data():
    """Fabricante y nombre por MAC conocida, para precargar las caches del scanner."""
    out = {"vendors": {}, "names": {}}
    with _lock, _conn() as c:
        rows = c.execute(
            "SELECT i.label AS label, i.vendor AS vendor, s.value AS mac "
            "FROM identity_signals s JOIN identities i ON i.id = s.identity_id "
            "WHERE s.kind IN ('mac','mac_random')")
        for r in rows:
            mac = (r["mac"] or "").lower()
            if not mac:
                continue
            if r["vendor"]:
                out["vendors"].setdefault(mac, r["vendor"])
            if r["label"]:
                out["names"].setdefault(mac, r["label"])
    return out


# --------------------------------------------------------------------------- #
#  Trafico agregado por ventana
# --------------------------------------------------------------------------- #
def add_traffic_window(site_id, window_start, identity_id, peer_ip, peer_host,
                       proto, port, bytes_in, bytes_out, packets):
    """Suma un agregado de ventana. Si ya existe esa clave de ventana, acumula."""
    with _lock, _conn() as c:
        row = c.execute(
            "SELECT id FROM traffic_samples WHERE site_id=? AND window_start=? AND "
            "identity_id IS ? AND peer_ip=? AND proto=? AND port=?",
            (site_id, window_start, identity_id, peer_ip, proto, port)).fetchone()
        if row:
            c.execute("UPDATE traffic_samples SET bytes_in=bytes_in+?, "
                      "bytes_out=bytes_out+?, packets=packets+? WHERE id=?",
                      (bytes_in, bytes_out, packets, row["id"]))
        else:
            c.execute(
                "INSERT INTO traffic_samples"
                "(site_id,window_start,identity_id,peer_ip,peer_host,proto,port,"
                " bytes_in,bytes_out,packets) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (site_id, window_start, identity_id, peer_ip, peer_host, proto,
                 port, bytes_in, bytes_out, packets))


def traffic_for_identity(identity_id, since=0):
    with _lock, _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM traffic_samples WHERE identity_id=? AND window_start>=? "
            "ORDER BY window_start DESC", (identity_id, since))]


def traffic_daily(site_id, identity_id, days=7):
    """Bytes in/out agregados por dia (para la grafica historica de la ficha)."""
    since = time.time() - days * 86400
    with _lock, _conn() as c:
        rows = c.execute(
            "SELECT CAST(window_start/86400 AS INT) AS day, "
            "       SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out "
            "FROM traffic_samples WHERE site_id=? AND identity_id=? AND window_start>=? "
            "GROUP BY day ORDER BY day", (site_id, identity_id, since))
        return [{"day_ts": r["day"] * 86400, "bytes_in": r["bytes_in"] or 0,
                 "bytes_out": r["bytes_out"] or 0} for r in rows]


def purge_traffic(older_than_secs=30 * 86400):
    cutoff = time.time() - older_than_secs
    with _lock, _conn() as c:
        c.execute("DELETE FROM traffic_samples WHERE window_start < ?", (cutoff,))


# --------------------------------------------------------------------------- #
#  Puertos
# --------------------------------------------------------------------------- #
def set_ports(identity_id, ports):
    """ports: lista de dicts {port, proto, service, product, version}."""
    now = time.time()
    with _lock, _conn() as c:
        for p in ports:
            c.execute(
                "INSERT INTO ports(identity_id,port,proto,service,product,version,ts) "
                "VALUES(?,?,?,?,?,?,?) "
                "ON CONFLICT(identity_id,port,proto) DO UPDATE SET "
                "service=excluded.service, product=excluded.product, "
                "version=excluded.version, ts=excluded.ts",
                (identity_id, int(p.get("port") or 0), p.get("proto", ""),
                 p.get("service", ""), p.get("product", ""), p.get("version", ""), now))


def ports_of(identity_id):
    with _lock, _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT port,proto,service,product,version FROM ports "
            "WHERE identity_id=? ORDER BY port", (identity_id,))]


# --------------------------------------------------------------------------- #
#  Eventos y ajustes
# --------------------------------------------------------------------------- #
def record_event(site_id, identity_id, type_, detail="", severity="info"):
    with _lock, _conn() as c:
        c.execute("INSERT INTO events(ts,site_id,identity_id,type,severity,detail) "
                  "VALUES(?,?,?,?,?,?)",
                  (time.time(), site_id, identity_id, type_, severity, detail))


def list_events(site_id=None, limit=200):
    with _lock, _conn() as c:
        if site_id is None:
            rows = c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
        else:
            rows = c.execute("SELECT * FROM events WHERE site_id=? "
                             "ORDER BY id DESC LIMIT ?", (site_id, limit))
        return [dict(r) for r in rows]


def set_fact(identity_id, key, value):
    """Guarda/actualiza un dato descriptivo del equipo (modelo, SO, etc.)."""
    value = (value or "").strip()
    if not value:
        return
    with _lock, _conn() as c:
        c.execute(
            "INSERT INTO identity_facts(identity_id,key,value,ts) VALUES(?,?,?,?) "
            "ON CONFLICT(identity_id,key) DO UPDATE SET "
            "value=excluded.value, ts=excluded.ts",
            (identity_id, key, value, time.time()))


def facts_of(identity_id):
    """Todos los datos descriptivos de una identidad como dict {key: value}."""
    with _lock, _conn() as c:
        return {r["key"]: r["value"] for r in c.execute(
            "SELECT key,value FROM identity_facts WHERE identity_id=?",
            (identity_id,))}


def get_setting(key, default=""):
    with _lock, _conn() as c:
        row = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default


def set_setting(key, value):
    with _lock, _conn() as c:
        c.execute("INSERT INTO settings(key,value) VALUES(?,?) "
                  "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                  (key, str(value)))


init()
