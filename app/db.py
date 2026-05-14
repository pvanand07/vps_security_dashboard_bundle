import sqlite3
from pathlib import Path
from .config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    source TEXT,
    severity TEXT,
    category TEXT,
    ip TEXT,
    username TEXT,
    message TEXT,
    raw TEXT,
    fingerprint TEXT UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
"""

def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn

def insert_event(event):
    conn = connect()
    with conn:
        conn.execute(
            """INSERT OR IGNORE INTO events
            (ts, source, severity, category, ip, username, message, raw, fingerprint)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (event.get("ts"), event.get("source"), event.get("severity"), event.get("category"),
             event.get("ip"), event.get("username"), event.get("message"), event.get("raw"), event.get("fingerprint"))
        )
    conn.close()

def query_events(limit=200, source=None, severity=None, ip=None):
    conn = connect()
    sql = "SELECT * FROM events WHERE 1=1"
    params = []
    if source:
        sql += " AND source = ?"; params.append(source)
    if severity:
        sql += " AND severity = ?"; params.append(severity)
    if ip:
        sql += " AND ip = ?"; params.append(ip)
    sql += " ORDER BY id DESC LIMIT ?"; params.append(limit)
    rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    conn.close()
    return rows

def summary():
    conn = connect()
    total = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
    by_sev = [dict(r) for r in conn.execute("SELECT severity, COUNT(*) count FROM events GROUP BY severity").fetchall()]
    by_cat = [dict(r) for r in conn.execute("SELECT category, COUNT(*) count FROM events GROUP BY category ORDER BY count DESC LIMIT 10").fetchall()]
    top_ips = [dict(r) for r in conn.execute("SELECT ip, COUNT(*) count FROM events WHERE ip IS NOT NULL AND ip != '' GROUP BY ip ORDER BY count DESC LIMIT 100").fetchall()]
    recent_high = [dict(r) for r in conn.execute("SELECT * FROM events WHERE severity IN ('critical','high') ORDER BY id DESC LIMIT 20").fetchall()]
    conn.close()
    return {"total": total, "by_severity": by_sev, "by_category": by_cat, "top_ips": top_ips, "recent_high": recent_high}
