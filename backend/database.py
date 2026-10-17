"""
database.py — SQLite log of every scan, used by the dashboard.
Only the domain is stored, never the full URL: the extension checks every page
a user opens, and paths/queries can hold private data (search terms, tokens).
Rows older than 30 days are deleted automatically.
"""

import datetime
import os
import sqlite3

DB_PATH = os.environ.get("PHISHGUARD_DB", os.path.join(os.path.dirname(__file__), "phishguard.db"))
RETENTION_DAYS = 30


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                domain        TEXT NOT NULL,
                result        TEXT NOT NULL,
                risk_score    REAL NOT NULL,
                response_time REAL NOT NULL,
                timestamp     TEXT NOT NULL
            )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_time ON scans(timestamp)")


def log_scan(domain: str, result: str, risk_score: float, response_time: float):
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    cutoff = (now - datetime.timedelta(days=RETENTION_DAYS)).isoformat()
    with _connect() as conn:
        conn.execute("INSERT INTO scans (domain, result, risk_score, response_time, timestamp) "
                     "VALUES (?, ?, ?, ?, ?)",
                     (domain[:253], result, risk_score, round(response_time, 4), now.isoformat()))
        conn.execute("DELETE FROM scans WHERE timestamp < ?", (cutoff,))


def get_stats() -> dict:
    with _connect() as conn:
        t = conn.execute("""
            SELECT COUNT(*) AS total,
                   SUM(result = 'PHISHING')   AS phishing,
                   SUM(result = 'SUSPICIOUS') AS suspicious,
                   SUM(result = 'SAFE')       AS safe,
                   AVG(response_time)         AS avg_time
            FROM scans""").fetchone()
        daily = conn.execute("""
            SELECT DATE(timestamp) AS day, COUNT(*) AS total, SUM(result = 'PHISHING') AS phishing
            FROM scans WHERE timestamp >= DATE('now', '-7 days')
            GROUP BY day ORDER BY day""").fetchall()
        top = conn.execute("""
            SELECT domain, COUNT(*) AS count FROM scans
            WHERE result != 'SAFE' GROUP BY domain ORDER BY count DESC LIMIT 10""").fetchall()

    total = t["total"] or 0
    return {
        "total_scans": total,
        "phishing_count": t["phishing"] or 0,
        "suspicious_count": t["suspicious"] or 0,
        "safe_count": t["safe"] or 0,
        "detection_rate": round((t["phishing"] or 0) / total * 100, 2) if total else 0,
        "avg_response_time_ms": round((t["avg_time"] or 0) * 1000, 1),
        "daily_breakdown": [dict(r) for r in daily],
        "top_threats": [dict(r) for r in top],
    }


def get_recent(limit: int = 20) -> list:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


init_db()
