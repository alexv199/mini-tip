# db.py
import sqlite3
from pathlib import Path
from datetime import datetime

DB_PATH = Path("tip.db")

def get_connection():
    # Connect to SQLite and return rows as dict-like objects
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cur = conn.cursor()

    # indicators: stores threat indicators
    cur.execute("""
    CREATE TABLE IF NOT EXISTS indicators (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT CHECK(type IN ('url','ip','domain','cidr')) NOT NULL,
        value TEXT NOT NULL,
        source TEXT NOT NULL,
        first_seen TEXT,
        last_seen TEXT,
        tags TEXT,
        confidence INTEGER DEFAULT 50 CHECK(confidence BETWEEN 0 AND 100),
        status TEXT DEFAULT 'active',
        UNIQUE(value, source)
    );
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(value);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators(type);")

    # feed_runs: tracks each fetch attempt (for visibility/debugging)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS feed_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        items_ingested INTEGER DEFAULT 0,
        status TEXT,
        error_text TEXT
    );
    """)

    conn.commit()
    conn.close()

def upsert_indicator(ind):
    """
    ind = {
      "type": "url"|"ip"|"domain"|"cidr",
      "value": "string",
      "source": "urlhaus"|"spamhaus",
      "first_seen": "YYYY-MM-DDTHH:MM:SSZ" or None,
      "last_seen":  same as above,
      "tags": "comma,separated" or "",
      "confidence": int 0-100,
      "status": "active"|"inactive"
    }
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO indicators (type, value, source, first_seen, last_seen, tags, confidence, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(value, source) DO UPDATE SET
        last_seen=excluded.last_seen,
        tags=excluded.tags,
        status=excluded.status,
        confidence=excluded.confidence
    """, (
        ind["type"], ind["value"], ind["source"], ind.get("first_seen"),
        ind.get("last_seen"), ind.get("tags",""), ind.get("confidence",50),
        ind.get("status","active")
    ))
    conn.commit()
    conn.close()

def record_feed_run_start(source: str) -> int:
    conn = get_connection()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat() + "Z"
    cur.execute("""
        INSERT INTO feed_runs (source, started_at, status)
        VALUES (?, ?, ?)
    """, (source, now, "running"))
    conn.commit()
    run_id = cur.lastrowid
    conn.close()
    return run_id

def record_feed_run_end(run_id: int, items_ingested: int, status: str, error_text: str | None = None):
    conn = get_connection()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat() + "Z"
    cur.execute("""
        UPDATE feed_runs
        SET finished_at=?, items_ingested=?, status=?, error_text=?
        WHERE id=?
    """, (now, items_ingested, status, error_text, run_id))
    conn.commit()
    conn.close()
