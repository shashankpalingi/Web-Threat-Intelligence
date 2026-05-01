import sqlite3
import json
import os
from datetime import datetime, timedelta


DB_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(DB_DIR, "threat_intel.db")


def get_connection():
    """Get a SQLite connection with row factory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize the database schema."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            domain TEXT,
            threat_score REAL,
            threat_label TEXT,
            prediction TEXT,
            confidence REAL,
            features_json TEXT,
            explanation_json TEXT,
            scan_type TEXT DEFAULT 'url_scan',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_scan_timestamp
        ON scan_logs(timestamp DESC)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_scan_label
        ON scan_logs(threat_label)
    """)

    conn.commit()
    conn.close()
    print("✅ Database initialized at", DB_PATH)


def log_scan(url, domain, threat_score, threat_label, prediction,
             confidence, features=None, explanation=None):
    """Log a scan result to the database."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scan_logs
        (url, domain, threat_score, threat_label, prediction,
         confidence, features_json, explanation_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        url,
        domain,
        threat_score,
        threat_label,
        prediction,
        confidence,
        json.dumps(features) if features else None,
        json.dumps(explanation) if explanation else None
    ))

    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    return scan_id


def get_scan_history(limit=50, offset=0, label_filter=None):
    """Get recent scan history."""
    conn = get_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM scan_logs"
    params = []

    if label_filter:
        query += " WHERE threat_label = ?"
        params.append(label_filter)

    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]


def get_stats():
    """Get aggregated statistics for the dashboard."""
    conn = get_connection()
    cursor = conn.cursor()

    stats = {}

    # Total scans
    cursor.execute("SELECT COUNT(*) as total FROM scan_logs")
    stats["total_scans"] = cursor.fetchone()["total"]

    # Label distribution
    cursor.execute("""
        SELECT threat_label, COUNT(*) as count
        FROM scan_logs
        GROUP BY threat_label
    """)
    stats["label_distribution"] = {row["threat_label"]: row["count"] for row in cursor.fetchall()}

    # Average threat score
    cursor.execute("SELECT AVG(threat_score) as avg_score FROM scan_logs")
    avg = cursor.fetchone()["avg_score"]
    stats["avg_threat_score"] = round(avg, 1) if avg else 0

    # Recent scan count (last 24h)
    cursor.execute("""
        SELECT COUNT(*) as recent
        FROM scan_logs
        WHERE timestamp >= datetime('now', '-1 day')
    """)
    stats["scans_last_24h"] = cursor.fetchone()["recent"]

    # Scans per day (last 7 days)
    cursor.execute("""
        SELECT DATE(timestamp) as date, COUNT(*) as count
        FROM scan_logs
        WHERE timestamp >= datetime('now', '-7 days')
        GROUP BY DATE(timestamp)
        ORDER BY date
    """)
    stats["daily_scans"] = [{"date": row["date"], "count": row["count"]} for row in cursor.fetchall()]

    # Top threat domains
    cursor.execute("""
        SELECT domain, COUNT(*) as count, AVG(threat_score) as avg_score
        FROM scan_logs
        WHERE threat_label IN ('WARN', 'BLOCK')
        GROUP BY domain
        ORDER BY count DESC
        LIMIT 10
    """)
    stats["top_threat_domains"] = [
        {"domain": row["domain"], "count": row["count"], "avg_score": round(row["avg_score"], 1)}
        for row in cursor.fetchall()
    ]

    conn.close()
    return stats


# Initialize DB on import
init_db()
