import sqlite3
import json
from datetime import datetime


DATABASE = "scans.db"


def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            score INTEGER,
            grade TEXT,
            findings TEXT,
            timestamp TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_scan(findings, score, grade):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    timestamp = datetime.now().isoformat()

    cursor.execute("""
        INSERT INTO scans (score, grade, findings, timestamp)
        VALUES (?, ?, ?, ?)
    """, (
        score,
        grade,
        json.dumps(findings),
        timestamp
    ))

    scan_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return scan_id


def get_scan_history():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM scans
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]