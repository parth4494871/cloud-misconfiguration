"""
database.py — Database setup and helper functions.

Uses SQLite, a file-based database (no server needed).
Creates two tables:
  - users: for login/registration (email, password hash, role)
  - scans: for storing scan results (score, grade, findings)
"""

import sqlite3
import json
from datetime import datetime
from config import DATABASE


def get_db():
    """
    Open a connection to the SQLite database.
    row_factory = sqlite3.Row lets us access columns by name (row['email'])
    instead of by index (row[0]).
    """
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Create the tables if they don't exist yet.
    Called once when the app starts.
    """
    conn = get_db()
    cursor = conn.cursor()

    # --- Users table ---
    # Stores registered users with hashed passwords and roles.
    # role can be: 'admin', 'auditor', or 'user'
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # --- Scans table ---
    # Stores each scan's results: score, grade, and the full findings as JSON.
    # user_id links the scan to the user who ran it.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            score INTEGER,
            grade TEXT,
            findings TEXT,
            aws_endpoint TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()


# --- User Functions ---

def create_user(username, email, password_hash, role='user'):
    """Insert a new user into the database. Returns the new user's ID."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
        (username, email, password_hash, role)
    )
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return user_id


def get_user_by_email(email):
    """Look up a user by email. Returns a dict or None."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_id(user_id):
    """Look up a user by ID. Returns a dict or None."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


# --- Scan Functions ---

def save_scan(findings, score, grade, user_id=None, aws_endpoint=None):
    """Save a scan result to the database. Returns the scan ID."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO scans (user_id, score, grade, findings, aws_endpoint, timestamp)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (user_id, score, grade, json.dumps(findings), aws_endpoint,
         datetime.now().isoformat())
    )
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def get_scan_history(user_id=None):
    """
    Get all past scans, newest first.
    If user_id is given, only return that user's scans.
    """
    conn = get_db()
    cursor = conn.cursor()

    if user_id:
        cursor.execute(
            "SELECT * FROM scans WHERE user_id = ? ORDER BY id DESC", (user_id,)
        )
    else:
        cursor.execute("SELECT * FROM scans ORDER BY id DESC")

    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_scan_by_id(scan_id):
    """Get a single scan by its ID. Returns a dict or None."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None
