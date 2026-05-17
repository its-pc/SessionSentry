"""
models.py — SQLite database layer (pure sqlite3, no ORM)
"""

import sqlite3
import os
import uuid

DB_PATH = os.path.join(os.path.dirname(__file__), 'database', 'database.db')


def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        login_time TEXT DEFAULT (datetime('now')),
        logout_time TEXT,
        ip_address TEXT,
        user_agent TEXT,
        browser TEXT,
        os_info TEXT,
        is_active INTEGER DEFAULT 1,
        is_hijacked INTEGER DEFAULT 0,
        risk_score REAL DEFAULT 0.0,
        risk_reason TEXT,
        label INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS request_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        timestamp TEXT DEFAULT (datetime('now')),
        page TEXT,
        referrer TEXT,
        request_method TEXT,
        browser TEXT,
        os_info TEXT
    );

    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        user_id INTEGER,
        username TEXT,
        timestamp TEXT DEFAULT (datetime('now')),
        risk_score REAL DEFAULT 0.0,
        reason TEXT,
        alert_type TEXT DEFAULT 'hijacking',
        resolved INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS feature_settings (
        feature_name TEXT PRIMARY KEY,
        enabled INTEGER DEFAULT 1
    );
    """)
    conn.commit()

    default_features = [
        'ip_change',
        'ip_frequency',
        'ip_mismatch',
        'browser_change',
        'os_change',
        'cookie_reuse',
        'session_duration',
        'session_idle_time',
        'request_rate',
        'request_variance',
        'post_get_ratio',
        'total_requests',
        'page_depth',
        'page_sequence_entropy',
        'admin_page_attempt',
        'direct_page_access',
        'click_interval_avg',
        'click_interval_std',
        'night_activity_flag',
    ]

    for feature in default_features:
        conn.execute(
            'INSERT OR IGNORE INTO feature_settings (feature_name, enabled) VALUES (?, 1)',
            (feature,)
        )

    conn.commit()
    conn.close()


def make_session_id():
    return str(uuid.uuid4())[:16].upper()


def row_to_dict(row):
    return dict(row) if row else None


def rows_to_list(rows):
    return [dict(r) for r in rows]
