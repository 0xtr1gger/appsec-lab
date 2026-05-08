"""
AppSec Lab — Database Setup & Helpers

Provides SQLite initialization, seeding, and per-request connection
management via Flask's `g` object.
"""

import os
import sqlite3

# pyrefly: ignore [missing-import]
from flask import current_app, g

# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------

def get_db():
    """Return a SQLite connection for the current request.

    The connection is stored on Flask's ``g`` object so that every call
    within the same request reuses the same connection.
    """
    if "db" not in g:
        g.db = sqlite3.connect(
            current_app.config["DATABASE_PATH"],
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        g.db.row_factory = sqlite3.Row  # dict-like access
    return g.db


def close_db(e=None):
    """Close the database connection at the end of the request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------------------------------------------------------------------------
# Schema & seed data
# ---------------------------------------------------------------------------

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT    NOT NULL UNIQUE,
    email    TEXT    NOT NULL,
    password TEXT    NOT NULL,
    role     TEXT    DEFAULT 'user',
    bio      TEXT
);

CREATE TABLE IF NOT EXISTS products (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    description TEXT,
    price       REAL,
    category    TEXT
);
"""

SEED_SQL = """
INSERT OR IGNORE INTO users (username, email, password, role, bio) VALUES
    ('admin',   'admin@appsec-lab.local',  'admin123',       'admin', 'System administrator'),
    ('alice',   'alice@example.com',       'password123',    'user',  'Security researcher'),
    ('bob',     'bob@example.com',         'bob2024',        'user',  'Bug bounty hunter'),
    ('charlie', 'charlie@example.com',     'charlie!',       'user',  'Pentester'),
    ('eve',     'eve@example.com',         'evil_password',  'user',  'Definitely not malicious');

INSERT OR IGNORE INTO products (name, description, price, category) VALUES
    ('Web Security Handbook',   'Complete guide to web application security',       49.99,  'Books'),
    ('Burp Suite Pro License',  'Annual license for Burp Suite Professional',       449.00, 'Tools'),
    ('OWASP Testing Guide',     'Official OWASP testing methodology',              0.00,   'Books'),
    ('Pentest Lab Access',      '30-day access to online penetration testing labs', 29.99,  'Training'),
    ('Security+ Study Guide',   'CompTIA Security+ certification prep',            39.99,  'Books');
"""


def init_db():
    """Create tables and seed sample data.

    Called once when the application starts.  Safe to call repeatedly thanks
    to ``CREATE TABLE IF NOT EXISTS`` and ``INSERT OR IGNORE``.
    """
    db_path = current_app.config["DATABASE_PATH"]

    # Ensure the data/ directory exists
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    db = sqlite3.connect(db_path)
    db.executescript(SCHEMA_SQL)
    db.executescript(SEED_SQL)
    db.commit()
    db.close()
