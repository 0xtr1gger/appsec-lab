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
    price       REAL NOT NULL,
    category    TEXT NOT NULL,
    image_emoji TEXT DEFAULT '☕'
);
"""

SEED_SQL = """
INSERT OR IGNORE INTO users (username, email, password, role, bio) VALUES
    ('admin',   'admin@brewhaus.local',    'S3cur3!Admin#2024', 'admin', 'System administrator'),
    ('alice',   'alice@example.com',       'alice_Pass!99',     'user',  'Security researcher'),
    ('bob',     'bob@example.com',         'b0bbyTables#1',     'user',  'Bug bounty hunter'),
    ('charlie', 'charlie@example.com',     'Ch4rl!3_2024',      'user',  'Pentester'),
    ('eve',     'eve@example.com',         'ev1l_Passw0rd!',    'user',  'Definitely not malicious');

INSERT OR IGNORE INTO products (name, description, price, category, image_emoji) VALUES
    ('Espresso',       'Rich and bold single shot',              3.50,  'Coffee',      '☕'),
    ('Cappuccino',     'Espresso with steamed milk foam',        4.50,  'Coffee',      '☕'),
    ('Latte',          'Smooth espresso with lots of milk',      4.75,  'Coffee',      '☕'),
    ('Mocha',          'Chocolate meets espresso',               5.25,  'Coffee',      '🍫'),
    ('Americano',      'Espresso diluted with hot water',        3.75,  'Coffee',      '☕'),
    ('Matcha Latte',   'Japanese green tea with steamed milk',   5.50,  'Tea',         '🍵'),
    ('Chai Latte',     'Spiced tea with frothy milk',            4.75,  'Tea',         '🍵'),
    ('Earl Grey',      'Classic bergamot black tea',             3.25,  'Tea',         '🍵'),
    ('Iced Tea',       'Refreshing cold-brewed tea',             3.75,  'Cold Drinks', '🧊'),
    ('Lemonade',       'Freshly squeezed with a hint of mint',   4.00,  'Cold Drinks', '🍋'),
    ('Iced Coffee',    'Cold brew served over ice',              4.50,  'Cold Drinks', '🧊'),
    ('Hot Chocolate',  'Rich cocoa with whipped cream',          4.50,  'Specialty',   '🍫'),
    ('Affogato',       'Vanilla gelato drowned in espresso',     5.75,  'Specialty',   '🍨'),
    ('Turmeric Latte', 'Golden milk with warming spices',        5.25,  'Specialty',   '✨');
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
