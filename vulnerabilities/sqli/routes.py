"""
SQL Injection — Routes

Endpoints
---------
GET  /sqli/                       → renders the vulnerability page (tabs, widget, explanations)
GET  /sqli/categories             → returns distinct product categories (JSON)
GET  /sqli/filter/vulnerable      → filters products by category using raw SQL (intentionally vulnerable)
GET  /sqli/filter/secure          → filters products by category using parameterized SQL (safe)
"""

# pyrefly: ignore [missing-import]
from flask import Blueprint, jsonify, render_template, request

from database import get_db
from vulnerabilities.sqli.content import VULN_META

sqli_bp = Blueprint("sqli", __name__)


@sqli_bp.route("/sqli/")
def index():
    """Render the SQL Injection lab page."""
    return render_template("vulnerability_page.html", vuln=VULN_META)


# ---------------------------------------------------------------------------
# Categories helper
# ---------------------------------------------------------------------------

@sqli_bp.route("/sqli/categories")
def categories():
    """Return distinct product categories for the filter dropdown."""
    db = get_db()
    rows = db.execute("SELECT DISTINCT category FROM products ORDER BY category").fetchall()
    cats = [r["category"] for r in rows]
    return jsonify(categories=cats)


# ---------------------------------------------------------------------------
# VULNERABLE endpoint
# ---------------------------------------------------------------------------

@sqli_bp.route("/sqli/filter/vulnerable")
def filter_vulnerable():
    """Filter products by category — **intentionally vulnerable** to SQL injection.

    The category value is interpolated directly into the SQL string via an
    f-string, enabling UNION-based SQL injection.
    """
    category = request.args.get("category", "")
    db = get_db()

    # ⚠️  VULNERABLE: f-string interpolation in SQL
    sql = f"SELECT name, description, price, category FROM products WHERE category = '{category}'"

    try:
        results = db.execute(sql).fetchall()
        rows = [dict(r) for r in results]
    except Exception as exc:
        return jsonify(error=str(exc), query_used=sql), 400

    return jsonify(results=rows, query_used=sql)


# ---------------------------------------------------------------------------
# SECURE endpoint
# ---------------------------------------------------------------------------

@sqli_bp.route("/sqli/filter/secure")
def filter_secure():
    """Filter products by category — **secure** parameterized query."""
    category = request.args.get("category", "")
    db = get_db()

    # ✅ SECURE: parameterized query — user input is never part of the SQL syntax
    sql = "SELECT name, description, price, category FROM products WHERE category = ?"

    try:
        results = db.execute(sql, (category,)).fetchall()
        rows = [dict(r) for r in results]
    except Exception as exc:
        return jsonify(error=str(exc), query_used=sql), 400

    return jsonify(results=rows, query_used=sql)