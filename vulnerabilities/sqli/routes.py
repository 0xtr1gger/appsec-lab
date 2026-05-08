"""
SQL Injection — Routes

Endpoints
---------
GET  /sqli/                     → renders the vulnerability page (tabs, widget, explanations)
POST /sqli/search/vulnerable    → executes raw SQL (intentionally vulnerable)
POST /sqli/search/secure        → executes parameterized SQL (safe)
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
# VULNERABLE endpoint
# ---------------------------------------------------------------------------

@sqli_bp.route("/sqli/search/vulnerable", methods=["POST"])
def search_vulnerable():
    """Search users — **intentionally vulnerable** to SQL injection."""
    query = request.form.get("q", "")
    db = get_db()

    # ⚠️  VULNERABLE: f-string interpolation in SQL
    sql = f"SELECT username, email, bio FROM users WHERE username LIKE '%{query}%'"

    try:
        results = db.execute(sql).fetchall()
        rows = [dict(r) for r in results]
    except Exception as exc:
        return jsonify(error=str(exc), query_used=sql), 400

    return jsonify(results=rows, query_used=sql)


# ---------------------------------------------------------------------------
# SECURE endpoint
# ---------------------------------------------------------------------------

@sqli_bp.route("/sqli/search/secure", methods=["POST"])
def search_secure():
    """Search users — **secure** parameterized query."""
    query = request.form.get("q", "")
    db = get_db()

    # ✅ SECURE: parameterized query
    sql = "SELECT username, email, bio FROM users WHERE username LIKE ?"
    param = f"%{query}%"

    results = db.execute(sql, (param,)).fetchall()
    rows = [dict(r) for r in results]

    return jsonify(results=rows, query_used=sql)
