"""
Cross-Site Scripting (Reflected) — Routes

Endpoints
---------
GET   /xss/                     → renders the vulnerability page
GET   /xss/search/vulnerable    → searches products, reflects query WITHOUT escaping (intentionally vulnerable)
GET   /xss/search/secure        → searches products, reflects query WITH Jinja2 auto-escaping (safe)
"""

# pyrefly: ignore [missing-import]
from flask import Blueprint, jsonify, render_template, request
from markupsafe import Markup

from database import get_db
from vulnerabilities.xss.content import VULN_META

xss_bp = Blueprint("xss", __name__)


def search_products(query: str) -> list[dict]:
    """Search products by name or description (case-insensitive LIKE)."""
    db = get_db()
    sql = (
        "SELECT name, description, price, category, image_emoji "
        "FROM products "
        "WHERE name LIKE ? OR description LIKE ? "
        "ORDER BY name"
    )
    pattern = f"%{query}%"
    rows = db.execute(sql, (pattern, pattern)).fetchall()
    return [dict(r) for r in rows]


@xss_bp.route("/xss/")
def index():
    """Render the Cross-Site Scripting lab page."""
    return render_template("xss_vulnerability_page.html", vuln=VULN_META)


# ---------------------------------------------------------------------------
# VULNERABLE endpoint
# ---------------------------------------------------------------------------

@xss_bp.route("/xss/search/vulnerable")
def search_vulnerable():
    """Search products — INTENTIONALLY VULNERABLE to reflected XSS.

    The query value is wrapped in Markup() which tells Jinja2 to skip
    auto-escaping, so any HTML/JS in the input is rendered verbatim.
    """
    query = request.args.get("q", "")
    if not query:
        return jsonify(error="No search query provided"), 400

    # VULNERABLE: wrap user input in Markup() to bypass Jinja2 auto-escaping.
    # The raw HTML/JS in `query` is inserted into the page without encoding.
    results = search_products(query)
    rendered = render_template(
        "components/xss_results.html",
        query=Markup(query),
        results=results,
    )
    return jsonify(rendered_html=rendered, query_used=query)


# ---------------------------------------------------------------------------
# SECURE endpoint
# ---------------------------------------------------------------------------

@xss_bp.route("/xss/search/secure")
def search_secure():
    """Search products — secure implementation with Jinja2 auto-escaping."""
    query = request.args.get("q", "")
    if not query:
        return jsonify(error="No search query provided"), 400

    # SECURE: pass the raw string directly to the template.
    # Jinja2 auto-escaping converts special HTML characters
    # (<, >, ", ', &) into their HTML entity equivalents,
    # preventing the browser from interpreting them as markup.
    results = search_products(query)
    rendered = render_template(
        "components/xss_results.html",
        query=query,
        results=results,
    )
    return jsonify(rendered_html=rendered, query_used=query)
