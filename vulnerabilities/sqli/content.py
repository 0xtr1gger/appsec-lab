"""
SQL Injection — Page metadata & content

This dict drives the vulnerability page template.  The ``vuln_code`` and
``secure_code`` fields contain the *actual* source that runs on the server,
so readers can see exactly what is happening.
"""

VULN_META = {
    # ── identity ──────────────────────────────────────────────
    "id": "sqli",
    "title": "SQL Injection (SQLi)",
    "short_title": "SQL Injection",
    "icon": "💉",
    "cwe": "CWE-89",
    "order": 1,

    # ── intro ─────────────────────────────────────────────────
    "description": (
        "SQL Injection occurs when an attacker is able to insert or "
        "&ldquo;inject&rdquo; malicious SQL code into a query that the "
        "application sends to its database. Instead of treating user "
        "input as <em>data</em>, the database interprets it as <em>code</em>, "
        "allowing the attacker to read, modify, or delete data they "
        "should never have access to."
    ),
    "blog_url": "http://localhost:5000/sqli",

    # ── widget ────────────────────────────────────────────────
    "widget_template": "components/sqli_widget.html",

    # ── vulnerable tab ────────────────────────────────────────
    "vuln_code": """\
@sqli_bp.route("/sqli/filter/vulnerable")
def filter_vulnerable():
    category = request.args.get("category", "")
    db = get_db()

    # ⚠️  VULNERABLE: f-string interpolation in SQL
    sql = f"SELECT name, description, price, category "\\
          f"FROM products WHERE category = '{category}'"

    try:
        results = db.execute(sql).fetchall()
        rows = [dict(r) for r in results]
    except Exception as exc:
        return jsonify(error=str(exc), query_used=sql), 400

    return jsonify(results=rows, query_used=sql)\
""",

    "vuln_explanation": (
        "The <code>category</code> query parameter is interpolated directly "
        "into the SQL string using an f-string. An attacker can close the "
        "surrounding quotes and inject arbitrary SQL — for example:<br><br>"
        "<code>' UNION SELECT username, password, email, role FROM users --</code>"
        "<br><br>"
        "This breaks out of the <code>WHERE</code> clause and appends "
        "a <code>UNION SELECT</code> that dumps every username &amp; "
        "password from the <code>users</code> table. The results are "
        "rendered right alongside regular product data since they share the "
        "same number of columns."
    ),

    # ── secure tab ────────────────────────────────────────────
    "secure_code": """\
@sqli_bp.route("/sqli/filter/secure")
def filter_secure():
    category = request.args.get("category", "")
    db = get_db()

    # ✅ SECURE: Parameterized query
    sql = "SELECT name, description, price, category "\\
          "FROM products WHERE category = ?"

    try:
        results = db.execute(sql, (category,)).fetchall()
        rows = [dict(r) for r in results]
    except Exception as exc:
        return jsonify(error=str(exc), query_used=sql), 400

    return jsonify(results=rows, query_used=sql)\
""",

    "secure_explanation": (
        "The parameterized query uses a <code>?</code> placeholder. "
        "The database driver sends the SQL structure and the user value "
        "<em>separately</em>, so the database always treats the input as "
        "a literal string — never as SQL syntax. The <code>UNION</code> "
        "payload is simply searched for as a category name and returns "
        "no results."
    ),
}
