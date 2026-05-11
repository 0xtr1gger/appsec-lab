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
        "<b>SQL injection (SQLi)</b> is a vulnerability that occurs when an application incorporates user-controlled input into a SQL query without proper validation or parameterization, which allows an attacker to alter the structure, logic, or execution of that query."
    ),
    "blog_url": "https://0xtr1gger.github.io/trigger_book/Hack-the-Web/Injection/SQLi/SQL-injection",

    # ── widget ────────────────────────────────────────────────
    "widget_template": "components/sqli_widget.html",

    # ── vulnerable tab ────────────────────────────────────────
    "vuln_code": """\
@sqli_bp.route("/sqli/filter/vulnerable")
def filter_vulnerable():
    category = request.args.get("category", "")
    db = get_db()

    # base query — show all products by default (if no category specified)
    sql = "SELECT name, description, price, category FROM products"

    # only apply filter if category is specified and not "all"
    if category != "" and category.lower() != "all":
        # VULNERABLE: f-string interpolation in SQL — user input is directly part of the query syntax
        sql = f"SELECT name, description, price, category FROM products WHERE category = '{category}'"

    try:
        results = db.execute(sql).fetchall()
        rows = [dict(r) for r in results]
    except Exception as exc:
        return jsonify(error=str(exc), query_used=sql), 400

    return jsonify(results=rows, query_used=sql)
""",

    "vuln_explanation": (
        "The <code>category</code> parameter is inserted directly into the SQL "
        "query using Python string interpolation. Because the application mixes "
        "user-controlled input with SQL syntax, an attacker can break out of "
        "the intended query structure and inject additional SQL commands.<br><br>"

        "For example, the payload:<br><br>"

        "<code>' UNION SELECT username, password, email, role FROM users --</code>"
        "<br><br>"

        "transforms the original query into a new SQL statement containing a "
        "<code>UNION SELECT</code>. The <code>UNION</code> operator combines "
        "the results of multiple <code>SELECT</code> queries into a single "
        "result set, allowing attacker-controlled data to be returned alongside "
        "legitimate application data.<br><br>"

        "The trailing <code>--</code> comments out the remaining portion of "
        "the original query to prevent syntax errors. For a successful "
        "<code>UNION</code>-based SQL injection attack, both queries must "
        "return the same number of columns with compatible data types.<br><br>"

        "In this demo, the injected query extracts data from the "
        "<code>users</code> table and displays it inside the product listing, "
        "demonstrating how SQLi can expose sensitive database contents."
    ),

    # ── secure tab ────────────────────────────────────────────
    "secure_code": """\
@sqli_bp.route("/sqli/filter/secure")
def filter_secure():
    category = request.args.get("category", "")
    db = get_db()

    # base query — show all products by default (if no category specified)
    sql = "SELECT name, description, price, category FROM products"
    params = ()

    # only apply filter if category is specified and not "all"
    if category != "" and category.lower() != "all":
        # SECURE: parameterized query — user input is never part of the SQL syntax
        sql = "SELECT name, description, price, category FROM products WHERE category = ?"
        params = (category,)

    try:
        results = db.execute(sql, params).fetchall()
        rows = [dict(r) for r in results]
    except Exception as exc:
        return jsonify(error=str(exc), query_used=sql), 400

    return jsonify(results=rows, query_used=sql)
""",


    "secure_explanation": (
        "The secure implementation uses a parameterized query with a "
        "<code>?</code> placeholder instead of directly concatenating user "
        "input into the SQL statement. The SQL query structure and the user-"
        "supplied value are sent to the database <em>separately</em>, so the database"
        "always treats the input as a literal string — never as SQL syntax.<br><br>"

        "Even if an attacker submits a payload like:<br><br>"

        "<code>' UNION SELECT username, password, email, role FROM users --</code>"
        "<br><br>"

        "the database interprets the input as a literal string value "
        "for the <code>category</code> field instead of executing it as SQL. "
        "So the injection attempt fails and no sensitive data is exposed.<br><br>"

        "Parameterized queries are one of the most effective defenses against "
        "SQL injection because they enforce a strict separation between "
        "application data and SQL syntax."
    ),

}
