"""
Insecure Direct Object Reference (IDOR) — Page metadata & content

This dict drives the vulnerability page template. The ``vuln_code`` and
``secure_code`` fields contain the *actual* source that runs on the server,
so readers can see exactly what is happening.
"""

VULN_META = {
    # ── identity ──────────────────────────────────────────────
    "id": "idor",
    "title": "Insecure Direct Object Reference (IDOR)",
    "short_title": "IDOR",
    "icon": "🔑",
    "cwe": "CWE-639",
    "order": 4,

    # ── intro ─────────────────────────────────────────────────
    "description": (
        "<b>Insecure Direct Object Reference (IDOR)</b> occurs when an application "
        "provides direct access to objects based on user-supplied input without performing "
        "authorization checks. Attackers can exploit this by modifying parameters "
        "(such as IDs in URL paths, query parameters, or form data) to access resources "
        "belonging to other users, such as profiles, invoices, transactions, or system configuration."
    ),
    "blog_url": "https://0xtr1gger.github.io/trigger_book/Hack-the-Web/Access-Control/IDOR/Insecure-direct-object-reference",

    # ── widget ────────────────────────────────────────────────
    "widget_template": "components/idor_widget.html",

    # ── vulnerable tab ────────────────────────────────────────
    "vuln_code": """\
@idor_bp.route("/idor/profile/vulnerable")
def profile_vulnerable():
    user_id = request.args.get("id")
    if not user_id:
        return jsonify(error="User ID is required"), 400

    db = get_db()
    # VULNERABLE: Directly fetching the user record by ID.
    # No checks are made to verify if the requesting user (Alice, ID 2)
    # is authorized to view this resource.
    user = db.execute(
        "SELECT id, username, email, api_key, role, bio "
        "FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    if not user:
        return jsonify(error="User not found"), 404

    # VULNERABLE: Also exposes sensitive fields (like API key) in response
    return jsonify(
        id=user["id"],
        username=user["username"],
        email=user["email"],
        api_key=user["api_key"],
        role=user["role"],
        bio=user["bio"],
    )
""",

    "vuln_explanation": (
        "The application accepts a <code>id</code> parameter directly from the client query "
        "string and queries the database for the matching record. It completely neglects to "
        "verify if the current authenticated user (Alice, ID 2) has authorization to view the requested "
        "profile.<br><br>"

        "An attacker can perform parameter tampering, changing the <code>id</code> from <code>2</code> "
        "(Alice) to <code>1</code> (Admin) or <code>3</code> (Bob). Because there is no access control "
        "check, the backend returns the profile details of other users. In this case, it even "
        "leaks sensitive data like private API keys that the developer mistakenly "
        "included in the query response."
    ),

    # ── secure tab ────────────────────────────────────────────
    "secure_code": """\
@idor_bp.route("/idor/profile/secure")
def profile_secure():
    user_id = request.args.get("id")
    if not user_id:
        return jsonify(error="User ID is required"), 400

    # SECURE: Retrieve the current authenticated user's ID from session
    logged_in_id = session.get("user_id")
    
    # SECURE: Validate request ownership / authorization checks
    if not logged_in_id or str(user_id) != str(logged_in_id):
        return jsonify(error="Unauthorized: Access denied"), 403

    db = get_db()
    # Fetch details without returning sensitive credentials like the API key
    user = db.execute(
        "SELECT id, username, email, role, bio "
        "FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    if not user:
        return jsonify(error="User not found"), 404

    return jsonify(
        id=user["id"],
        username=user["username"],
        email=user["email"],
        role=user["role"],
        bio=user["bio"],
    )
""",

    "secure_explanation": (
        "The secure implementation introduces robust authorization checks:"
        "<br><br>"
        "<strong>1. Session Validation</strong> — Instead of relying solely on the client-supplied "
        "<code>id</code> parameter, the server retrieves the authenticated user's identity from a "
        "trusted, server-managed <code>session</code> variable."
        "<br><br>"
        "<strong>2. Strict Access Control Match</strong> — The server verifies if the requested "
        "ID matches the session ID. If there's a mismatch (e.g., Alice trying to fetch ID 1), the "
        "request is rejected with a <code>403 Forbidden</code> response before performing any database "
        "operations."
        "<br><br>"
        "<strong>3. Data Minimization</strong> — Sensitive fields like the API key are "
        "excluded from the database query projection (<code>SELECT</code> statement), protecting "
        "credentials from accidental leak."
    ),
}
