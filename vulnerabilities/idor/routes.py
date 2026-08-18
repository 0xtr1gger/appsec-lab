"""
Insecure Direct Object Reference (IDOR) — Routes

Endpoints
---------
GET   /idor/                     → renders the vulnerability page, sets mock session to Alice (ID 2)
GET   /idor/profile/vulnerable   → returns user details directly from id query param (vulnerable)
GET   /idor/profile/secure       → returns user details after verifying session matches request (secure)
"""

# pyrefly: ignore [missing-import]
from flask import Blueprint, jsonify, render_template, request, session

from database import get_db
from vulnerabilities.idor.content import VULN_META

idor_bp = Blueprint("idor", __name__)


@idor_bp.route("/idor/")
def index():
    """Render the IDOR lab page and simulate authentication as Alice (ID 2)."""
    # Simulate authenticating as 'alice' (User ID: 2)
    session["user_id"] = 2
    session["username"] = "alice"
    return render_template("idor_vulnerability_page.html", vuln=VULN_META)


# ---------------------------------------------------------------------------
# VULNERABLE endpoint
# ---------------------------------------------------------------------------

@idor_bp.route("/idor/profile/vulnerable")
def profile_vulnerable():
    """Retrieve user profile — INTENTIONALLY VULNERABLE to IDOR.

    Accesses DB object purely by the user-supplied ID parameter.
    """
    user_id = request.args.get("id", "")
    if not user_id:
        return jsonify(error="User ID is required"), 400

    db = get_db()
    user = db.execute(
        "SELECT id, username, email, api_key, role, bio "
        "FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    if not user:
        return jsonify(error="User not found"), 404

    return jsonify(
        id=user["id"],
        username=user["username"],
        email=user["email"],
        api_key=user["api_key"],
        role=user["role"],
        bio=user["bio"],
    )


# ---------------------------------------------------------------------------
# SECURE endpoint
# ---------------------------------------------------------------------------

@idor_bp.route("/idor/profile/secure")
def profile_secure():
    """Retrieve user profile — Secure implementation.

    Verifies the requested object ID belongs to the current session owner.
    """
    user_id = request.args.get("id", "")
    if not user_id:
        return jsonify(error="User ID is required"), 400

    # SECURE: Access validation against session state
    logged_in_id = session.get("user_id")
    if not logged_in_id or str(user_id) != str(logged_in_id):
        return jsonify(error="Unauthorized: Access denied"), 403

    db = get_db()
    # SECURE: Exclude sensitive credentials (like API key) from projection
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
