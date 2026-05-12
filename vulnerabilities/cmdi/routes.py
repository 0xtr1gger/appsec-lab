"""
OS Command Injection — Routes

Endpoints
---------
GET   /cmdi/                  → renders the vulnerability page
POST  /cmdi/ping/vulnerable   → runs ping with shell=True (intentionally vulnerable)
POST  /cmdi/ping/secure       → runs ping with input validation + shell=False (safe)
"""

import re
import subprocess

# pyrefly: ignore [missing-import]
from flask import Blueprint, jsonify, render_template, request

from vulnerabilities.cmdi.content import VULN_META

cmdi_bp = Blueprint("cmdi", __name__)


@cmdi_bp.route("/cmdi/")
def index():
    """Render the OS Command Injection lab page."""
    return render_template("cmdi_vulnerability_page.html", vuln=VULN_META)


# ---------------------------------------------------------------------------
# VULNERABLE endpoint
# ---------------------------------------------------------------------------

@cmdi_bp.route("/cmdi/ping/vulnerable", methods=["POST"])
def ping_vulnerable():
    """Ping a host — INTENTIONALLY VULNERABLE to OS command injection.

    The host value is interpolated directly into a shell command string via
    an f-string with shell=True, which allows shell meta-characters in user
    input to be interpreted.
    """
    host = request.form.get("host", "")
    if not host:
        return jsonify(error="No host provided"), 400

    # VULNERABLE: shell=True passes the string to /bin/sh,
    # so shell meta-characters in `host` are interpreted.
    cmd = f"ping -c 3 {host}"
    try:
        result = subprocess.run(
            cmd, shell=True,
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        output = "Command timed out."

    return jsonify(output=output, command_used=cmd)


# ---------------------------------------------------------------------------
# SECURE endpoint
# ---------------------------------------------------------------------------

ALLOWED_HOST_RE = re.compile(r"^[a-zA-Z0-9.\-]+$")


@cmdi_bp.route("/cmdi/ping/secure", methods=["POST"])
def ping_secure():
    """Ping a host — secure implementation with input validation and no shell."""
    host = request.form.get("host", "")
    if not host:
        return jsonify(error="No host provided"), 400

    # SECURE: validate input against a strict whitelist
    if not ALLOWED_HOST_RE.match(host):
        return jsonify(
            error="Invalid host. Only alphanumeric characters, dots, and hyphens are allowed.",
            command_used=f"ping -c 3 {host} (blocked by validation)",
        ), 400

    # SECURE: shell=False — pass arguments as a list.
    # The OS executes ping directly without a shell interpreter,
    # so meta-characters have no special meaning.
    cmd_list = ["ping", "-c", "3", host]
    try:
        result = subprocess.run(
            cmd_list, capture_output=True, text=True, timeout=10,
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        output = "Command timed out."

    return jsonify(output=output, command_used=" ".join(cmd_list))
