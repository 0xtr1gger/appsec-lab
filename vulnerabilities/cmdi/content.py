"""
OS Command Injection — Page metadata & content

This dict drives the vulnerability page template.  The ``vuln_code`` and
``secure_code`` fields contain the *actual* source that runs on the server,
so readers can see exactly what is happening.
"""

VULN_META = {
    # ── identity ──────────────────────────────────────────────
    "id": "cmdi",
    "title": "OS Command Injection",
    "short_title": "Command Injection",
    "icon": "💻",
    "cwe": "CWE-78",
    "order": 2,

    # ── intro ─────────────────────────────────────────────────
    "description": (
        "<b>OS command injection</b> (also called shell injection) is a "
        "security vulnerability that allows an attacker to execute arbitrary "
        "operating system commands on the server hosting the application. "
        "It occurs when user input is passed to a system shell without proper "
        "validation or sanitization, allowing meta-characters like "
        "<code>;</code>, <code>&&</code>, or <code>|</code> to chain "
        "additional commands onto the intended one."
    ),
    "blog_url": "https://0xtr1gger.github.io/trigger_book/Hack-the-Web/Injection/OS-command-injection",
    "blog_link_text": "0xtr1gger book/OS command injection",

    # ── widget ────────────────────────────────────────────────
    "widget_template": "components/cmdi_widget.html",

    # ── vulnerable tab ────────────────────────────────────────
    "vuln_code": """\
@cmdi_bp.route("/cmdi/ping/vulnerable", methods=["POST"])
def ping_vulnerable():
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
""",

    "vuln_explanation": (
        "The <code>host</code> parameter is inserted directly into a shell "
        "command string using an f-string. Because <code>shell=True</code> is "
        "passed to <code>subprocess.run()</code>, Python hands the entire "
        "string to <code>/bin/sh -c</code> for parsing.<br><br>"

        "The shell tokenizes the string according to its grammar — and any "
        "meta-characters in the user input are interpreted as shell syntax, "
        "not as literal data. For example, the payload:<br><br>"

        "<code>127.0.0.1; whoami</code>"
        "<br><br>"

        "produces the shell command <code>ping -c 3 127.0.0.1; whoami</code>. "
        "The semicolon <code>;</code> is a command separator — the shell "
        "executes <code>ping</code> first, then <code>whoami</code> as a "
        "completely independent command.<br><br>"

        "Other operators like <code>&&</code>, <code>||</code>, "
        "<code>|</code>, and backticks <code>`cmd`</code> work similarly. "
        "The injected commands run with the same privileges as the web server "
        "process, which can lead to full system compromise."
    ),

    # ── secure tab ────────────────────────────────────────────
    "secure_code": """\
import re

ALLOWED_HOST_RE = re.compile(r"^[a-zA-Z0-9.\\-]+$")

@cmdi_bp.route("/cmdi/ping/secure", methods=["POST"])
def ping_secure():
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
""",

    "secure_explanation": (
        "The secure implementation applies two layers of defense:"
        "<br><br>"
        "<strong>1. Input validation (allowlist)</strong> — a regex "
        "<code>^[a-zA-Z0-9.\\-]+$</code> rejects any input containing shell "
        "meta-characters (<code>;</code>, <code>&</code>, <code>|</code>, "
        "backticks, etc.) before it ever reaches a system call. Only "
        "hostnames and IP addresses pass through."
        "<br><br>"
        "<strong>2. No shell invocation</strong> — <code>subprocess.run()</code> "
        "is called with a list of arguments instead of a single string, and "
        "<code>shell=True</code> is omitted (defaults to <code>False</code>). "
        "This means the OS executes <code>ping</code> directly via "
        "<code>execvp()</code> — no shell interpreter parses the arguments, "
        "so meta-characters have no special meaning even if they somehow "
        "bypassed the regex."
        "<br><br>"
        "Either defense alone significantly reduces risk, but combining them "
        "provides defense in depth. In production applications, consider "
        "replacing the system command entirely with a native library (e.g., "
        "Python's <code>socket</code> or <code>icmplib</code>) to avoid "
        "shelling out altogether."
    ),
}
