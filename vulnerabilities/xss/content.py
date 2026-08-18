"""
Cross-Site Scripting (Reflected) — Page metadata & content

This dict drives the vulnerability page template.  The ``vuln_code`` and
``secure_code`` fields contain the *actual* source that runs on the server,
so readers can see exactly what is happening.
"""

VULN_META = {
    # ── identity ──────────────────────────────────────────────
    "id": "xss",
    "title": "Cross-Site Scripting (Reflected XSS)",
    "short_title": "Reflected XSS",
    "icon": "🔀",
    "cwe": "CWE-79",
    "order": 3,

    # ── intro ─────────────────────────────────────────────────
    "description": (
        "<b>Cross-Site Scripting (XSS)</b> is a vulnerability that occurs "
        "when an application includes untrusted data in its HTML output "
        "without proper validation or encoding. In <b>reflected XSS</b>, "
        "the malicious script is embedded in a request (typically a URL "
        "parameter) and immediately reflected back in the server's response. "
        "When a victim clicks a crafted link, the injected script executes "
        "in their browser within the context of the vulnerable application, "
        "allowing the attacker to steal session cookies, redirect users, "
        "or perform actions on the victim's behalf."
    ),
    "blog_url": "https://0xtr1gger.github.io/trigger_book/Hack-the-Web/Client-Side/XSS/Cross-site-scripting",

    # ── widget ────────────────────────────────────────────────
    "widget_template": "components/xss_widget.html",

    # ── vulnerable tab ────────────────────────────────────────
    "vuln_code": """\
from markupsafe import Markup

@xss_bp.route("/xss/search/vulnerable")
def search_vulnerable():
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
""",

    "vuln_explanation": (
        "The <code>query</code> parameter is taken directly from the URL "
        "and wrapped in <code>Markup()</code> before being passed to the "
        "template. The <code>Markup</code> class from MarkupSafe tells "
        "Jinja2 that the string is <em>already safe</em> and should "
        "<strong>not</strong> be auto-escaped.<br><br>"

        "This means any HTML or JavaScript in the user's input is inserted "
        "into the page <em>as-is</em>. For example, the payload:<br><br>"

        "<code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code>"
        "<br><br>"

        "is reflected directly into the HTML response. The browser parses it "
        "as a legitimate <code>&lt;script&gt;</code> element and executes "
        "the JavaScript immediately. Because the script runs in the context "
        "of the vulnerable application's origin, it has full access to the "
        "page's DOM, cookies (unless <code>HttpOnly</code>), and can make "
        "authenticated requests on behalf of the user.<br><br>"

        "In a real attack, the attacker would craft a URL containing the "
        "payload and trick the victim into clicking it — for example, via "
        "a phishing email or a link on a forum."
    ),

    # ── secure tab ────────────────────────────────────────────
    "secure_code": """\
@xss_bp.route("/xss/search/secure")
def search_secure():
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
""",

    "secure_explanation": (
        "The secure implementation passes the raw <code>query</code> string "
        "directly to the Jinja2 template <strong>without</strong> wrapping "
        "it in <code>Markup()</code>. Jinja2's auto-escaping — which is "
        "enabled by default in Flask — automatically converts dangerous "
        "HTML characters into their entity equivalents:<br><br>"

        "<code>&lt;</code> → <code>&amp;lt;</code>, "
        "<code>&gt;</code> → <code>&amp;gt;</code>, "
        "<code>\"</code> → <code>&amp;quot;</code>, "
        "<code>'</code> → <code>&amp;#39;</code>, "
        "<code>&amp;</code> → <code>&amp;amp;</code>"
        "<br><br>"

        "So even if an attacker submits:<br><br>"

        "<code>&lt;script&gt;alert(1)&lt;/script&gt;</code><br><br>"

        "the browser receives "
        "<code>&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;</code> "
        "and renders the payload as harmless, visible text instead of "
        "executing it as JavaScript.<br><br>"

        "This is the primary defense against reflected XSS: <strong>output "
        "encoding</strong> (also called contextual escaping). The key "
        "principle is that user-controlled data must always be treated as "
        "text content, never as HTML markup. In Flask/Jinja2, this happens "
        "automatically — the vulnerability in the insecure version was "
        "explicitly <em>bypassing</em> this built-in protection."
    ),
}
