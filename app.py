"""
AppSec Lab — Application Factory

Run with:  python app.py
"""

# pyrefly: ignore [missing-import]
from flask import Flask, render_template

from config import Config
from database import close_db, init_db
from vulnerabilities import VULNERABILITY_REGISTRY, discover_and_register


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    # ── database ──────────────────────────────────────────────
    app.teardown_appcontext(close_db)

    with app.app_context():
        init_db()

    # ── vulnerability blueprints ──────────────────────────────
    with app.app_context():
        discover_and_register(app)

    # ── inject sidebar data into every template ───────────────
    @app.context_processor
    def inject_globals():
        return {"vulnerabilities": VULNERABILITY_REGISTRY}

    # ── home page ─────────────────────────────────────────────
    @app.route("/")
    def index():
        return render_template("index.html")

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, port=5000)
