"""
AppSec Lab — Vulnerability Auto-Discovery

Scans subdirectories of ``vulnerabilities/`` for modules that expose:
  - ``content.VULN_META``  — metadata dict used by templates & sidebar
  - ``routes.<name>_bp``   — a Flask Blueprint with the lab endpoints

To add a new vulnerability, create a new sub-package (directory) here
with ``__init__.py``, ``content.py``, and ``routes.py``.  The framework
picks it up automatically on the next restart.
"""

from __future__ import annotations

import importlib
import os
import pkgutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # pyrefly: ignore [missing-import]
    from flask import Flask

# Global registry populated at startup — consumed by templates for sidebar nav
VULNERABILITY_REGISTRY: list[dict] = []


def discover_and_register(app: Flask) -> None:
    """Walk vulnerability sub-packages, import them, and register blueprints."""

    package_dir = os.path.dirname(__file__)

    for _importer, mod_name, is_pkg in pkgutil.iter_modules([package_dir]):
        if not is_pkg:
            continue  # skip loose .py files in this directory

        # Import content.py for metadata
        try:
            content_mod = importlib.import_module(
                f"vulnerabilities.{mod_name}.content"
            )
        except ModuleNotFoundError:
            app.logger.warning(
                "vulnerabilities/%s/ has no content.py — skipping", mod_name
            )
            continue

        meta: dict = getattr(content_mod, "VULN_META", None)
        if meta is None:
            app.logger.warning(
                "vulnerabilities/%s/content.py missing VULN_META — skipping",
                mod_name,
            )
            continue

        # Import routes.py for the blueprint
        try:
            routes_mod = importlib.import_module(
                f"vulnerabilities.{mod_name}.routes"
            )
        except ModuleNotFoundError:
            app.logger.warning(
                "vulnerabilities/%s/ has no routes.py — skipping", mod_name
            )
            continue

        # Convention: blueprint variable is named ``<mod_name>_bp``
        bp_name = f"{mod_name}_bp"
        bp = getattr(routes_mod, bp_name, None)
        if bp is None:
            app.logger.warning(
                "vulnerabilities/%s/routes.py missing %s — skipping",
                mod_name,
                bp_name,
            )
            continue

        app.register_blueprint(bp)
        VULNERABILITY_REGISTRY.append(meta)
        app.logger.info("Registered vulnerability: %s", meta.get("title", mod_name))

    # Sort by the ``order`` key so sidebar is deterministic
    VULNERABILITY_REGISTRY.sort(key=lambda m: m.get("order", 999))
