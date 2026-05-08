"""
AppSec Lab — Configuration
"""

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "appsec-lab-dev-key-change-me")
    DATABASE_PATH = os.path.join(BASE_DIR, "data", "app.db")
    DEBUG = True
