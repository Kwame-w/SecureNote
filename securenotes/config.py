from __future__ import annotations

import os
from datetime import timedelta


class BaseConfig:
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///securenotes.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session cookie hardening (A07): not readable by JS, not sent cross-site, short-lived.
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

    # Reject oversized request bodies before they reach the app.
    MAX_CONTENT_LENGTH = 64 * 1024

    WTF_CSRF_TIME_LIMIT = 3600
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_HEADERS_ENABLED = True

    # Account lockout (A07): after this many failures, lock for LOCKOUT_MINUTES.
    MAX_FAILED_LOGINS = 5
    LOCKOUT_MINUTES = 15
    MFA_PENDING_SECONDS = 300  # time allowed between password and second factor
    FORCE_HTTPS_HEADERS = False


class DevelopmentConfig(BaseConfig):
    DEBUG = False  # the Werkzeug debugger allows code execution, so it stays off even in dev


class TestingConfig(BaseConfig):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    RATELIMIT_ENABLED = False


class ProductionConfig(BaseConfig):
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    SESSION_COOKIE_NAME = "__Host-session"
    FORCE_HTTPS_HEADERS = True


CONFIGS = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}
