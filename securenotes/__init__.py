"""SecureNotes: a small notes app built to demonstrate defenses against the OWASP Top 10."""

from __future__ import annotations

import logging
import os
import secrets

from flask import Flask, render_template

from .config import CONFIGS
from .extensions import csrf, db, limiter, login_manager
from .security import register_security_headers

__version__ = "1.0.0"


def create_app(config_name: str | None = None, **overrides) -> Flask:
    app = Flask(__name__)
    config_name = config_name or os.environ.get("SECURENOTES_ENV", "development")
    app.config.from_object(CONFIGS[config_name])
    app.config.update(overrides)

    secret = app.config.get("SECRET_KEY") or os.environ.get("SECRET_KEY")
    if not secret:
        if config_name == "production":
            # A05 Security Misconfiguration: never fall back to a guessable key in production.
            raise RuntimeError("SECRET_KEY must be set in production")
        secret = secrets.token_hex(32)
    app.config["SECRET_KEY"] = secret

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    login_manager.init_app(app)
    register_security_headers(app)

    from .account import bp as account_bp
    from .auth import bp as auth_bp
    from .notes import bp as notes_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(notes_bp)
    app.register_blueprint(account_bp)

    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(429)
    @app.errorhandler(400)
    def handle_error(error):
        # A05: generic error pages, no stack traces or framework details leak to users.
        return render_template("errors/error.html", code=error.code, name=error.name), error.code

    @app.errorhandler(500)
    def handle_500(error):
        return render_template("errors/error.html", code=500, name="Internal Server Error"), 500

    with app.app_context():
        db.create_all()

    return app
