"""Entry point for gunicorn: ``gunicorn wsgi:app``."""

from securenotes import create_app

app = create_app()
