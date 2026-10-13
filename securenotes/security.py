"""HTTP security headers and security event logging."""

from __future__ import annotations

import logging

from flask import Flask, request
from flask_login import current_user

# A05 Security Misconfiguration / A03 Injection: a strict Content Security Policy means
# that even if an XSS bug slipped through, injected inline scripts would not run.
CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])

SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}

# A09 Security Logging and Monitoring Failures: security events go to a dedicated
# logger in key=value form so a SIEM can parse and alert on them.
audit_log = logging.getLogger("securenotes.audit")


def audit(event: str, **fields) -> None:
    user = current_user.get_id() if current_user and current_user.is_authenticated else "-"
    details = " ".join(f"{k}={str(v)!r}" for k, v in fields.items())
    audit_log.info("event=%s user=%s ip=%s %s", event, user, request.remote_addr, details)


def register_security_headers(app: Flask) -> None:
    @app.after_request
    def set_headers(response):
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        if app.config.get("FORCE_HTTPS_HEADERS"):
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        # Pages that show private notes must never be cached by shared proxies or the browser.
        if response.mimetype == "text/html":
            response.headers["Cache-Control"] = "no-store"
        response.headers.pop("Server", None)
        return response
