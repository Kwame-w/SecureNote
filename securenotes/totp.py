"""Time-based one-time passwords (RFC 6238), implemented from the spec.

Works with Google Authenticator, Microsoft Authenticator, Authy, 1Password, etc.
Implemented here (rather than pulled from a library) to show how TOTP works:
HMAC-SHA1 over a 30-second counter, then dynamic truncation (RFC 4226).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

STEP_SECONDS = 30
DIGITS = 6
VALID_WINDOW = 1  # accept the previous and next step to tolerate clock drift


def generate_secret() -> str:
    """160 random bits, base32-encoded, as recommended by RFC 4226."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _key(secret: str) -> bytes:
    padded = secret.upper() + "=" * (-len(secret) % 8)
    return base64.b32decode(padded)


def hotp(key: bytes, counter: int, digits: int = DIGITS, digest=hashlib.sha1) -> str:
    mac = hmac.new(key, struct.pack(">Q", counter), digest).digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % 10**digits).zfill(digits)


def current_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // STEP_SECONDS)


def code_at(secret: str, now: float | None = None) -> str:
    return hotp(_key(secret), current_step(now))


def verify(secret: str, code: str, last_used_step: int | None = None, now: float | None = None) -> int | None:
    """Return the matched time step, or None.

    Codes for a step at or before ``last_used_step`` are rejected, so an
    intercepted code can't be replayed within its 30-second lifetime.
    """
    code = (code or "").replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return None
    key = _key(secret)
    step = current_step(now)
    for candidate in range(step - VALID_WINDOW, step + VALID_WINDOW + 1):
        if last_used_step is not None and candidate <= last_used_step:
            continue
        if hmac.compare_digest(hotp(key, candidate), code):  # constant-time comparison
            return candidate
    return None


def provisioning_uri(secret: str, username: str, issuer: str = "SecureNotes") -> str:
    """The otpauth:// URI that authenticator apps read from the QR code."""
    label = quote(f"{issuer}:{username}")
    return f"otpauth://totp/{label}?" + urlencode({"secret": secret, "issuer": issuer, "digits": DIGITS, "period": STEP_SECONDS})


def generate_recovery_codes(count: int = 10) -> list[str]:
    """One-time backup codes like ``k7rq-2mxp-9fzt`` (about 60 bits of entropy each)."""
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"  # no 0/o/1/l/i to avoid misreading
    return ["-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3)) for _ in range(count)]
