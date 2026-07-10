"""Redaction helpers. Applied to anything that may be logged or returned.
Stdlib only."""
from __future__ import annotations

from typing import Any

# Exact key match (case-insensitive). Keep this tight so policy fields like
# "authz_profile" / "authorization_rule" / "auth_mode" are NOT clobbered.
SENSITIVE_KEY_EXACT = {
    "authorization",
    "password",
    "passwd",
    "credential",
    "credentials",
    "apikey",
    "encoded_auth",
    "x-mcp-session",
}
# Substring match (case-insensitive) for genuinely secret-bearing key names.
SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "encoded_auth",
    "client_secret",
)

MASK = "***REDACTED***"


def _is_sensitive(key: str) -> bool:
    k = key.lower()
    return k in SENSITIVE_KEY_EXACT or any(part in k for part in SENSITIVE_KEY_PARTS)


def redact(obj: Any, _depth: int = 0) -> Any:
    """Recursively mask values whose key looks sensitive. Non-mutating."""
    if _depth > 25:
        return obj
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and _is_sensitive(k):
                out[k] = MASK
            else:
                out[k] = redact(v, _depth + 1)
        return out
    if isinstance(obj, (list, tuple)):
        return [redact(v, _depth + 1) for v in obj]
    return obj


def mask(_value: str | None) -> str:
    """Explicit mask for a known-secret scalar (used in reprs)."""
    return MASK
