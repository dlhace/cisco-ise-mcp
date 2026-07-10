"""Auth provider interface + in-memory auth context.

Two independent concepts (see docs/authentication.md):
  * client -> MCP server session (X-MCP-Session id)
  * MCP server -> ISE credential context (AuthContext)

Adding a new provider (api_key / entra_oidc / jwt / reverse_proxy_header / mtls)
means implementing AuthProvider; tool logic never changes because tools only ever
see a resolved AuthContext.
"""
from __future__ import annotations

import base64
import contextvars
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..redaction import MASK


@dataclass
class AuthContext:
    """Everything a tool needs to call ISE as some identity. Password is held in
    memory only, kept out of repr/str, and never serialized."""

    username: str
    mode: str  # passthrough | service_account | ...
    _password: str = field(default="", repr=False)
    _encoded: str = field(default="", repr=False)  # base64 "user:pass" if provided

    def basic_auth(self) -> tuple[str, str]:
        """(username, password) for HTTP Basic against ISE."""
        if self._encoded:
            try:
                user, _, pwd = base64.b64decode(self._encoded).decode().partition(":")
                return user, pwd
            except Exception as exc:  # noqa: BLE001
                raise ValueError("ISE_ENCODED_AUTH is not valid base64 'user:pass'") from exc
        return self.username, self._password

    def __repr__(self) -> str:  # never leak the secret
        return f"AuthContext(username={self.username!r}, mode={self.mode!r}, password={MASK})"

    __str__ = __repr__


# Set per-request by the transport layer (middleware / tool dependency).
current_auth: contextvars.ContextVar[AuthContext | None] = contextvars.ContextVar(
    "current_auth", default=None
)
# MCP session id extracted from the configured session header (or Bearer token).
current_session_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "current_session_id", default=None
)


class AuthProvider(ABC):
    """Base for all authentication strategies."""

    name: str = "base"

    @abstractmethod
    async def resolve(self, *, session_id: str | None) -> AuthContext:
        """Return the AuthContext to use for a call, or raise AuthError."""
        raise NotImplementedError
