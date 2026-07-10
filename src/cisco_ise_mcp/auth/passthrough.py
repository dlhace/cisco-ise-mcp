"""Passthrough auth: client presents ISE creds, we validate against ISE, then
issue an MCP session id. The ISE credential context lives only in memory in the
session's AuthContext.
"""
from __future__ import annotations

from typing import Awaitable, Callable

from ..ise.errors import AuthError, SessionError
from .base import AuthContext, AuthProvider
from .session_store import Session, SessionStore

# validator(username, password) -> bool ; injected so this module has no httpx dep
Validator = Callable[[str, str], Awaitable[bool]]


class PassthroughProvider(AuthProvider):
    name = "passthrough"

    def __init__(self, store: SessionStore, validator: Validator):
        self._store = store
        self._validate = validator

    async def login(self, username: str, password: str) -> Session:
        if not username or not password:
            raise AuthError("username and password are required")
        try:
            valid = await self._validate(username, password)
        except Exception as exc:  # noqa: BLE001
            raise AuthError("ISE credential validation failed") from exc
        if not valid:
            raise AuthError("Invalid ISE credentials")
        auth = AuthContext(username=username, mode=self.name, _password=password)
        return self._store.create(username, auth)

    def logout(self, session_id: str) -> bool:
        return self._store.delete(session_id)

    async def resolve(self, *, session_id: str | None) -> AuthContext:
        sess = self._store.get(session_id)
        if sess is None:
            raise SessionError("Missing or expired MCP session; call ise_login first")
        return sess.auth
