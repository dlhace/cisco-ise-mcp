"""Service-account auth: a single configured ISE identity from env, for
non-interactive clients (Copilot Studio, Teams, automation). No sessions."""
from __future__ import annotations

from ..config import Config
from ..ise.errors import AuthError
from .base import AuthContext, AuthProvider


class ServiceAccountProvider(AuthProvider):
    name = "service_account"

    def __init__(self, cfg: Config):
        if not (cfg.ise_encoded_auth or (cfg.ise_username and cfg.ise_password)):
            raise AuthError("service_account mode needs ISE_USERNAME/ISE_PASSWORD or ISE_ENCODED_AUTH")
        self._ctx = AuthContext(
            username=cfg.ise_username or "(encoded)",
            mode=self.name,
            _password=cfg.ise_password,
            _encoded=cfg.ise_encoded_auth,
        )

    async def resolve(self, *, session_id: str | None) -> AuthContext:
        # session_id ignored: identity is fixed by configuration.
        return self._ctx
