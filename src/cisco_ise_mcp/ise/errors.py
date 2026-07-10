"""Exception hierarchy. Stdlib only."""
from __future__ import annotations


class IseMcpError(Exception):
    """Base for all server errors. `code` is a stable machine string for clients."""

    code = "ise_error"

    def __init__(self, message: str, *, detail: object | None = None):
        super().__init__(message)
        self.message = message
        self.detail = detail

    def to_dict(self) -> dict:
        d = {"error": self.code, "message": self.message}
        if self.detail is not None:
            d["detail"] = self.detail
        return d


class ValidationError(IseMcpError):
    code = "validation_error"


class AuthError(IseMcpError):
    code = "auth_error"


class SessionError(IseMcpError):
    code = "session_error"


class WriteNotAllowedError(IseMcpError):
    code = "write_not_allowed"


class ToolDisabledError(IseMcpError):
    code = "tool_disabled"


class IseApiError(IseMcpError):
    code = "ise_api_error"

    def __init__(self, message: str, *, status: int | None = None, detail: object | None = None):
        super().__init__(message, detail=detail)
        self.status = status

    def to_dict(self) -> dict:
        d = super().to_dict()
        if self.status is not None:
            d["status"] = self.status
        return d


class NotFoundError(IseApiError):
    code = "not_found"


class RateLimitError(IseApiError):
    code = "rate_limited"
