"""Standard MCP tool response envelope. Stdlib only."""
from __future__ import annotations

from typing import Any

from .redaction import redact


def ok(data: Any, *, raw: Any = None, include_raw: bool = False, **meta: Any) -> dict:
    resp: dict[str, Any] = {"ok": True, "data": redact(data)}
    if meta:
        resp["meta"] = meta
    if include_raw and raw is not None:
        resp["raw"] = redact(raw)
    return resp


def paged(items: list, *, page: int, page_size: int, total: int | None = None,
          raw: Any = None, include_raw: bool = False) -> dict:
    meta = {"page": page, "page_size": page_size, "returned": len(items)}
    if total is not None:
        meta["total"] = total
    return ok(items, raw=raw, include_raw=include_raw, **meta)


def error(err: Exception) -> dict:
    from .ise.errors import IseMcpError

    if isinstance(err, IseMcpError):
        return {"ok": False, **err.to_dict()}
    return {"ok": False, "error": "internal_error", "message": str(err)}
