"""ISE API access layer.

Kept import-light on purpose: importing this package must not pull in httpx, so the
stdlib-only summarizers/models stay testable without runtime deps. Import the
concrete client via `cisco_ise_mcp.ise.client`.
"""
