# Authentication

## Two independent concepts

1. **Client → MCP server session.** The client sends ISE username/password to `ise_login`.
   The server validates them against ISE (a cheap authenticated ERS probe). On success it
   creates a random MCP session id (`secrets.token_urlsafe(32)`) and returns it. The client
   presents that id on later calls via `MCP_SESSION_HEADER` (default `X-MCP-Session`) or
   `Authorization: Bearer <id>`.
2. **MCP server → ISE.** How the server authenticates to ISE for a given call:
   - `passthrough`: uses the authenticated user's ISE credential context (from the session).
   - `service_account`: uses `ISE_USERNAME`/`ISE_PASSWORD` (or `ISE_ENCODED_AUTH`).

## Modes

`ISE_AUTH_MODE=passthrough` (default) or `service_account`.

- **passthrough** — interactive/human clients; writes run as the real ISE user (ISE RBAC
  applies). Requires HTTP transport so the session header can travel.
- **service_account** — non-interactive clients (Copilot Studio, Teams agents, automation).
  Commonly paired with `ISE_MCP_MODE=readonly`. No sessions; identity is fixed by config.

## Provider interface

`auth/base.py:AuthProvider` has one method: `resolve(session_id) -> AuthContext`. To add a
provider (`api_key`, `entra_oidc`, `jwt`, `reverse_proxy_header`, `mtls`), implement it and
select it in `server.build()`. Tools are unaffected because they only consume `AuthContext`.
Reserved env vars: `MCP_AUTH_PROVIDER`, `MCP_API_KEYS`, `ENTRA_TENANT_ID`,
`ENTRA_CLIENT_ID`, `ENTRA_ALLOWED_GROUPS`, `JWT_ISSUER`, `JWT_AUDIENCE`, `JWT_JWKS_URL`.

## Sessions

- Memory-only in v1 (`auth/session_store.py`). Lost on restart.
- `ISE_SESSION_TTL_SECONDS` (absolute) and `ISE_SESSION_IDLE_TIMEOUT_SECONDS` (idle).
- `ise_logout` deletes immediately.
- **TODO (phase 2):** pluggable backend (e.g. Redis) for multi-instance CF deployments. The
  store already hides storage behind a small API, so tools/providers won't change.

## Credential-handling guarantees

- Passwords exist only in memory (session `AuthContext`), never on disk.
- `AuthContext.__repr__`/`__str__` mask the password; logs and responses are redacted.
- The `Authorization` header is built by httpx per request and never logged.
