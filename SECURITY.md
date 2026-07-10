# Security

## Reporting

Report vulnerabilities to the ICS Engineering security contact through internal channels.
Do not open public issues for security problems.

## Secret handling — hard rules

The code and repository enforce these:

- **No real secrets in the repo.** All example credentials are obvious placeholders.
- **Credentials are never written to disk.** Passthrough passwords live only in memory in
  the session's `AuthContext`, which redacts them in `repr()`/`str()`.
- **Credentials are never logged.** `AuthContext` masks its password; `redaction.redact()`
  masks any dict key containing `password`, `secret`, `token`, `authorization`, `auth`,
  `credential`, `apikey`, `encoded`, `private`, etc. Audit logs and tool responses pass
  through redaction.
- **Authorization headers are never printed.** The `Authorization` Basic header is built by
  `httpx` per request and never logged; only method/URL/status are logged at debug level.
- **No secrets in MCP responses.** Responses are redacted before return.
- **No secrets in test fixtures.** Fixtures use placeholder IDs and non-routable data.
- **No secrets in Cloud Foundry manifests.** Real manifests are gitignored; only `*.sample.yml`
  are committed, with placeholders. Inject real values via your pipeline/secret store.

## Session security

- MCP session ids are generated with `secrets.token_urlsafe(32)`.
- Sessions are memory-only (v1); a restart invalidates all sessions.
- Configurable absolute TTL (`ISE_SESSION_TTL_SECONDS`) and idle timeout
  (`ISE_SESSION_IDLE_TIMEOUT_SECONDS`). Logout deletes immediately.

## Transport

- `ISE_VERIFY_SSL=true` by default; only disable against lab systems and never in production.
- Terminate TLS in front of the server (Docker/CF route, then F5) for client-facing traffic.

## Write safety

- Default `ISE_MCP_MODE=readonly`. Writes require `readwrite`; delete also requires
  `ISE_ENABLE_DANGEROUS_TOOLS=true`. ISE enforces the caller's own RBAC regardless.
