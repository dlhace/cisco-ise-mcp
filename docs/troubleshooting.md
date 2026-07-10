# Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `ise_login` fails / `auth_error` | Wrong ISE creds, or ERS not enabled | Verify creds; enable ERS (API Settings); check `ISE_BASE_URL` |
| Session tools return `ise_api_error` status 401 | Account lacks MNT/monitoring rights | Use a monitoring-capable identity (see ise-permissions.md) |
| Endpoint-by-MAC 400 | Deployment rejects `mac.EQUALS` filter | Server already uses `/endpoint/name/{mac}`; for search use `mac.CONTAINS` |
| `write_not_allowed` | Server is readonly | Deploy with `ISE_MCP_MODE=readwrite`; delete also needs `ISE_ENABLE_DANGEROUS_TOOLS=true` |
| `tool_disabled` | `ISE_ALLOWED_TOOLS`/`ISE_DISABLED_TOOLS` excludes it | Adjust the allow/deny lists |
| `session_error` on every call | Session header not forwarded | Send `X-MCP-Session` (or `Authorization: Bearer`); check proxy strips headers |
| TLS verify errors | Self-signed ISE cert | Trust the CA; only set `ISE_VERIFY_SSL=false` in a lab |
| CF app crashes on start | Port mismatch | Bind `MCP_PORT` to `$PORT` (see cloud-foundry.md) |
| ISE 429 | Rate limited | `ISE_RATE_LIMIT_WAIT=true` (default) retries with backoff/Retry-After |

## Logs

Structured JSON on stdout. Set `LOG_LEVEL=DEBUG` for per-request method/URL/status
(never credentials). Audit events (`AUDIT_LOG_ENABLED=true`) record actor, tool, redacted
params, and status.

## Quick connectivity check

```bash
curl -s http://localhost:8005/healthz        # {"status":"ok","mode":"readonly"}
```
