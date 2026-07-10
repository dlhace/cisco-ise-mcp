# MCP tools

All tools return a JSON envelope: `{"ok": true, "data": ..., "meta": {...}, "raw": ...}` or
`{"ok": false, "error": "<code>", "message": "..."}`. `raw` appears only when the caller
passes `include_raw=true` (or `ISE_INCLUDE_RAW_DEFAULT=true`). All output is redacted.

## Health / auth

| Tool | Args | Notes |
|------|------|-------|
| `ise_health_check` | — | Liveness + non-secret config summary |
| `ise_auth_status` | — | Resolved caller identity |
| `ise_login` | `username`, `password` | Passthrough only. Returns `session_id`. Password never stored/logged/returned |
| `ise_validate_session` | — | Validates presented session id |
| `ise_logout` | — | Invalidates current session |
| `ise_whoami` | — | Identity + effective write capability |

## Endpoint (use case #1)

| Tool | Args |
|------|------|
| `ise_get_endpoint_by_mac` | `mac`, `include_raw?` |
| `ise_get_endpoint_by_id` | `endpoint_id`, `include_raw?` |
| `ise_get_endpoint_by_ip` | `ip`, `include_raw?` |
| `ise_search_endpoints` | `filter_expression?` (`field.OP.value`), `page?`, `page_size?`, `include_raw?` |

## Session / auth logs (use cases #2, #3)

| Tool | Args |
|------|------|
| `ise_get_active_session_by_mac` | `mac`, `include_raw?` |
| `ise_get_active_session_by_ip` | `ip`, `include_raw?` |
| `ise_get_auth_logs_by_mac` | `mac`, `seconds?` (default 86400), `records?` (default 50), `include_raw?` |

## Policy / context (use cases #4, #5, #6)

| Tool | Args | Returns |
|------|------|---------|
| `ise_get_policy_context_by_mac` | `mac` | endpoint + group + profile + active session + SGT + recent auth |
| `ise_get_incident_summary_by_mac` | `mac` | NOC narrative + structured context |

## Identity / TrustSec / device

| Tool | Args |
|------|------|
| `ise_get_user_sessions_by_username` | `username`, `include_raw?` |
| `ise_get_endpoint_group` | `group_id` |
| `ise_list_security_groups` | `page?`, `page_size?`, `include_raw?` |
| `ise_list_sgacls` | `page?`, `page_size?`, `include_raw?` |
| `ise_list_authorization_profiles` | `page?`, `page_size?`, `include_raw?` |
| `ise_list_network_devices` | `filter_expression?`, `page?`, `page_size?`, `include_raw?` |

## Write (gated: `ISE_MCP_MODE=readwrite`)

| Tool | Args | Extra gate |
|------|------|-----------|
| `ise_create_endpoint` | `mac`, `group_id?`, `description?` | — |
| `ise_assign_endpoint_group` | `endpoint_id`, `group_id` | — |
| `ise_delete_endpoint` | `endpoint_id` | also needs `ISE_ENABLE_DANGEROUS_TOOLS=true` |

Tool availability can be further restricted with `ISE_ALLOWED_TOOLS` / `ISE_DISABLED_TOOLS`.
