# cisco-ise-mcp

An MCP (Model Context Protocol) server for **Cisco Identity Services Engine (ISE) 3.2**,
exposing ISE **ERS** and **MNT** APIs as MCP tools. It runs locally (stdio), in Docker,
and as a Cloud Foundry application, with **ISE credential passthrough** as the primary
authentication model.

## Scope (and deliberate non-scope)

This server focuses on **identity, endpoints, sessions, authentication, policy,
profiling, and authorization context** from ISE. It intentionally does **not** try to
duplicate topology or device discovery — those belong to Catalyst Center, Arista CVaaS,
NetBox, and similar source-of-truth MCP servers. It is designed to be one **sub-agent**
that a future orchestrator combines with:

- Cisco Catalyst Center MCP
- Arista CVaaS MCP
- NetBox / other network MCPs

## Primary use cases

1. Query endpoint info by MAC, IP, hostname, username, or endpoint ID.
2. Query authentication/session logs for a MAC.
3. Query active session info for a MAC or IP.
4. Query policy/context associated with a MAC.
5. Aggregate ISE context for a MAC (endpoint group, profile, identity group, SGT/SGACL,
   authorization profile, auth status, recent RADIUS failures, MNT data where available).
6. Produce NOC/incident-style summaries.
7. Act as an ISE identity/policy sub-agent for orchestration.
8. Run centrally on Cloud Foundry for Copilot Studio, Teams, and direct MCP clients.

## Architecture

```
MCP client ──HTTP(S)──> [cisco-ise-mcp]
                           ├── auth/       passthrough | service_account (pluggable)
                           ├── tools/      endpoint, session, policy, sgt, identity, write
                           ├── ise/        client (async httpx) → ERS + MNT
                           └── audit/redaction/validation
                                     │
                                     ▼
                         Cisco ISE 3.2 deployment VIP (ERS :443 /ers, MNT /admin/API/mnt)
```

See [docs/architecture.md](docs/architecture.md).

## Authentication (two independent concepts)

1. **Client → MCP server**: the client authenticates with **ISE credentials**; the server
   validates them against ISE and issues a random **MCP session id**. Subsequent calls
   present that id in the `X-MCP-Session` header (or `Authorization: Bearer <id>`).
2. **MCP server → ISE**: in `passthrough` the server uses the authenticated user's ISE
   credential context; in `service_account` it uses configured ISE service-account creds.

Modes: `ISE_AUTH_MODE=passthrough` (default) | `service_account`. Reserved for later:
`api_key`, `entra_oidc`, `jwt`, `reverse_proxy_header`, `mtls` (interface is pluggable —
adding one does not touch tool logic). Full detail: [docs/authentication.md](docs/authentication.md).

Sessions are **memory-only** in v1 (lost on restart); TTL and idle timeout are configurable.
Credentials are never written to disk, never logged, never returned.

## Read-only vs read/write

`ISE_MCP_MODE=readonly` (default) | `readwrite`. Write tools (`ise_create_endpoint`,
`ise_assign_endpoint_group`, `ise_delete_endpoint`) are gated by this flag; delete
additionally requires `ISE_ENABLE_DANGEROUS_TOOLS=true`. ISE still enforces the caller's
own permissions server-side.

## Quick start (local)

```bash
uv venv && source .venv/bin/activate      # or: python -m venv .venv && source .venv/bin/activate
uv pip install -e ".[dev]"                # or: pip install -e ".[dev]"
cp .env.example .env                      # edit; .env is gitignored
python -m cisco_ise_mcp                    # honors MCP_TRANSPORT (streamable-http default)
```

For stdio (single-user local MCP client), set `MCP_TRANSPORT=stdio` and use
`ISE_AUTH_MODE=service_account` (stdio has no place to carry a session header).

### Tests

```bash
pytest
```

## Docker

```bash
cp .env.example .env
docker compose up --build
# server on http://localhost:8005 ; health at /healthz
```

## Cloud Foundry

Target: **ORG `ESM` / SPACE `POC`**. Two apps: `cisco-ise-mcp-ro` and `cisco-ise-mcp-rw`.

Only **sample** manifests are committed. Real manifests (`manifest.yml`, `manifest-ro.yml`,
`manifest-rw.yml`) are **gitignored** because they carry environment-specific values:

```bash
cp manifest-ro.sample.yml manifest-ro.yml     # then edit routes/env for your space
cf push -f manifest-ro.yml
```

Secrets must come from your approved pipeline/secret mechanism into CF env vars — never
commit them into manifests or VCAP. The external route (`cisco-ise-mcp.churchofjesuschrist.org`)
is fronted by F5 later; nothing in this repo assumes F5 details. See
[docs/cloud-foundry.md](docs/cloud-foundry.md).

## MCP tools

Full reference: [docs/mcp-tools.md](docs/mcp-tools.md). Summary:

| Group | Tools |
|-------|-------|
| Health/auth | `ise_health_check`, `ise_auth_status`, `ise_login`, `ise_validate_session`, `ise_logout`, `ise_whoami` |
| Endpoint | `ise_get_endpoint_by_mac`, `ise_get_endpoint_by_id`, `ise_get_endpoint_by_ip`, `ise_search_endpoints` |
| Session/auth | `ise_get_active_session_by_mac`, `ise_get_active_session_by_ip`, `ise_get_auth_logs_by_mac` |
| Policy/context | `ise_get_policy_context_by_mac`, `ise_get_incident_summary_by_mac` |
| Identity | `ise_get_user_sessions_by_username`, `ise_get_endpoint_group` |
| TrustSec | `ise_list_security_groups`, `ise_list_sgacls`, `ise_list_authorization_profiles` |
| Network device | `ise_list_network_devices` |
| Write (gated) | `ise_create_endpoint`, `ise_assign_endpoint_group`, `ise_delete_endpoint` |

## Security

See [SECURITY.md](SECURITY.md) and [docs/ise-permissions.md](docs/ise-permissions.md).
No real secrets live in this repo; all examples are obvious placeholders.

## License

MIT — see [LICENSE](LICENSE).
