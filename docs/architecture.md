# Architecture

## Layers

| Layer | Module(s) | Responsibility |
|-------|-----------|----------------|
| Transport | `server.py`, `__main__.py` | FastMCP app, stdio/HTTP, session-header middleware |
| Auth | `auth/` | provider interface, passthrough, service account, in-memory sessions |
| Tools | `tools/` | MCP tool definitions; thin, delegate to ISE layer |
| ISE access | `ise/` | async HTTP client, ERS + MNT wrappers, models, errors |
| Cross-cutting | `config.py`, `logging_config.py`, `audit.py`, `redaction.py`, `validation.py`, `responses.py` | config, structured logs, audit, redaction, input validation, response envelope |

Design intent: **tools never build URLs or parse ISE payloads directly** — they call the
`ise/` layer, so ISE API drift is isolated. Tools also never see raw credentials — only a
resolved `AuthContext`, so new auth providers require no tool changes.

## Request flow (HTTP)

1. `SessionHeaderMiddleware` reads `X-MCP-Session` (or `Authorization: Bearer`) into a
   contextvar.
2. Tool calls `Deps.resolve_auth()` → provider returns an `AuthContext`
   (passthrough: session lookup; service_account: fixed identity).
3. `tools.run()` gates the tool (enabled? write allowed?), runs it, audits, and shapes the
   response/error.
4. `ise/client.py` issues the ISE call with per-request HTTP Basic from the `AuthContext`.

## Non-scope and orchestration

ISE answers "who/what is this identity, what policy/session applies". Topology, device
inventory, and reachability come from other MCPs. A future orchestrator correlates by MAC/
IP/user across:

- **cisco-ise-mcp** — identity/policy/session/profiling (this repo)
- **Catalyst Center MCP** — campus topology, device/client, assurance
- **Arista CVaaS MCP** — switch/interface, MLAG
- **NetBox MCP** — source-of-truth IPAM/DCIM

The `ise_get_incident_summary_by_mac` tool returns both a narrative and the structured
context so an orchestrator can merge it with peers.

## pxGrid (phase 2)

Not implemented in v1. The provider/tool separation and the `ise/` client abstraction leave
room to add a `ise/pxgrid.py` module and pxGrid-backed session tools without disturbing ERS/
MNT paths. Reserve auth providers already exist for the pxGrid client-cert model (`mtls`).
