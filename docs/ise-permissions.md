# ISE permissions

The MCP server calls two ISE API families with different privilege requirements.

## ERS (External RESTful Services)

- Base: `https://<ise-vip>/ers/config/...`
- Enable ERS: **Administration → System → Settings → API Settings → ERS (Read/Write)**.
- Roles:
  - **ERS Operator** — read-only (GET). Sufficient for all read tools.
  - **ERS Admin** — full CRUD. Required for write tools (`ise_create_endpoint`,
    `ise_assign_endpoint_group`, `ise_delete_endpoint`).
- The read-only CF app should use an **ERS Operator** service account.
- The read/write app in passthrough mode relies on each user's own ISE role — a read-only
  user simply gets 403 from ISE on writes, which the server surfaces as `ise_api_error`.

## MNT (Monitoring)

- Base: `https://<ise-vip>/admin/API/mnt/...`
- Requires a **monitoring-capable admin** identity (e.g. Super Admin / MnT-authorized).
- An **ERS-only** account will get **HTTP 401** from MNT. This is expected; session/auth-log
  tools will return an `ise_api_error` with status 401 and the aggregate context tool notes
  "active session unavailable (MNT)". Use an account with monitoring rights if you need live
  session and RADIUS-failure data.

## Least privilege recommendation

- `cisco-ise-mcp-ro`: ERS Operator + (optionally) monitoring read, if session data is needed.
- `cisco-ise-mcp-rw`: passthrough; grant users the minimum ISE role for their task.

## MAC lookup note

Endpoint-by-MAC uses `GET /ers/config/endpoint/name/{mac}` (canonical, reliable). Some ISE
deployments reject `filter=mac.EQUALS.<mac>` with HTTP 400; `ise_search_endpoints` supports
`mac.CONTAINS.<value>` as a fallback search.
