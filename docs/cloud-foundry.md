# Cloud Foundry deployment

Target: **ORG `ESM` / SPACE `POC`**. Two apps:

| App | Mode | Auth | Route(s) |
|-----|------|------|----------|
| `cisco-ise-mcp-ro` | readonly | service_account (or passthrough) | `cisco-ise-mcp.<default-domain>`, `cisco-ise-mcp.churchofjesuschrist.org` |
| `cisco-ise-mcp-rw` | readwrite | passthrough | `cisco-ise-mcp-rw.<default-domain>` |

## Manifests

Only `*.sample.yml` are committed. Copy to real (gitignored) files and edit:

```bash
cf target -o ESM -s POC
cp manifest-ro.sample.yml manifest-ro.yml
cp manifest-rw.sample.yml manifest-rw.yml
# edit routes + ISE_BASE_URL; leave secrets to the pipeline
cf push -f manifest-ro.yml
cf push -f manifest-rw.yml
```

## Port binding

CF injects `$PORT`. The server reads `MCP_PORT`; set it from `$PORT` at push time or via a
start command. Simplest: keep `command: python -m cisco_ise_mcp` and add to the app env a
small shim, or set `MCP_PORT` to the platform port. If your foundation exposes `$PORT` only
at runtime, use:

```yaml
    command: bash -c 'MCP_PORT="$PORT" python -m cisco_ise_mcp'
```

## Python buildpack

The `python_buildpack` needs a dependency manifest. This project uses `pyproject.toml`.
If your foundation's buildpack version does not resolve `pyproject.toml` directly, generate
a `requirements.txt` at deploy time from the pinned deps (not committed):

```bash
uv pip compile pyproject.toml -o requirements.txt   # or: pip freeze > requirements.txt
```

## Secrets

Inject `ISE_USERNAME` / `ISE_PASSWORD` / `ISE_ENCODED_AUTH` from your approved pipeline or
secret store into CF env — never commit them. Do not place secrets in VCAP examples or in
source-controlled manifests.

## External route / F5

The `churchofjesuschrist.org` route is fronted by **F5 after validation**. This repo assumes
no F5 details; validate on the default-domain route first, then coordinate the external VIP.
