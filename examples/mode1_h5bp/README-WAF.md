# Mode 1 example — h5bp/server-configs-nginx

[h5bp/server-configs-nginx](https://github.com/h5bp/server-configs-nginx) is
the canonical "real-world modular nginx config" reference. We use it to
exercise the WAF's `nginx_config` mode end-to-end: include resolution,
server-block extraction, static file copying, and security-header pass-through.

## What was adapted from upstream

The h5bp repo's top-level `nginx.conf` is a *full nginx config* — it sets
`user`, `events`, `http { ... }`, etc. The WAF only consumes the server
block out of an uploaded config (the rest is supplied by the global Angie
config in `configs/angie/angie.conf`), so we ship a custom WAF-targeted
`nginx.conf` at the root of this folder and preserve the upstream one as
`nginx-fullstack.conf.example`.

The WAF entrypoint `nginx.conf` here:
- Has a single `server { ... }` block (what the WAF extracts).
- `include`s only the variable-free h5bp partials (the ones that depend on
  `map`-based variables — e.g. `referrer-policy.conf` referencing
  `$referrer_policy` — can't work because `map` is only valid inside
  `http { ... }` and we can't inject it from a server block).
- Inlines the small headers that would otherwise need a map.

## Connection form values

| Field | Value |
| --- | --- |
| `name` | `mode1-h5bp` |
| `domains` | `["h5bp.test"]` |
| `source_type` | `nginx_config` |
| `nginx_config_path` | `/app/site-templates/examples/mode1_h5bp/nginx.conf` |
| `preserve_host` | `true` |

(Because `examples/` is mounted read-only into the backend at
`/app/site-templates/examples/`, no upload is needed — just reference the
file by path.)

## Verifying

```bash
# Probe endpoint short-circuits to a literal 200 inside the deployed server
# block, with ModSecurity auto-bypassed by the WAF's _inject_modsec_bypass.
curl -sk -H 'Host: h5bp.test' https://localhost/probe
# → mode1-h5bp-ok

# Static index.html (from this folder, copied into the conn site dir).
curl -sk -L -H 'Host: h5bp.test' https://localhost/ | grep '<title>'
# → <title>h5bp · WAF mode 1 (nginx_config)</title>

# h5bp security headers actually present on the response.
curl -sk -I -H 'Host: h5bp.test' https://localhost/ | grep -iE 'x-frame|x-content|referrer'
```

## Parser bugs this example surfaced

Wiring this up uncovered two bugs in the WAF's nginx parser, now fixed and
covered by regression tests in
[`tests/unit/backend/test_connections_nginx_parser.py`](../../tests/unit/backend/test_connections_nginx_parser.py):

1. `_extract_nginx_server_blocks` was comment-blind — a literal `server {`
   inside a `# …` comment would be picked up as a real block.
2. `_resolve_nginx_includes` resolved nested includes against the
   *including file's* directory; nginx resolves them against the prefix
   (top-level conf's directory), and h5bp's modular partials rely on that.
