# WAF

## Quick start

```bash
git clone https://github.com/Cringeneers/demo-repository.git waf
cd ./waf
./scripts/generate-env.sh
docker compose up -d --build
```

## Deploy

```bash
./deploy.sh
```

## Security model

### Threat model: `admin` role is host-root equivalent

The `docker_compose` connection source type (introduced 2026-05) lets an
**admin** user submit an inline `docker-compose.yml` body that the backend
brings up with `docker compose up -d`. Because the WAF backend container
already mounts `/var/run/docker.sock` (required for Angie reloads and
container introspection), a compose body interpreted by the host Docker
daemon can — by design — create privileged containers, bind-mount host
paths, or mount the Docker socket itself.

**The `admin` role is therefore equivalent to host root** on the machine
running the WAF. This is intentional for a self-hosted single-tenant
deployment.

#### Defense-in-depth that is in place

- All connection-management endpoints (`POST/PUT/DELETE /api/connections/*`)
  require `require_admin`. Viewers and unauthenticated users cannot reach
  them. See [`backend/src/main.py`](backend/src/main.py).
- The compose-YAML body is run through a deny-list before
  `docker compose up -d`. See `_validate_compose_yaml` in
  [`backend/src/connections/service.py`](backend/src/connections/service.py).
  Patterns currently rejected (case-insensitive):
  - `privileged: true`
  - `pid: host`, `network_mode: host`, `ipc: host`, `userns_mode: host`
  - any `cap_add:` block
  - bind mounts of `/`, `/etc`, `/proc`, `/sys`, `/root`, or
    `/var/run/docker.sock`
  - any `devices:` block
- The generated `docker-compose.yml` is written with mode `0o600` inside a
  `0o700` project directory so other processes sharing the volume cannot
  read secrets embedded in `environment:` blocks.

The deny-list is a string scan, **not** a hardened parser. It is meant as
one layer of defense in depth on top of the admin-only restriction, not as
a sandbox. Do **not** add a role that can create connections without also
restricting it from `source_type: docker_compose`.

#### What you must NOT do

- Do **not** add a `viewer` or `editor` role that can create connections
  without also rejecting `source_type: docker_compose` for that role.
- Do **not** loosen the deny-list without an explicit security review.
- Do **not** expose the WAF admin panel to untrusted networks. Put it
  behind your own VPN or IP allow-list.

### Other notable security defaults

- Authentication: cookie-based sessions; auth/RBAC enforced in FastAPI
  dependencies (`require_password_changed`, `require_admin`).
- All dashboard / CrowdSec endpoints validate query parameters via
  Pydantic ranges (`hours: float = Query(..., ge=0.0167, le=8760)`,
  `connection_id: int = Query(..., ge=1)`).
- ClickHouse queries that interpolate per-domain filters strip `'`, `\`
  and `\x00` from domain names before building the SQL fragment
  (`_quote_domains` in [`backend/src/dashboard/service.py`](backend/src/dashboard/service.py)).

## Tests

```bash
# Unit + integration (no docker needed)
PYTHONPATH=backend pytest -m "unit or integration" tests/unit tests/integration -v

# Full stack e2e (requires the docker-compose stack running)
pytest -m e2e tests/e2e -v
```
