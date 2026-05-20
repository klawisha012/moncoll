# Mode 4 example — Umami analytics

[umami-software/umami](https://github.com/umami-software/umami) is a
privacy-friendly web analytics platform. Its upstream `docker-compose.yml`
ships two services (the Next.js app + a PostgreSQL database). This is the
canonical case for the WAF `docker_compose` mode: the WAF brings the stack
up, derives `service:port` as the backend URL, and reverse-proxies into it.

## What was adapted from upstream

`docker-compose.upstream.yml` is the unmodified file from the Umami repo.
`docker-compose.yml` makes two changes:

1. **Removed** the host port publication (`ports: "3000:3000"`). The WAF
   does the public-facing TLS termination — exposing umami on the host
   would bypass the WAF entirely.
2. **Joined** the `waf_default` network as an alias `waf` so the WAF backend
   container can resolve `umami:3000` and forward requests in.

```yaml
networks:
  waf:
    external: true
    name: waf_default
```

## Connection form values

| Field | Value |
| --- | --- |
| `name` | `mode4-umami` |
| `domains` | `["umami.test"]` |
| `source_type` | `docker_compose` |
| `compose_yaml` | contents of [`docker-compose.yml`](./docker-compose.yml) |
| `compose_service` | `umami` |
| `compose_port` | `3000` |
| `preserve_host` | `true` |

The WAF derives `backend_url = umami:3000` from the service+port pair after
`docker compose up -d` completes.

## First-boot cost

Umami runs `prisma migrate deploy` on first start, which takes ~30s before the
app starts serving. The WAF's compose timeout is set to 600s (in
`backend/src/connections/service.py`) to give cold pulls + first-boot migrations
enough headroom. The very first deploy will also pull the umami image, which
is several hundred MB — pre-pull it (`docker pull
ghcr.io/umami-software/umami:postgresql-latest`) before creating the connection
if you want to skip a slow first reload.

## Verifying

```bash
curl -sk -L -H 'Host: umami.test' https://localhost/ | grep '<title>'
# → <title>Umami</title>

curl -sk -H 'Host: umami.test' https://localhost/api/heartbeat
# → {"ok":true}
```

Default credentials are `admin` / `umami`. Change them on first login.
