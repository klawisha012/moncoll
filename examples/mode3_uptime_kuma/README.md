# Mode 3 example — Uptime Kuma

[louislam/uptime-kuma](https://github.com/louislam/uptime-kuma) is a popular
self-hosted uptime monitor that ships as a single Docker container. This is
the canonical case for the WAF `container` mode: a long-lived app you spin
up out-of-band, then point the WAF at by container name.

## How it was wired up

```bash
# 1. Launch the container, joining the WAF's docker network so the backend
#    can resolve it by name.
docker run -d \
  --name waf-example-uptime-kuma \
  --network waf_default \
  --restart unless-stopped \
  -v uptime-kuma-data:/app/data \
  louislam/uptime-kuma:1
```

## Connection form values

| Field | Value |
| --- | --- |
| `name` | `mode3-uptime-kuma` |
| `domains` | `["uptime.test"]` |
| `source_type` | `container` |
| `backend_url` | `http://waf-example-uptime-kuma:3001` |
| `preserve_host` | `true` |

## Verifying

```bash
# Should return HTTP 302 → /dashboard (Kuma's setup redirect)
curl -sk -o /dev/null -w 'HTTP %{http_code}\n' -H 'Host: uptime.test' https://localhost/

# Reaches Kuma's setup wizard
curl -sk -L -H 'Host: uptime.test' https://localhost/ | grep '<title>'
# → <title>Uptime Kuma</title>
```

## Cleanup

```bash
docker rm -f waf-example-uptime-kuma
docker volume rm uptime-kuma-data
```
