# WAF load testing (k6)

Scripts in this folder drive [k6](https://k6.io) against the running Angie
front-end so we can measure real-world throughput, latency, and the cost of
ModSecurity / CrowdSec / compression on the hot path.

## Running locally (via docker compose)

```bash
# Smoke (10s, 10 VUs) — wired into CI
docker compose --profile loadtest run --rm k6 run /scripts/smoke.js

# Baseline (60s ramp to 200 VUs)
docker compose --profile loadtest run --rm k6 run /scripts/baseline.js

# Spike (sudden 1k VUs)
docker compose --profile loadtest run --rm k6 run /scripts/spike.js

# Soak (20-minute steady state)
docker compose --profile loadtest run --rm k6 run /scripts/soak.js

# Compression-aware sweep — re-runs the baseline with each encoder
docker compose --profile loadtest run --rm k6 run /scripts/compression-matrix.js

# HTTP/2 vs HTTP/3 comparison (targets a TLS connection with --http2 / --http3)
docker compose --profile loadtest run --rm \
  -e TARGET_SCHEME=https -e TARGET_PORT=443 \
  k6 run /scripts/http-versions.js
```

The `k6` service runs in compose profile `loadtest` so it does **not** start
with the rest of the stack — invoke it explicitly when you want to measure.

## Environment

| Var                  | Default | Notes                                          |
|----------------------|---------|------------------------------------------------|
| `TARGET_HOST`        | `angie` | Service / hostname to hit (`angie` over Docker net) |
| `TARGET_PORT`        | `80`    | `443` for HTTPS                                |
| `TARGET_SCHEME`      | `http`  | `http` or `https`                              |
| `TARGET_PATH`        | `/`     | Path under test                                |
| `K6_VUS`             | (script) | Override VUs per stage                        |
| `K6_DURATION`        | (script) | Override duration                             |
| `K6_OUT`             | (empty) | e.g. `experimental-prometheus-rw` or `json=results.json` |

## Targets

The default `smoke.js` thresholds are:

* `http_req_failed`  ≤ 1%
* `http_req_duration{p(95)}` ≤ 500ms
* `iterations` ≥ 100

Tune these in each script as you raise the load envelope.
