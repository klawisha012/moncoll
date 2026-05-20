# WAF connection examples

Four real-world OSS projects, one per connection mode. Each shows how to wire
the project into the WAF and what knobs the connection form needs.

| Mode | Folder | Upstream | What's interesting |
| --- | --- | --- | --- |
| 1. `nginx_config` | [`mode1_h5bp/`](./mode1_h5bp/) | [h5bp/server-configs-nginx](https://github.com/h5bp/server-configs-nginx) | Real modular nginx config with `include` partials |
| 2. `static_generate` | [`mode2_astro/`](./mode2_astro/) | [Astro starter blog](https://github.com/withastro/astro/tree/main/examples/blog) | Built static SPA with `/dist` as the served root |
| 3. `container` | [`mode3_uptime_kuma/`](./mode3_uptime_kuma/) | [louislam/uptime-kuma](https://github.com/louislam/uptime-kuma) | Pre-running Docker container reverse-proxied by name |
| 4. `docker_compose` | [`mode4_umami/`](./mode4_umami/) | [umami-software/umami](https://github.com/umami-software/umami) | Multi-service compose stack orchestrated by the WAF |

See each folder for the exact `domains` / `backend_url` / `static_dir` /
`compose_yaml` values used during the verification run that landed this set.

The legacy `test_mode1/`, `test_mode2/`, `test_mode3/` folders are smoke-test
fixtures and are not real-world references — keep them around for the unit
test suite, prefer the `modeN_*/` folders when demoing.
