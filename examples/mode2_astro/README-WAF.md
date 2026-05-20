# Mode 2 example — Astro starter blog

[withastro/astro](https://github.com/withastro/astro/tree/main/examples/blog)
`examples/blog` is a clean MDX-based static blog template. After `npm run build`
it lands in `dist/`, which is exactly what the WAF `static_generate` mode
expects: a directory of pre-rendered HTML/CSS/JS to serve as-is.

## How it was wired up

```bash
# 1. Scaffold:
npm create astro@latest examples/mode2_astro -- --template blog \
  --no-install --no-git --typescript strict --skip-houston

# 2. Install + build:
cd examples/mode2_astro
npm install
npm run build           # → produces ./dist/
```

The `dist/` directory is what the WAF serves. Because `examples/` is mounted
read-only into the backend container at `/app/site-templates/examples/`, the
backend can find `dist/` without uploading anything via the UI.

## Connection form values

| Field | Value |
| --- | --- |
| `name` | `mode2-astro` |
| `domains` | `["astro.test"]` |
| `source_type` | `static_generate` |
| `static_dir` | `examples/mode2_astro/dist` |
| `preserve_host` | `true` |

## Verifying

```bash
curl -sk -o /dev/null -w 'HTTP %{http_code}\n' -H 'Host: astro.test' https://localhost/
curl -sk -L -H 'Host: astro.test' https://localhost/ | grep '<title>'
# → <title>Astro Blog</title>
curl -sk -o /dev/null -w 'HTTP %{http_code}\n' -H 'Host: astro.test' https://localhost/rss.xml
# → HTTP 200 (Astro's auto-generated feed)
```

## Re-building after content changes

Astro is a build step, not a runtime — edit posts under `src/content/blog/`,
re-run `npm run build`, then trigger a connection reload from the WAF UI
(or `POST /api/connections/reload`) to re-copy `dist/` into the live site dir.
