# TODOS

Backlog for the WAF project, grouped by component. Within each component,
items are listed P0 → P4, then a `## Completed` section at the bottom.

## Connections (domain-only rewrite, 2026-05-22)

Spec: [docs/superpowers/specs/2026-05-22-connections-domain-only-design.md](docs/superpowers/specs/2026-05-22-connections-domain-only-design.md).
All items below are **deferred from the original spec §10** or surfaced
during T1–T9 implementation. None block the rewrite from shipping.

### Pebble (LE replica) in docker-compose.test.yml

**Priority:** P1
**What:** Add a `pebble` service to `docker-compose.yml` (or a sibling
`docker-compose.test.yml`) running `ghcr.io/letsencrypt/pebble:latest`,
and make `cert_service.trigger_acme_request` read `ACME_DIRECTORY` from
env so tests can point it at Pebble instead of real Let's Encrypt.
**Why:** The 4 DNS-flip / TLS-toggle / multi-A / SSRF-late-flip e2e
specs (spec §9) can't land without it — running them against real LE
would burn rate-limits on every CI build.
**Pros:** Unlocks the full e2e suite. Standard pattern (Caddy / Traefik
both ship with Pebble in their CI).
**Cons:** ~3h human / ~25min CC to wire compose + env + verify cert chain.
**Context:** `cert_service.trigger_acme_request` is in
[`backend/src/certificates/service.py`](backend/src/certificates/service.py)
around line 217. Today it likely hard-codes the LE prod directory URL.
The 4 deferred specs are sketched in the eng-review's test coverage
diagram and called out in `570a8c9`'s "Deferred to T9 followup" section.
**Depends on:** —

### DNS-flip e2e (`test_connections_dns_proxy.py`)

**Priority:** P2
**What:** Full happy-path e2e: create domain → add TXT → wait for poller
→ flip A-record to WAF edge → wait for ACME → assert traffic flows through
WAF to a test origin container.
**Why:** Single test that proves the entire state machine works end-to-end.
**Cons:** Needs a controllable DNS server in the compose stack (CoreDNS or
dnsmasq) + Pebble for ACME. Without those, the test would hit real DNS /
LE and become flaky + rate-limited.
**Context:** see spec §9 test coverage table.
**Depends on:** Pebble service above + a docker-DNS resolver.

### TLS-toggle e2e (`test_connections_tls_toggle.py`)

**Priority:** P3
**What:** Spin up a test origin container with a self-signed cert. Create
a connection in `strict` mode → expect 422 with a clear error. Toggle to
`lenient` → expect 200 + traffic flows.
**Why:** Proves the per-connection toggle from decision 5C works end-to-end
and that the strict-fail error message guides users to the lenient escape
hatch.
**Depends on:** test origin with self-signed cert (~30 lines compose).

### Multi-A pool e2e (`test_connections_multi_a.py`)

**Priority:** P3
**What:** DNS returns `[1.1.1.1, 1.0.0.1]` for the test domain. Assert
the rendered Angie config contains both as upstream servers with
`max_fails=3 fail_timeout=30s`.
**Depends on:** controllable DNS server in compose.

### SSRF late-flip e2e (`test_connections_ssrf.py`)

**Priority:** P2
**What:** Onboard a connection successfully. Later, change the domain's A
record to a private IP (10.0.0.5). The poller's next tick must transition
the connection to `error` instead of proxying to the internal address.
**Why:** Defence-in-depth — the deny-list at *create time* already covers
the obvious attack, but a late-flip is a separate code path through the
poller's re-resolve.
**Depends on:** controllable DNS server + see if the poller already
re-validates resolved IPs (it should via dns.resolve_a which filters,
but the test pins that behaviour).

### IPv6 / AAAA end-to-end support

**Priority:** P3
**What:** Accept domains with only AAAA records, resolve them, store in
`origin_hosts`, and require `WAF_EDGE_IPV6` env var when serving them.
Backend already filters IPv6 ULA / link-local via is_blocked_ip — the
gap is only in the resolve path (today only A records are queried).
**Why:** IPv6-first origins (Cloudflare-protected sites, Hetzner v6-only
boxes) can't onboard. Modern internet baseline.
**Context:** dns.resolve_a in `backend/src/connections/dns.py` is
A-record only. Add a parallel `resolve_aaaa` and a combined
`resolve_origins` that returns both. Adjust Angie config to emit IPv6
upstream entries.
**Depends on:** —

### CDN ASN warning for CNAME-shadowed origins

**Priority:** P4
**What:** If `socket.gethostbyname_ex` resolves a domain to an IP that
belongs to a known CDN ASN (Cloudflare, Akamai, Fastly, AWS CloudFront),
warn the user at create time: "this looks like a CDN — we'd proxy to the
CDN, not your real origin". Optional override flag to ignore.
**Why:** Users on Cloudflare orange-cloud will unknowingly create a
WAF→CF→origin sandwich, which works but doubles latency and breaks
WAF's ability to see real client IPs.
**Cons:** ASN lookup needs a periodically-refreshed database; flagged
in spec §10 as known limitation. Out of v1 scope.

### Multi-replica poller (pg_advisory_lock)

**Priority:** P4
**What:** Replace the per-row session-scoped poll with a
`pg_advisory_xact_lock(connection.id)` so multiple backend replicas can
poll the same DB without racing on ACME or TXT verification.
**Why:** Single-replica is fine for v1. If/when we scale, two replicas
running asyncio.tasks against the same `pending_dns` row could both
trigger ACME and burn the LE rate limit.

### Auto-pair apex + www

**Priority:** P4
**What:** When user adds `acme.com`, auto-create a sibling for
`www.acme.com` (and vice versa) so visitors don't 502 depending on which
hostname they typed.
**Why:** Customer support burden eliminator. Most marketing sites need
both. Currently the user has to do this manually.
**Depends on:** —

### DNS-01 ACME fallback

**Priority:** P4
**What:** When HTTP-01 fails (port 80 firewalled, ACME challenges
blocked), offer DNS-01 as an alternative. Requires API integration with
the user's DNS provider (Cloudflare API, Route53 API, etc.).
**Cons:** API integration per provider — big. Skipped in v1.

### Origin IP-change detection while active

**Priority:** P3
**What:** When a domain's origin server moves to a new IP (e.g. AWS
auto-scaling, server migration), the WAF keeps proxying to the dead IP.
**Context:** Decision 2A in the spec said "DNS re-resolve in poller" but
once the domain points at WAF, we can't re-resolve it to find the new
origin — the domain points at us, not the origin. Need a separate
`origin_hostname` field that's *different* from the proxied domain.
**Why:** Reliability — today the only recovery is delete+recreate.

### Rate-limit per-user on connection creation

**Priority:** P4
**What:** Throttle POST /api/connections per user_id to N/min so a
compromised admin account can't burn LE rate limits by spamming domains.
**Why:** Defence-in-depth. Out of v1 scope.

### Manual origin override field

**Priority:** P4
**What:** Optional `origin_host` field in the create form (free-text) so
power-users can point WAF at a different host than the domain resolves
to. Lets them put `origin.example.com` on a separate A record they never
flip, while `example.com` flips to WAF.
**Why:** Solves both "origin-behind-CDN" and "origin-IP-change-while-
active" cleanly. Decision 2C was rejected in design review because it
contradicts "knowing only the domain" — but as an *optional* power-user
field it's compatible.

### Orphan i18n keys cleanup

**Priority:** P3
**What:** Remove the stale `connections.field.*`, `connections.sourceType.*`,
`connections.help.*`, `connections.btn.uploadIndex/Folder`,
`connections.toast.uploadedFolder/uploadFailedMsg`, and related dead keys
from `frontend/src/i18n/translations.ts`. They referenced the 4-mode
form fields and upload UI that no longer exist.
**Why:** Bundle bloat + readability. Currently ~60 lines × 2 dicts.
**Context:** Left in d4765e2 to keep the diff scope tight. Mechanical
sweep — grep each key for actual usage, delete unused.
**Depends on:** —

## Other

(Other components have no open items at the moment. Add new sections here
as work surfaces.)

## Completed

- **Connections domain-only rewrite (T1–T9)** — Completed: v1.0.0 (2026-05-22).
  Commits 0ce8914, d4765e2, a7202cc, 570a8c9 on
  `feat/connections-domain-only`.
