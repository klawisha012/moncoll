# Connections — domain-only rewrite (DNS reverse-proxy WAF)

**Status:** Approved design, ready for implementation plan
**Date:** 2026-05-22
**Author:** brainstorming + plan-eng-review (9 decisions locked)
**Supersedes:** existing 4-mode connections (`nginx_config` / `static_generate` / `container` / `docker_compose`)

---

## 1. Problem & Goal

**Problem.** Текущая `connections` фича — 4 source_type режима, разветвлённая форма, 1633-строчный `service.py`, ломкие e2e тесты (последняя поломка — конн. рефактор сломал `nginx_config_path` тест). UX: пользователь должен понимать nginx, compose или принести static-build.

**Goal.** User connects a website to the platform knowing only the domain. Меняет DNS на edge, трафик идёт через WAF к их origin'у — как Cloudflare/Sucuri.

**Non-goal v1:** хостинг сайта на WAF, выгрузка static, прокси на docker-compose стек, обёртывание чужого nginx-конфига.

---

## 2. User journey

```
1. User: вводит domain (например acme.com)
2. WAF: показывает TXT-токен → user добавляет _waf-verify.acme.com TXT
3. WAF: резолвит TXT → подтверждает владение
4. WAF: резолвит A/AAAA(acme.com) → получает origin IP(s); SSRF deny-list проверка
5. WAF: health-check HEAD https://{origin}:443 с SNI=acme.com
6. WAF: создаёт row, пишет Angie config (HTTP-only, status=pending_dns)
7. UI: "Point A record of acme.com to <WAF_EDGE_IPV4>"
8. User: меняет A-запись
9. Poller: видит A==EDGE_IP → status=provisioning_cert → ACME HTTP-01
10. Cert issued → status=active, Angie конфиг переписан с TLS, reload
11. Трафик: client → WAF (TLS termination, WAF rules) → HTTPS → origin
```

---

## 3. Data model

### Table `connections` (миграция 0005)

| Column | Type | Note |
|---|---|---|
| `id` | int PK | |
| `user_id` | int FK users(id) | **NEW**, не null, ON DELETE CASCADE |
| `name` | varchar(128) | human label |
| `domain` | varchar(253) | UNIQUE, lowercase+IDNA normalized |
| `origin_hosts` | JSON list[str] | multi-A origin pool (decision 6A) |
| `origin_port` | int | default 443 |
| `origin_tls_mode` | enum('strict','lenient') | default 'strict' (decision 5C) |
| `verify_token` | varchar(64) | random token for TXT _waf-verify (decision 1B) |
| `verified_at` | timestamp null | NULL until TXT confirmed |
| `status` | enum | `pending_verification` / `pending_dns` / `provisioning_cert` / `active` / `error` |
| `status_detail` | text null | last error/progress message |
| `acme_retry_count` | int default 0 | decision 4A |
| `acme_next_retry_at` | timestamp null | exp-backoff next attempt |
| `next_poll_at` | timestamp null | DNS-TTL respecting (decision 9A) |
| `dns_ttl_seconds` | int default 60 | resolved TTL for next_poll_at |
| `last_checked_at` | timestamp null | |
| `ssl_cert_path` | varchar null | ACME-managed |
| `ssl_key_path` | varchar null | |
| `http_versions` | varchar | "h1,h2,h3" comma-list (kept) |
| `compression_algo` | enum | auto/gzip/brotli/zstd/none (kept) |
| `enabled` | bool default true | |
| `created_at`, `updated_at` | timestamp | |

**Dropped columns:** `source_type`, `nginx_config_path`, `static_dir`, `backend_url`, `compose_yaml`, `compose_service`, `compose_port`, `preserve_host`, `custom_nginx_config`, `ssl_enabled`.

### State machine

```
              POST /connections
                    │
                    ▼
       pending_verification (TXT not seen)
                    │
                    ▼  poller resolves TXT == verify_token
            pending_dns
                    │
                    ▼  poller: A(domain) ⊇ {EDGE_IPV4}
            provisioning_cert
                  │   │
        ACME ok  │   │  ACME fail
                  ▼   ▼
                active   error (acme_retry >= 5)
                  ▲       │
                  │       │ manual POST /probe
                  └───────┘
```

---

## 4. Endpoints

| Method | Path | Body / Effect |
|---|---|---|
| POST | `/api/connections` | `{name, domain, origin_tls_mode?}` → создать row(status=pending_verification), вернуть `{id, verify_token, dns_instructions}` |
| GET | `/api/connections` | список (scoped to user via RBAC) |
| GET | `/api/connections/{id}` | один |
| PATCH | `/api/connections/{id}` | `{name?, enabled?, origin_tls_mode?}` — domain неизменяем |
| DELETE | `/api/connections/{id}` | снос: row + Angie config + cert + reload |
| POST | `/api/connections/{id}/probe` | manual re-trigger (TXT check OR DNS check OR ACME, в зависимости от state) |

**Удалены:** `/static-upload`, `/nginx-upload`, `/static-dir-upload`, `/per-connection-upload`, `/connections/{id}/upload`, любые compose-эндпоинты.

---

## 5. Module layout (decision 7A — 5 файлов)

```
backend/src/connections/
├── __init__.py        # router export
├── router.py          # FastAPI endpoints (RBAC, request/response)
├── schemas.py         # Pydantic — Connection/Create/Update/VerifyInstructions
├── service.py         # CRUD orchestration, transactions  (~80 LOC)
├── dns.py             # resolve_a/aaaa/txt, validate_domain, is_blocked (~80 LOC)
├── angie_config.py    # render_pending_dns, render_active templates (~100 LOC)
├── acme.py            # backoff state machine wrapper over cert_service (~50 LOC)
└── poller.py          # background asyncio task, semaphore-bounded (~80 LOC)
```

### `dns.py` (security-critical)

```python
PRIVATE_NETWORKS = [
    ip_network("10.0.0.0/8"), ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"), ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"), ip_network("0.0.0.0/8"),
    ip_network("::1/128"), ip_network("fc00::/7"), ip_network("fe80::/10"),
]

def is_blocked(ip_str: str) -> bool:
    ip = ip_address(ip_str)
    return ip.is_private or ip.is_loopback or ip.is_link_local \
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified

def validate_domain(s: str) -> str:
    """Return normalised IDNA-ASCII lowercase; raise ValueError otherwise."""
    s = s.strip().rstrip(".").lower()
    if not s or "/" in s or " " in s: raise ValueError(...)
    if s in ("localhost",) or s.endswith((".local", ".internal", ".corp", ".lan")):
        raise ValueError("private TLDs not allowed")
    try:
        return idna.encode(s).decode("ascii")
    except idna.IDNAError as e: raise ValueError(...) from e

async def resolve_a(domain: str) -> list[str]:
    """Resolve to public IPv4 list, raises if all addresses are blocked."""
    ...
```

### `acme.py` — backoff (decision 4A)

```python
BACKOFF_TABLE_SECONDS = [60, 300, 1800, 7200, 43200]  # 1m, 5m, 30m, 2h, 12h
MAX_RETRIES = 5

def schedule_next_retry(retry_count: int) -> datetime:
    base = BACKOFF_TABLE_SECONDS[min(retry_count, len(BACKOFF_TABLE_SECONDS)-1)]
    jitter = base * random.uniform(-0.2, 0.2)
    return now() + timedelta(seconds=base + jitter)
```

### `poller.py` — bounded concurrency (decision 9A)

```python
SEM = asyncio.Semaphore(20)

async def tick():
    rows = await select_due_rows()  # WHERE next_poll_at <= now() AND enabled
    async with asyncio.TaskGroup() as tg:
        for row in rows:
            tg.create_task(_process_one(row))

async def _process_one(row):
    async with SEM:
        if row.status == "pending_verification":
            await _check_txt(row)
        elif row.status in ("pending_dns", "error"):
            await _check_dns_and_maybe_acme(row)
        elif row.status == "active":
            await _maybe_refresh_origin(row)
        row.next_poll_at = now() + max(60, row.dns_ttl_seconds)
        await commit()
```

---

## 6. Angie config — two states

### `pending_dns` / `pending_verification` — HTTP only

```nginx
upstream conn_{id}_origin { {% for ip in origin_hosts %}server {ip}:443 max_fails=3 fail_timeout=30s;{% endfor %} keepalive 16; }

server {
    listen 80;
    server_name {domain};
    access_log /var/log/angie/geoip.log with_geoip_json;
    access_log /var/log/angie/access.log combined;
    include http.d/conn_{id}/blocked_ips.conf;

    location ^~ /.well-known/acme-challenge/ {
        root /etc/angie/http.d/conn_{id}/acme;
        try_files $uri =404;
    }
    modsecurity on;
    modsecurity_rules_file /etc/angie/modsecurity/rules.conf;
    location /socket.io/ { modsecurity off; <<<proxy_block>>>; }
    location /          { <<<proxy_block>>>; }
}
```

### `active` — full HTTPS

```nginx
upstream conn_{id}_origin { ... }

server {
    listen 80; server_name {domain};
    location ^~ /.well-known/acme-challenge/ { root /etc/angie/http.d/conn_{id}/acme; try_files $uri =404; }
    location / { return 301 https://$host$request_uri; }
}

server {
    listen 443 ssl;
    {% if h2 %}http2 on;{% endif %}
    {% if h3 %}listen 443 quic; http3 on; add_header Alt-Svc 'h3=":443"; ma=86400' always;{% endif %}
    server_name {domain};
    ssl_certificate     {ssl_cert_path};
    ssl_certificate_key {ssl_key_path};
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    access_log /var/log/angie/geoip.log with_geoip_json;
    access_log /var/log/angie/access.log combined;
    include http.d/conn_{id}/blocked_ips.conf;
    modsecurity on;
    modsecurity_rules_file /etc/angie/modsecurity/rules.conf;
    {% compression overrides if not auto %}
    location /socket.io/ { modsecurity off; <<<proxy_block>>>; }
    location /          { <<<proxy_block>>>; }
}
```

### Reused `<<<proxy_block>>>`

```nginx
proxy_pass                          https://conn_{id}_origin;
proxy_ssl_server_name               on;
proxy_ssl_name                      {domain};
{% if origin_tls_mode == 'strict' %}
proxy_ssl_verify                    on;
proxy_ssl_trusted_certificate       /etc/ssl/certs/ca-certificates.crt;
{% else %}
proxy_ssl_verify                    off;
{% endif %}
proxy_set_header Host               {domain};
proxy_set_header X-Real-IP          $remote_addr;
proxy_set_header X-Forwarded-For    $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto  $scheme;
proxy_http_version 1.1;
proxy_set_header Upgrade            $http_upgrade;
proxy_set_header Connection         $connection_upgrade;
proxy_buffering off; proxy_request_buffering off; proxy_redirect off;
proxy_read_timeout 3600s; proxy_send_timeout 3600s;
```

`$connection_upgrade` map в `angie.conf` **сохраняется** (project memory: удаление крашит Angie globally).

---

## 7. UI flow

### Connections page

- Большая кнопка "Add domain"
- Список connections: `name | domain | status badge | enabled toggle | actions`
- Status badge:
  - `pending_verification` — серый "Verify domain ownership" + кнопка "Show TXT instructions"
  - `pending_dns` — жёлтый "Waiting for DNS change to <EDGE_IPV4>"
  - `provisioning_cert` — синий "Issuing TLS certificate…"
  - `active` — зелёный "Protected"
  - `error` — красный + status_detail + кнопка "Retry"

### Add-domain wizard (modal, 3 шага)

```
Step 1 — Domain
  ┌─────────────────────────────────────────┐
  │ Name:   [ My production site         ]  │
  │ Domain: [ example.com                ]  │
  │ Origin TLS:  ◉ Strict   ○ Lenient       │
  │                              [ Next → ] │
  └─────────────────────────────────────────┘

Step 2 — Verify ownership (POST /api/connections returned token)
  ┌─────────────────────────────────────────┐
  │ Add this TXT record to your DNS:        │
  │                                          │
  │   _waf-verify.example.com  TXT  XXXXX   │
  │                                          │
  │ Then click Verify.       [ Verify ⟳ ]   │
  └─────────────────────────────────────────┘

Step 3 — Switch DNS (after TXT verified, A resolved, origin probed)
  ┌─────────────────────────────────────────┐
  │ ✓ Verified, origin found at 1.2.3.4     │
  │                                          │
  │ Now point your A record to WAF:         │
  │                                          │
  │   example.com  A  93.184.216.34          │
  │                                          │
  │ Your traffic will start flowing through  │
  │ WAF within ~60s of DNS propagation.      │
  │                                       [ Done ] │
  └─────────────────────────────────────────┘
```

Frontend file: `frontend/src/pages/Connections.tsx` — полностью переписать, ~50% меньшего размера.

### 7.1 Design system alignment (Constructivist)

Use existing tokens from `frontend/src/index.css`. Никаких нативных компонент-библиотек.

| Element | Token | Notes |
|---|---|---|
| Modal frame | `bg: var(--cream)` + `box-shadow: var(--shadow-offset-lg)` (9px ink offset) + `border: 2px solid var(--line)` | Sharp corners (radius 0 global) |
| Modal heading | `font-family: var(--font-display)` (Unbounded), size 24px, weight 700 | Step indicator "01 / 03" в `var(--font-cond)` (Oswald) |
| Body text | `var(--font-body)` 14-16px line-height 1.45 | |
| Input field | `bg: var(--input-bg)` + `border: 2px solid var(--line)` + `focus-ring`: global red 3px | Height 44px (touch target) |
| TXT/IP value block | `bg: var(--cream-3)` + `border: 2px solid var(--line)` + `font-family: var(--font-mono)` (JetBrains Mono) | Tap to copy on mobile, click-select-all on desktop |
| Primary button | `bg: var(--ink)` + `color: var(--cream)` + `box-shadow: var(--shadow-offset-sm)` | Hover: shadow shifts to (2px 2px) — "press" effect |
| Secondary button | `bg: transparent` + `border: 2px solid var(--line)` | Same press-effect on hover |
| Step indicator dots | 3 squares (12px), filled `var(--ink)` if current/done, `var(--cream-3)` if pending | No circles — sharp |

**Status badges** (list page):

| Status | bg | text | icon | label |
|---|---|---|---|---|
| pending_verification | `var(--cream-3)` | `var(--ink-soft)` | `⃞` (sharp square outline) | "Verify ownership" |
| pending_dns | `rgba(178, 122, 0, 0.16)` (--warning bg) | `var(--amber)` | `▷` | "Waiting for DNS" |
| provisioning_cert | `rgba(12, 12, 12, 0.08)` | `var(--ink)` | `◐` (animated rotate) | "Issuing certificate" |
| active | `rgba(44, 122, 61, 0.16)` (--success bg) | `var(--ok)` | `■` | "Protected" |
| error | `var(--red-soft)` | `var(--red-deep)` | `▲` | "Setup failed" + `var(--status_detail)` tooltip |

Badges: sharp-cornered, `border: 1.5px solid currentColor`, padding 4px 10px, font `var(--font-cond)` uppercase letter-spacing 0.04em. **NO** rounded chips, NO gradient fills, NO emoji.

### 7.2 State matrix (per screen)

```
Screen           | Idle               | Loading              | Empty                          | Error                                   | Success
─────────────────|────────────────────|──────────────────────|────────────────────────────────|─────────────────────────────────────────|──────────
List page        | Table of conns     | Skeleton rows ×3     | Hero: "No domains connected"   | Banner under header: "Failed to load"   | n/a
                 |                    |                      | + big Add button + 1-line hint |                                         |
─────────────────|────────────────────|──────────────────────|────────────────────────────────|─────────────────────────────────────────|──────────
Wizard step 1    | Form fields        | Submit btn → spinner | n/a                            | Inline under field:                     | →step2
 (Domain)        |                    | "Resolving origin…"  |                                | • "Invalid domain" (client-side)        |
                 |                    |                      |                                | • "Domain already added" (409)          |
                 |                    |                      |                                | • "DNS resolution failed: <reason>"     |
                 |                    |                      |                                | • "Domain points to internal IP" (SSRF) |
                 |                    |                      |                                | • "Origin TLS invalid: …                |
                 |                    |                      |                                |    [switch to Lenient mode]"            |
─────────────────|────────────────────|──────────────────────|────────────────────────────────|─────────────────────────────────────────|──────────
Wizard step 2    | TXT instructions   | "Checking DNS…"      | n/a                            | "TXT not found yet. Propagation can     | →step3
 (TXT verify)    | + "Verify now" btn | spinner under btn    |                                |  take 5-30 min. We're re-checking."     |
                 | + auto-poll        |                      |                                | Subtle red border on TXT block          |
─────────────────|────────────────────|──────────────────────|────────────────────────────────|─────────────────────────────────────────|──────────
Wizard step 3    | DNS instructions   | n/a                  | n/a                            | n/a (instructions only)                 | Done btn
 (Switch A)      | + edge IP value    |                      |                                |                                         | closes
─────────────────|────────────────────|──────────────────────|────────────────────────────────|─────────────────────────────────────────|──────────
Resume row in    | Badge + name +     | n/a                  | n/a                            | "Setup failed: <detail>" + Retry button | n/a
 list (pending)  | "Resume setup"     |                      |                                |                                         |
                 | secondary button   |                      |                                |                                         |
```

### 7.3 Motion

- Modal entrance: 200ms ease-out scale 0.96→1 + fade 0→1. No bounce.
- Step transition: 160ms slide left, content fade.
- Status badge transition (pending→active): 360ms `var(--duration-slow)` — bg color crossfade + small scale 1.04→1 pulse on icon.
- `provisioning_cert` icon ◐ rotates 1.2s linear infinite.
- Auto-poll spinner: same `◐` rotation, 0.8s.
- Toast (Resume saved): slide-in from bottom-right, 4s auto-dismiss, dismissable.
- Respect `prefers-reduced-motion: reduce` — kill all rotations + scale, keep crossfades at 120ms.

### 7.4 Responsive

| Breakpoint | Wizard | List |
|---|---|---|
| ≥768px (desktop) | Modal 560px wide, centered | Table layout with columns |
| 480-767px (tablet) | Modal 90vw, max 480px | Compact table, hide updated-at column |
| <480px (phone) | Modal becomes full-screen sheet (slide-up from bottom) | Card list (one row = one card) |

Mobile-specific:
- TXT/IP blocks are tappable; tap copies to clipboard, shows "Copied" toast.
- Step indicator becomes "Step 2 of 3" text instead of dots.
- Buttons stack vertically when modal width <420px.
- Touch targets ≥44px everywhere.

### 7.5 Accessibility

- **Focus trap** within wizard modal; Esc behaviour per §7.7 (save+toast, not discard).
- **Tab order:** form fields → primary action (Next/Verify/Done) → secondary action (Back/Cancel).
- **ARIA live region** (`aria-live="polite"`) on list page announcing status badge transitions: "acme.com now Protected".
- **Status badges are never color-only** — always include icon + text label (the constructivist design already does this).
- **Color contrast:** verified against WCAG AA on cream paper (`--ink` on `--cream` = 16:1; `--red-deep` on `--cream` = 7.4:1; `--ok` `#2c7a3d` on `--cream` = 5.1:1; `--amber` `#b27a00` on `--cream` = 4.6:1). All pass.
- **Keyboard shortcuts:** `Enter` advances wizard; `Cmd/Ctrl+C` on focused TXT/IP block copies it; `Esc` closes (per §7.7).
- **Form errors** linked via `aria-describedby` to their input field; auto-focus the first invalid field on submit failure.
- **Loading states** announced: `<button aria-busy="true">Resolving origin…</button>`.
- **Modal labelled** with `aria-labelledby` pointing at the step heading.

### 7.6 Copy guidelines + AI-slop guardrails

**Voice:** utility, not marketing. Spec'd against the Constructivist system.

GOOD: "Add this TXT record to your DNS." | "Waiting for DNS change." | "Setup failed: origin certificate expired."

BAD: "Let's get you protected! 🛡️" | "Welcome to your secure new home" | "We're working our magic ✨"

**Hard-banned patterns:**
- ❌ 3-column "How it works" decoration block anywhere in the page or wizard
- ❌ Icons in colored circles for status (use sharp shapes per §7.1)
- ❌ Hero copy clichés ("Unlock", "All-in-one", "Powerful")
- ❌ Emoji as UI (✓ ⚠ → arrow icons via lucide-react are fine; 🎉 🚀 etc are not)
- ❌ Centered everything — list is left-aligned, wizard heading + body left-aligned
- ❌ Gradient backgrounds anywhere
- ❌ Decorative blobs/wavy SVG dividers

### 7.7 Resume flow (decision D3A)

Closing the wizard mid-flight does **not** delete the connection.

- On modal close (Esc / click outside / Back nav): toast "Connection saved — finish setup from the list" (4s).
- List row for incomplete connection shows its badge (`pending_verification` or `pending_dns`) + secondary "Resume setup" button next to it.
- Click "Resume setup" → re-opens wizard at the correct step (step 2 if pending_verification, step 3 if pending_dns).
- The verify_token persists in DB; we re-display the same TXT value on resume (idempotent).

Error rows: status badge red + "Retry" button. Click retries the poller's current-state action (TXT check, DNS check, or ACME).

### 7.8 TXT verify pattern (decision D2A)

Wizard step 2 polls `POST /api/connections/{id}/probe` every 10s while open. Manual "Verify now" button triggers immediate probe (rate-limited to 1/sec client-side). Auto-transitions to step 3 the moment verify returns success — no click required.

### 7.9 User journey storyboard

```
SCENE 1 — Discovery        [user feels: hopeful]
  Opens Connections page → sees big primary Add button → clicks

SCENE 2 — Domain input     [user feels: focused]
  Wizard step 1 modal slides in → types acme.com → clicks Next
  → button shows "Resolving origin…" 3-5s → success

SCENE 3 — TXT instruction  [user feels: cautious, "did I do it right?"]
  Step 2: clear TXT block, big copy button, "We're checking every 10s" reassurance
  → user copies, switches to DNS provider, pastes, returns
  → wizard auto-advances to step 3 when DNS propagates (no click) [moment of relief]

SCENE 4 — DNS switch       [user feels: official]
  Step 3: "Point A record of acme.com to 93.184.216.34"
  Edge IP highlighted, copy-on-click. Done button closes.

SCENE 5 — Wait             [user feels: trusting]
  Back on list, row shows acme.com with amber "Waiting for DNS" badge.
  "Last checked 12s ago" subline updates.
  User can leave / come back / refresh — state survives.

SCENE 6 — Activation       [user feels: relieved]
  Badge transitions to green "Protected" with ~360ms pulse + ARIA announce.
  Implicit success — no celebration toast, no confetti.

SCENE 7 — Trust (5 years)  [user feels: this product is honest]
  Every status message is literal ("Failed to issue TLS certificate: rate limit hit, retrying in 30m").
  No hype, no marketing. Status text matches reality. Cert renewals happen silently.
```

---

## 8. Migration plan (alembic 0005)

```python
def upgrade():
    # Drop old columns
    op.drop_column('connections', 'source_type')
    op.drop_column('connections', 'nginx_config_path')
    op.drop_column('connections', 'static_dir')
    op.drop_column('connections', 'compose_yaml')
    op.drop_column('connections', 'compose_service')
    op.drop_column('connections', 'compose_port')
    op.drop_column('connections', 'backend_url')
    op.drop_column('connections', 'preserve_host')
    op.drop_column('connections', 'custom_nginx_config')
    op.drop_column('connections', 'ssl_enabled')

    # Rename domains list → single domain (best-effort: take [0])
    op.add_column('connections', sa.Column('domain', sa.String(253)))
    op.execute("UPDATE connections SET domain = (domains->>0)")
    op.drop_column('connections', 'domains')
    op.create_unique_constraint('uq_connections_domain', 'connections', ['domain'])

    # New columns
    op.add_column('connections', sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, server_default='1'))
    op.add_column('connections', sa.Column('origin_hosts', sa.JSON(), nullable=False, server_default='[]'))
    op.add_column('connections', sa.Column('origin_port', sa.Integer(), nullable=False, server_default='443'))
    op.add_column('connections', sa.Column('origin_tls_mode', sa.Enum('strict','lenient'), nullable=False, server_default='strict'))
    op.add_column('connections', sa.Column('verify_token', sa.String(64), nullable=False, server_default=''))
    op.add_column('connections', sa.Column('verified_at', sa.DateTime(timezone=True)))
    op.add_column('connections', sa.Column('status', sa.Enum('pending_verification','pending_dns','provisioning_cert','active','error'), nullable=False, server_default='error'))
    op.add_column('connections', sa.Column('status_detail', sa.Text()))
    op.add_column('connections', sa.Column('acme_retry_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('connections', sa.Column('acme_next_retry_at', sa.DateTime(timezone=True)))
    op.add_column('connections', sa.Column('next_poll_at', sa.DateTime(timezone=True)))
    op.add_column('connections', sa.Column('dns_ttl_seconds', sa.Integer(), nullable=False, server_default='60'))
    op.add_column('connections', sa.Column('last_checked_at', sa.DateTime(timezone=True)))
```

**Existing rows fate.** Stale rows из old modes ставятся в `status='error'`, `status_detail='migrated from legacy mode — please recreate'`. User видит их в UI с красным badge и может удалить. Не пытаемся автоматически переехать (origin неизвестен).

---

## 9. Tests (decision 8A — Pebble for ACME)

### Test compose stack additions

```yaml
# docker-compose.test.yml
services:
  pebble:
    image: ghcr.io/letsencrypt/pebble:latest
    command: ["-config", "/test/config/pebble-config.json", "-strict"]
    ports: ["14000:14000", "15000:15000"]
  ...
```

env: `ACME_DIRECTORY=https://pebble:14000/dir` in test backend.

### Unit tests (`backend/tests/connections/`)

- `test_dns.py` — resolve_a happy/CNAME/NXDOMAIN/timeout/multi-A; is_blocked all RFC1918 ranges; validate_domain edge cases + IDNA
- `test_angie_config.py` — render snapshot tests for pending_dns + active × {h1,h2,h3,all} × tls mode × compression
- `test_acme.py` — schedule_next_retry table check; backoff jitter bounds
- `test_poller.py` — state transitions; semaphore actually bounds concurrency
- `test_service.py` — create happy/dup-409/dns-fail-422/ssrf-422/tls-fail-with-toggle/delete-cleanup

### E2E tests (`e2e/`)

- `connections-dns-proxy.spec.ts` — full happy path: add domain, TXT verify (test DNS server in compose), DNS-flip simulation, wait for active, hit URL, verify WAF rules apply
- `connections-ssrf.spec.ts` — submit domain with A=10.0.0.5 → 422
- `connections-tls-toggle.spec.ts` — origin with self-signed cert + strict → 422; toggle to lenient → 200
- `connections-rollback.spec.ts` — flip DNS away → status returns to pending_dns
- `connections-multi-a.spec.ts` — domain with 2 A records → upstream block has both

### CI

- Existing `e2e.yml` workflow — заменить `test_connection_modes` references на новые spec'ы
- Add pebble service to compose used by e2e job

---

## 10. NOT in scope (deferred)

| Deferred | Why | TODO target |
|---|---|---|
| Origin behind CDN (CNAME chain to Cloudflare/Akamai) | Resolves CDN IP; v1 — known limitation, documented | TODOS.md → "ASN warning for CDN-shadowed origins" |
| IPv6 (AAAA) end-to-end | v1 — IPv4 only; document | TODOS.md → "AAAA support + IPv6 edge" |
| Manual origin override field | User chose "DNS lookup ДО смены" path; manual entry conflicts with goal | None |
| Multi-domain certs (apex + www together) | One conn = one domain in v1 | TODOS.md → "auto-pair apex+www" |
| DNS-01 ACME (for cert with locked-down origin) | HTTP-01 only suffices | TODOS.md → "DNS-01 fallback" |
| Multi-replica backend / distributed poller | Single-replica deploy assumed | TODOS.md → "pg_advisory_lock for multi-replica poller" |
| Origin IP-change detection while active | Can't be detected from domain-DNS in active state | TODOS.md → "secondary `origin_hostname` field for shadow re-resolution" |
| Rate-limit per user on connection creation | Out of scope; add when abuse seen | None |

---

## 11. What already exists (reused)

- `cert_service.trigger_acme_request(id, [domain])` — wrap in `acme.py`, drive HTTP-01
- `cert_service.generate_self_signed_certificate` — fallback (kept inside acme.py)
- `_reload_angie()` — reused as-is
- `$connection_upgrade` map in `angie.conf` — **preserved** (do not touch)
- ModSecurity rules — keep, mounted into Angie
- GeoIP logs / CrowdSec / blocked_ips per-conn pattern — preserved
- Users + RBAC infrastructure — reused for `user_id` FK and `require_role` decorator on endpoints

---

## 12. Failure modes

| Failure | Test? | Handled? | User sees |
|---|---|---|---|
| Origin unreachable at create time | ✅ test_service.py | ✅ 422 | clear "origin unreachable: connection refused" |
| Origin DNS resolves to private IP | ✅ test_dns.py + e2e | ✅ 422 | "domain points to internal address; not allowed" |
| Origin TLS strict-mode fails | ✅ test_service.py + e2e | ✅ 422 + UI toggle | "origin certificate invalid: <reason> — switch to Lenient?" |
| LE rate-limit hit | ❌ hard to test | ✅ backoff defers; status=error after 5 | "TLS provisioning failed: rate limit; retry in <time>" |
| User deletes TXT before verify | ✅ unit | ✅ stays pending_verification | "ownership not yet confirmed" |
| User flips DNS but cert never issues (port 80 blocked) | ✅ e2e with simulated firewall | ✅ status=error after 5 retries | "cert issuance failed: HTTP-01 challenge unreachable" |
| Backend crash mid-ACME | ⚠️ partial coverage | ⚠️ poller picks up on restart by status | resumes naturally |
| **CRITICAL GAP:** thundering herd from poller without semaphore | ✅ test_poller.py asserts Semaphore | ✅ bounded to 20 concurrent | — |

---

## 13. Worktree parallelization

| Step | Modules | Depends on |
|---|---|---|
| 1. Alembic 0005 migration | `backend/alembic/versions/` | — |
| 2. dns.py + tests | `backend/src/connections/dns.py` | 1 |
| 3. angie_config.py + tests | `backend/src/connections/angie_config.py` | 1 |
| 4. acme.py + tests | `backend/src/connections/acme.py` | 1, cert_service |
| 5. poller.py + tests | `backend/src/connections/poller.py` | 2, 3, 4 |
| 6. service.py + router.py | `backend/src/connections/` | 2-5 |
| 7. schemas.py + API client TS types | `backend/src/connections/schemas.py`, `frontend/src/api/client.ts` | 6 |
| 8. UI Connections.tsx rewrite | `frontend/src/pages/Connections.tsx`, locales | 7 |
| 9. e2e specs | `e2e/` | 6, 8 |
| 10. Pebble in docker-compose.test.yml | `docker-compose.test.yml` | — |

**Lanes:**
- Lane A (independent): 1 → 2, 3 (parallel pair) → 4 → 5 → 6 (backend backbone)
- Lane B (independent): 10 (test infra)
- Lane C: 7 → 8 (frontend) — waits on Lane A step 6
- Lane D: 9 (e2e) — waits on Lane A step 6 + Lane C step 8 + Lane B step 10

Recommended execution: Lane A + Lane B in parallel; Lane C after A6; Lane D last.

---

## 14. Implementation Tasks

- [ ] **T1 (P1, human: ~30min / CC: ~5min)** — schema — Alembic 0005 migration
  - Surfaced by: Section 8 (Migration plan)
  - Files: `backend/alembic/versions/0005_connections_domain_only.py`
  - Verify: `alembic upgrade head` + `pytest backend/tests/test_migrations.py`

- [ ] **T2 (P1, human: ~2h / CC: ~15min)** — dns — DNS resolver + SSRF defence + validation
  - Surfaced by: Section 1 issue 3 (SSRF)
  - Files: `backend/src/connections/dns.py`, `backend/tests/connections/test_dns.py`
  - Verify: `pytest backend/tests/connections/test_dns.py -v`

- [ ] **T3 (P1, human: ~3h / CC: ~20min)** — config — Angie config template (pending_dns + active)
  - Surfaced by: Section 6
  - Files: `backend/src/connections/angie_config.py`, snapshot tests
  - Verify: `pytest backend/tests/connections/test_angie_config.py + angie -t` on generated samples

- [ ] **T4 (P1, human: ~2h / CC: ~15min)** — acme — backoff state machine wrapper
  - Surfaced by: Section 1 issue 4
  - Files: `backend/src/connections/acme.py`, tests
  - Verify: `pytest backend/tests/connections/test_acme.py -v`

- [ ] **T5 (P1, human: ~3h / CC: ~20min)** — poller — semaphore-bounded background task with TTL respect
  - Surfaced by: Section 1 issue 4 + Section 4 issue 9
  - Files: `backend/src/connections/poller.py`, tests, `backend/src/main.py` lifespan wiring
  - Verify: `pytest backend/tests/connections/test_poller.py -v`

- [ ] **T6 (P1, human: ~3h / CC: ~25min)** — service+router — CRUD with RBAC, TXT verification, origin probe
  - Surfaced by: Section 4 (Endpoints) + Section 1 issues 1, 5
  - Files: `backend/src/connections/service.py`, `router.py`, `schemas.py`
  - Verify: `pytest backend/tests/connections/test_service.py -v`

- [ ] **T7 (P1, human: ~1h / CC: ~10min)** — delete obsolete code
  - Surfaced by: Step 0 — remove ~1100 LOC of old 4-mode logic
  - Files: trim `service.py`, drop static-upload / nginx-upload / compose endpoints, drop site-templates copy logic, drop nginx-include parser
  - Verify: `ruff check + mypy + pytest backend/`

- [ ] **T8 (P1, human: ~5h / CC: ~40min)** — frontend — Connections.tsx rewrite (3-step wizard + status badges + resume flow)
  - Surfaced by: Section 7 (§7.1–§7.9)
  - Files: `frontend/src/pages/Connections.tsx`, `frontend/src/api/client.ts`, locales (en/ru)
  - Acceptance: matches §7.1 design system bindings; all states in §7.2 implemented; motion per §7.3 with `prefers-reduced-motion` honored; responsive per §7.4 (full-screen sheet <480px); a11y per §7.5 (focus trap, ARIA live region, tab order, 16:1/5.1:1/4.6:1 contrast verified); copy per §7.6 (no AI slop patterns); resume flow per §7.7; auto-poll TXT per §7.8
  - Verify: `pnpm test:components` + Axe scan (0 critical) + Lighthouse a11y ≥95 + manual click-through on Chrome+Safari+mobile-emulated

- [ ] **T9 (P1, human: ~2h / CC: ~15min)** — e2e — Pebble + 5 new specs
  - Surfaced by: Section 9
  - Files: `docker-compose.test.yml`, `e2e/connections-dns-proxy.spec.ts` (+4 others), delete `e2e/connection-modes.spec.ts`
  - Verify: `pnpm e2e`

- [ ] **T10 (P2, human: ~30min / CC: ~5min)** — docs — README + TODOS.md entries for deferred items
  - Surfaced by: Section 10
  - Files: `README.md`, `TODOS.md` (create), `docs/connections.md`
  - Verify: manual read

---

## 15. Open / unresolved

None. All 9 review decisions captured (1B, 2A, 3A, 4A, 5C, 6A, 7A, 8A, 9A).

## Approved Mockups

| Screen | Variant | Wireframe | Direction |
|---|---|---|---|
| Wizard step 1 — Add domain | **A · Inset Modal** | [docs/wireframes/connections-wizard/index.html](../../../docs/wireframes/connections-wizard/index.html) | Centered modal 560px, cream paper + 9px ink offset shadow, sharp corners, dimmed connections-list backdrop behind. Matches §7.1 default tokens. Mobile → full-screen sheet per §7.4. |

The implementer (T8) builds Connections.tsx referencing this wireframe + §7.1–§7.9 specs. Variants B (editorial poster) and C (terminal) are not pursued in v1 — kept in the wireframe file for future redesign reference.

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 0 | — | not run |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | CLEAR (PLAN) | 9 issues, 0 critical gaps |
| Design Review | `/plan-design-review` | UI/UX gaps | 1 | CLEAR (PLAN) | score: 4/10 → 9/10, 2 decisions (D2A auto-poll, D3A save+resume) |
| Outside Voice | `/codex review` | Independent 2nd opinion | 0 | — | skipped |

**UNRESOLVED:** 0
**VERDICT:** ENG + DESIGN CLEARED — ready to implement. T8 acceptance criteria now reference §7.1–§7.9 (token bindings, state matrix, motion, responsive, a11y, copy, resume flow).
