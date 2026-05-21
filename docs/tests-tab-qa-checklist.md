# Tests Tab — QA Checklist

Manual QA after implementation, before merging the Tests tab into main.
Tracks T10 (Dashboard visual regression) and the must-have happy-path
flows from `zwarder-main-eng-review-test-plan-20260521.md`.

## 1. Dashboard visual regression (T10, CRITICAL)

The `<TrafficChart>` component was extracted out of `Dashboard.tsx` into
`frontend/src/components/charts/TrafficChart.tsx`. Required: pixel parity on
the existing Dashboard.

- [ ] Open `/dashboard` in the **production build** of the previous commit
      (e.g. `git stash && npm run build && open dist/`) — take a screenshot
      of the "Traffic Overview (Clean vs Malicious)" panel.
- [ ] Switch back (`git stash pop`), rebuild, screenshot the same panel.
- [ ] Diff side-by-side. Acceptance: no visible difference in bar geometry,
      colors, hover crosshair, legend position, or tooltip rendering.
- [ ] Hover an arbitrary bar: tooltip appears in the **same place** (no
      "flip-left" trigger difference at chart edges).
- [ ] Resize the window to mobile width: chart still scales (preserved by
      viewBox + percentage width).

If diff is visible: roll back chart-utils.tsx / TrafficChart.tsx, debug.

## 2. Tests page — happy paths

### Catalog renders
- [ ] Sign in as `admin`, navigate to `/tests`.
- [ ] Sidebar shows "Tests" entry under the Security section with a
      TestTube icon.
- [ ] Catalog loads with ≥10 tests grouped by family (XSS, SQLi, RCE, …).
      Total ≈ 246 tests across 15 families.

### Run an XSS test (CRITICAL happy path)
- [ ] Pick XSS-941100 from the catalog.
- [ ] Click Run. Within 5 s a result chip appears.
- [ ] Acceptable outcomes:
  - `Blocked` (most likely on a fresh stack with default CRS).
  - `Fired, not blocked` (paranoia-level config).
  - `Passed` if ModSec engine is in `DetectionOnly` or `Off`.
- [ ] Live impact chart shows an amber marker overlay on the most recent
      bar within ~10 s.
- [ ] "Triggered rules" table lists at least one row with the matching
      `941xxx` rule id.

### Run a SQLi test
- [ ] Pick SQLi-942100. Same checks as above — different rule family.
- [ ] Result chip color matches status (red = blocked, amber = fired-not-
      blocked, green = passed, grey = timeout).

### Connection picker behaviour
- [ ] If at least one enabled connection exists, the dropdown defaults to
      it. Pick a different connection → next Run goes there (verify via the
      `target_url` line on the result panel and via the host's access log).
- [ ] If zero connections exist, dropdown shows only
      "localhost (default vhost)". A test still runs against Angie.

### Rate limit
- [ ] Click Run twice within one second on different tests. The second
      click is blocked client-side (button disabled while polling). If you
      send two POST /api/tests/run from devtools within <1 s for the same
      admin user, the second returns 429 with `tests.rateLimit` message.

### Auth
- [ ] Sign in as `viewer`. Sidebar does NOT show "Tests". Navigating
      directly to `/tests` redirects via `AdminOnly` guard.
- [ ] Logged-out browser: `/tests` redirects to `/login`.

## 3. CrowdSec subcatalog

- [ ] Switch to the "CrowdSec" sub-tab.
- [ ] Three scenarios render: `http-probing`, `http-crawl-non_statics`,
      `http-bad-user-agent`.
- [ ] Click Run on `http-probing`. Within ~5 s a result panel appears
      showing `bursts_sent=8` and `decisions_after` count.
- [ ] Cross-check the CrowdSec tab — any newly listed decision attributed
      to `crowdsecurity/http-probing` from the backend container's IP.
- [ ] Documented limitation: parallel CrowdSec tests with the same
      scenario can't be disambiguated. UI serializes runs (Run buttons
      disabled while one is in flight).

## 4. Pytest regression

The existing pytest e2e suite must still pass end-to-end (the manifest
loader does NOT replace the pytest files; it parses them at build time):

```
pytest tests/e2e/modsecurity/test_xss_941.py
```

- [ ] Suite passes without modification.

## 5. Security

- [ ] `GET /api/dashboard/test-traffic/<not-a-uuid>` → 400 with
      `marker must be a UUID4`.
- [ ] `GET /api/dashboard/test-traffic/<uuid>%0A;%20DROP%20TABLE` → 400 (the
      `\Z` regex anchor blocks the trailing newline injection).
- [ ] `GET /api/tests/catalog` without admin session → 401 / 403.

## 6. i18n

- [ ] Switch language to RU via the settings popover. The Tests page UI
      strings switch language (catalog labels, status chips, warning
      banner, table headers).

---

Sign-off (initials + date when each section passes):

- §1 Dashboard regression: ____
- §2 Tests happy paths:    ____
- §3 CrowdSec subcatalog:  ____
- §4 Pytest regression:    ____
- §5 Security:             ____
- §6 i18n:                 ____
