// Shared target-URL builder for every k6 scenario.
//
// Reads TARGET_SCHEME / TARGET_HOST / TARGET_PORT / TARGET_PATH from the
// environment so each script just composes scenarios + thresholds and lets
// the harness decide where to point.

export function targetUrl(path) {
  const scheme = __ENV.TARGET_SCHEME || "http";
  const host = __ENV.TARGET_HOST || "angie";
  const port = __ENV.TARGET_PORT || (scheme === "https" ? "443" : "80");
  const p = path || __ENV.TARGET_PATH || "/";
  // Omit default ports (cleaner k6 metrics tags).
  const portSuffix =
    (scheme === "http" && port === "80") ||
    (scheme === "https" && port === "443")
      ? ""
      : `:${port}`;
  return `${scheme}://${host}${portSuffix}${p}`;
}

export function envInt(name, fallback) {
  const raw = __ENV[name];
  if (!raw) return fallback;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) ? n : fallback;
}

export function envStr(name, fallback) {
  return __ENV[name] || fallback;
}
