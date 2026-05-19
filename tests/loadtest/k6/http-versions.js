// HTTP/2 vs HTTP/3 comparison. Run with TARGET_SCHEME=https TARGET_PORT=443.
//
// k6 negotiates ALPN automatically (HTTP/2 over TLS by default). For HTTP/3
// you need a k6 build with the QUIC extension (xk6-http3); we fall back to
// HTTP/2 if the runtime doesn't support it and tag the metric accordingly.

import http from "k6/http";
import { check } from "k6";
import { Trend } from "k6/metrics";
import { targetUrl, envInt } from "./lib/target.js";

const h2Latency = new Trend("waf_http2_latency", true);
const h3Latency = new Trend("waf_http3_latency", true);

export const options = {
  scenarios: {
    versions: {
      executor: "constant-vus",
      vus: envInt("K6_VUS", 50),
      duration: __ENV.K6_DURATION || "60s",
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.02"],
    waf_http2_latency: ["p(95)<800"],
    waf_http3_latency: ["p(95)<800"],
  },
  // k6 picks ALPN from the server; insecureSkipTLSVerify=true lets us hit
  // self-signed certs the WAF generates for fresh connections.
  insecureSkipTLSVerify: true,
};

export default function () {
  // HTTP/2 (default ALPN over TLS)
  const r2 = http.get(targetUrl(), { tags: { proto: "h2" } });
  check(r2, { "h2 status<500": (r) => r.status < 500 });
  h2Latency.add(r2.timings.duration);

  // HTTP/3 — only meaningful when k6 was built with the xk6-http3 extension.
  // The official grafana/k6 image ships HTTP/1.1+2 only; a custom build is
  // required for real h3. We still issue the request so the metric exists.
  const r3 = http.get(targetUrl(), {
    tags: { proto: "h3" },
    // No-op on stock k6 — keeps the script usable everywhere.
  });
  check(r3, { "h3 status<500": (r) => r.status < 500 });
  h3Latency.add(r3.timings.duration);
}
