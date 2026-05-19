// Smoke: quick sanity check — 10 VUs for 10 seconds.
// Wired into CI to catch regressions ("does Angie still serve at all?")
// without paying a long load test on every PR.

import http from "k6/http";
import { check, sleep } from "k6";
import { targetUrl } from "./lib/target.js";

export const options = {
  vus: 10,
  duration: "10s",
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<500"],
    iterations: ["count>100"],
  },
};

export default function () {
  const res = http.get(targetUrl());
  check(res, {
    "status 2xx/3xx": (r) => r.status >= 200 && r.status < 400,
  });
  sleep(0.1);
}
