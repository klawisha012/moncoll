// Baseline: ramp to a sustainable steady-state to surface true RPS / p95.
//
// Stages: 30s ramp → 60s hold @200 VUs → 30s ramp down.
// Use this as the reference run when tuning Angie / ModSecurity.

import http from "k6/http";
import { check } from "k6";
import { targetUrl, envInt } from "./lib/target.js";

export const options = {
  scenarios: {
    baseline: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "30s", target: envInt("K6_VUS", 200) },
        { duration: "60s", target: envInt("K6_VUS", 200) },
        { duration: "30s", target: 0 },
      ],
      gracefulRampDown: "10s",
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.02"],
    http_req_duration: ["p(95)<800", "p(99)<2000"],
  },
};

export default function () {
  const res = http.get(targetUrl());
  check(res, {
    "status<500": (r) => r.status < 500,
  });
}
