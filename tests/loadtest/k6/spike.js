// Spike: sudden jump from 0 → 1000 VUs to measure how the WAF handles a flood.
// Validates that Angie's listen queue, worker pool, and the ModSecurity hot
// path do not collapse under burst traffic.

import http from "k6/http";
import { check } from "k6";
import { targetUrl, envInt } from "./lib/target.js";

export const options = {
  scenarios: {
    spike: {
      executor: "ramping-arrival-rate",
      startRate: 50,
      timeUnit: "1s",
      preAllocatedVUs: envInt("K6_VUS", 500),
      maxVUs: envInt("K6_MAX_VUS", 1500),
      stages: [
        { duration: "10s", target: 50 },
        { duration: "5s", target: 2000 },   // spike
        { duration: "30s", target: 2000 },  // hold
        { duration: "5s", target: 50 },
      ],
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.10"],         // tolerate 10% drop under sudden flood
    http_req_duration: ["p(95)<3000"],
  },
};

export default function () {
  const res = http.get(targetUrl());
  check(res, { "status<500": (r) => r.status < 500 });
}
