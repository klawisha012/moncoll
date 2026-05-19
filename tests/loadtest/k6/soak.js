// Soak: 20-minute steady load to surface memory leaks / FD leaks / cache rot.
// Run before deploys when changing anything in the request hot path.

import http from "k6/http";
import { check } from "k6";
import { targetUrl, envInt } from "./lib/target.js";

export const options = {
  scenarios: {
    soak: {
      executor: "constant-vus",
      vus: envInt("K6_VUS", 100),
      duration: __ENV.K6_DURATION || "20m",
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<1000"],
  },
};

export default function () {
  const res = http.get(targetUrl());
  check(res, { "status<500": (r) => r.status < 500 });
}
