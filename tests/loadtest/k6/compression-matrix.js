// Compression matrix: drive the same target with each encoder so we can see
// the real bytes-on-wire delta and the CPU cost of compression in flight.
//
// k6 reports each variant as a tagged metric so the summary breaks down by
// `encoding`. The actual encoder is selected by the request's Accept-Encoding
// header — Angie negotiates per `map $http_accept_encoding $waf_pref_encoding`.

import http from "k6/http";
import { check, group } from "k6";
import { Trend, Counter } from "k6/metrics";
import { targetUrl, envInt } from "./lib/target.js";

const ENCODINGS = ["zstd", "br", "gzip", "identity"];

const respBytes = new Trend("waf_resp_bytes", true);
const respCount = new Counter("waf_resp_count");

export const options = {
  scenarios: {
    matrix: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "20s", target: envInt("K6_VUS", 100) },
        { duration: "60s", target: envInt("K6_VUS", 100) },
        { duration: "10s", target: 0 },
      ],
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.02"],
    "http_req_duration{encoding:zstd}":     ["p(95)<800"],
    "http_req_duration{encoding:br}":       ["p(95)<800"],
    "http_req_duration{encoding:gzip}":     ["p(95)<800"],
    "http_req_duration{encoding:identity}": ["p(95)<800"],
  },
};

export default function () {
  for (const enc of ENCODINGS) {
    group(`encoding=${enc}`, function () {
      const res = http.get(targetUrl(), {
        headers: { "Accept-Encoding": enc },
        tags: { encoding: enc },
        // k6 will auto-decompress by default; turn it off so the wire size we
        // see is the actual compressed payload.
        responseType: "text",
        compression: "",
      });
      check(res, { "status<500": (r) => r.status < 500 });
      respBytes.add(res.body ? res.body.length : 0, { encoding: enc });
      respCount.add(1, { encoding: enc });
    });
  }
}
