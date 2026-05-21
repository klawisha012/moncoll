#!/usr/bin/env python3
"""Generate ``backend/src/tests/manifest.json`` from the pytest e2e allowlist.

The generator parses each whitelisted ``tests/e2e/modsecurity/test_*.py`` file
by ast-importing it, then reads the named attribute (``xss_payloads``,
``lfi_test_cases``, …). The shape (dict vs list) decides how each entry is
unpacked into a ``TestCase``.

Run from the repo root:

    python scripts/generate-tests-manifest.py

Or from anywhere — it resolves paths relative to its own location.
"""

from __future__ import annotations

import datetime as _dt
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = ROOT / "tests" / "e2e" / "modsecurity"
OUTPUT = ROOT / "backend" / "src" / "tests" / "manifest.json"

# Mirror of backend/src/tests/manifest.py::MANIFEST_SOURCES so the generator
# can run standalone (no need to put the backend on sys.path).
SOURCES: list[tuple[str, str, str, str]] = [
    ("xss", "test_xss_941.py", "xss_payloads", "dict"),
    ("sqli", "test_sqli_942.py", "sqli_payloads", "dict"),
    ("rce", "test_rce_932.py", "rce_payloads", "dict"),
    ("rfi", "test_rfi_931.py", "rfi_payloads", "dict"),
    ("scanner", "test_scanner_913.py", "scanner_payloads", "dict"),
    ("java", "test_java_944.py", "java_payloads", "dict"),
    ("php", "test_php_933.py", "php_payloads", "dict"),
    ("session_fixation", "test_session_fixation_943.py", "session_fixation_payloads", "dict"),
    ("multipart", "test_multipart_922.py", "multipart_payloads", "dict"),
    ("method", "test_method_911.py", "method_payloads", "dict"),
    ("protocol_attack", "test_protocol_attack_921.py", "protocol_payloads", "dict"),
    ("protocol_enforce", "test_protocol_enforcement_920.py", "protocol_payloads", "dict"),
    ("generic", "test_generic_934.py", "generic_payloads", "dict"),
    ("blocking", "test_blocking_949.py", "blocking_payloads", "dict"),
    ("lfi", "test_lfi_930.py", "lfi_test_cases", "list"),
]

DESCRIPTIONS: dict[str, str] = {
    "xss": "Cross-Site Scripting (OWASP CRS 941)",
    "sqli": "SQL Injection (OWASP CRS 942)",
    "rce": "Remote Command Execution (OWASP CRS 932)",
    "rfi": "Remote File Inclusion (OWASP CRS 931)",
    "scanner": "Vulnerability Scanner (OWASP CRS 913)",
    "java": "Java attacks (OWASP CRS 944)",
    "php": "PHP attacks (OWASP CRS 933)",
    "session_fixation": "Session Fixation (OWASP CRS 943)",
    "multipart": "Multipart Anomalies (OWASP CRS 922)",
    "method": "HTTP Method enforcement (OWASP CRS 911)",
    "protocol_attack": "Protocol Attack (OWASP CRS 921)",
    "protocol_enforce": "Protocol Enforcement (OWASP CRS 920)",
    "generic": "Generic Anomalies (OWASP CRS 934)",
    "blocking": "Blocking Evaluation (OWASP CRS 949)",
    "lfi": "Local File Inclusion (OWASP CRS 930)",
}


def _import_payload_module(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(f"_payloads_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"can't load {path}")
    mod = importlib.util.module_from_spec(spec)
    # Suppress pytest fixture decorators noise — they're harmless to evaluate.
    spec.loader.exec_module(mod)
    return mod


def _coerce_dict_payload(family: str, rule_id: str, payload: Any) -> dict[str, Any]:
    """Turn a {rule_id: payload_string} entry into a TestCase dict."""
    if not isinstance(payload, str):
        payload = str(payload)
    return {
        "id": f"{family}.{rule_id}",
        "family": family,
        "rule_id": str(rule_id),
        "description": f"{DESCRIPTIONS.get(family, family)} — rule {rule_id}",
        "method": "GET",
        "path": "/",
        "query": {"param": payload},
        "headers": {},
        "body": None,
    }


def _coerce_list_payload(family: str, item: dict[str, Any]) -> dict[str, Any]:
    """Turn a list-style test case dict into a TestCase dict."""
    rule_id = str(item.get("rule_id", ""))
    url = str(item.get("url", "http://localhost/"))
    # Strip the scheme + host — we only care about the path inside the request.
    path = "/"
    if "://" in url:
        _, _, rest = url.partition("://")
        _, _, path_with_qs = rest.partition("/")
        path = "/" + path_with_qs.split("?", 1)[0]
    elif url.startswith("/"):
        path = url

    params = item.get("params") or {}
    headers = item.get("headers") or {}
    return {
        "id": f"{family}.{rule_id}",
        "family": family,
        "rule_id": rule_id,
        "description": f"{DESCRIPTIONS.get(family, family)} — rule {rule_id}",
        "method": "GET",
        "path": path,
        "query": {str(k): str(v) for k, v in params.items()},
        "headers": {str(k): str(v) for k, v in headers.items()},
        "body": None,
    }


def main() -> int:
    if not TESTS_DIR.is_dir():
        print(f"error: tests dir not found: {TESTS_DIR}", file=sys.stderr)
        return 2

    cases: list[dict[str, Any]] = []
    missing: list[str] = []

    for family, filename, attr, schema in SOURCES:
        path = TESTS_DIR / filename
        if not path.exists():
            missing.append(filename)
            continue
        try:
            mod = _import_payload_module(path)
        except Exception as exc:
            print(f"warning: failed to import {filename}: {exc}", file=sys.stderr)
            continue
        raw = getattr(mod, attr, None)
        if raw is None:
            print(f"warning: {filename} missing attribute {attr!r}", file=sys.stderr)
            continue

        if schema == "dict":
            if not isinstance(raw, dict):
                print(f"warning: {filename}.{attr} expected dict, got {type(raw).__name__}", file=sys.stderr)
                continue
            for rule_id, payload in raw.items():
                cases.append(_coerce_dict_payload(family, str(rule_id), payload))
        elif schema == "list":
            if not isinstance(raw, list):
                print(f"warning: {filename}.{attr} expected list, got {type(raw).__name__}", file=sys.stderr)
                continue
            for item in raw:
                if not isinstance(item, dict):
                    continue
                cases.append(_coerce_list_payload(family, item))
        else:
            print(f"warning: unknown schema {schema!r} for {filename}", file=sys.stderr)

    catalog = {
        "tests": cases,
        "generated_at": _dt.datetime.now(_dt.UTC).isoformat(),
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(catalog, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"wrote {OUTPUT.relative_to(ROOT)} — {len(cases)} test cases across {len(SOURCES)} families")
    if missing:
        print(f"missing pytest files (skipped): {', '.join(missing)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
