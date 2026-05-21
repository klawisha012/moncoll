"""Manifest loader sanity tests.

The generator runs at build time; the loader runs at every startup. If the
loader can't validate the generated file, the catalog endpoint silently
returns empty and the Tests tab looks broken. This locks in the contract.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def test_manifest_json_exists_and_validates():
    """The repo-committed manifest must load via Pydantic without errors."""
    from src.tests.manifest import _MANIFEST_PATH, load_catalog

    assert _MANIFEST_PATH.exists(), (
        f"manifest.json missing — run scripts/generate-tests-manifest.py "
        f"(expected at {_MANIFEST_PATH})"
    )
    catalog = load_catalog(force=True)
    assert len(catalog.tests) > 0, "manifest.json contains zero tests"


def test_manifest_covers_15_families():
    from src.tests.manifest import load_catalog

    catalog = load_catalog(force=True)
    families = {t.family for t in catalog.tests}
    # 15 expected families per the allowlist in manifest.py
    assert len(families) >= 15, (
        f"expected ≥15 families in manifest, got {len(families)}: {sorted(families)}"
    )


def test_every_test_has_unique_id():
    from src.tests.manifest import load_catalog

    catalog = load_catalog(force=True)
    seen: set[str] = set()
    dups: list[str] = []
    for t in catalog.tests:
        if t.id in seen:
            dups.append(t.id)
        seen.add(t.id)
    assert not dups, f"duplicate test ids in manifest: {dups[:10]}"


def test_manifest_path_is_safe_format():
    """No test case should carry a path that escapes the WAF (e.g. absolute URL)."""
    from src.tests.manifest import load_catalog

    catalog = load_catalog(force=True)
    for t in catalog.tests:
        assert t.path.startswith("/"), f"non-relative path in {t.id}: {t.path}"
        assert "://" not in t.path, f"absolute URL in {t.id}: {t.path}"
