"""Top-level pytest config.

Auto-applies layer markers based on directory so individual test files
don't need to repeat `pytestmark = pytest.mark.e2e`:

    tests/unit/...        -> @pytest.mark.unit
    tests/integration/... -> @pytest.mark.integration
    tests/e2e/...         -> @pytest.mark.e2e

Run a specific layer:
    pytest -m unit
    pytest -m e2e
"""

from pathlib import Path


def pytest_configure(config):
    config.addinivalue_line("markers", "unit: unit-level tests (fast, no I/O)")
    config.addinivalue_line(
        "markers", "integration: integration tests (FastAPI + mocked services)"
    )
    config.addinivalue_line("markers", "e2e: end-to-end tests requiring the full stack")


def pytest_collection_modifyitems(config, items):
    tests_root = Path(__file__).parent
    for item in items:
        try:
            rel = Path(item.fspath).relative_to(tests_root)
        except ValueError:
            continue
        layer = rel.parts[0] if rel.parts else None
        if layer in {"unit", "integration", "e2e"}:
            item.add_marker(layer)
