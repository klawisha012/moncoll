"""AST guard: verify that every select() on tenant-scoped models in the
service layer carries a `tenant_id` filter.

If a developer adds or modifies a service function that selects from a
tenant-scoped model without filtering by tenant_id, this test will fail.

Design:
- Parse every .py file under SERVICE_DIRS with ast.
- Walk the AST looking for `select(Model)` calls where Model is in
  TENANT_SCOPED_MODELS.
- For each such call, assert that somewhere in the enclosing statement
  (or chained .where() calls) the text `tenant_id` appears.

The check is intentionally text-based (looks at the source of the
containing statement) for simplicity. It catches the overwhelming
majority of mis-scoped queries without requiring full dataflow analysis.
"""

import ast
import textwrap
from pathlib import Path

import pytest

# ── configuration ─────────────────────────────────────────────────────────────

# Models that MUST be filtered by tenant_id in every user-facing select().
TENANT_SCOPED_MODELS: set[str] = {"Connection"}

# Service directories to audit (relative to repo root).
SERVICE_DIRS: list[str] = ["connections"]

# Repo root = four levels up from this file (tests/unit/backend/<file>)
REPO_ROOT = Path(__file__).resolve().parents[3]
BACKEND_SRC = REPO_ROOT / "backend" / "src"

# Functions explicitly exempted because they are platform-internal /
# cross-tenant by design. Format: "<module_stem>.<func_name>".
CROSS_TENANT_EXEMPTIONS: set[str] = {
    # Platform-level bulk config regeneration — admin-only, not user-facing.
    "service.reload_connections_config",
    # Background ACME/DNS poller — operates across all tenants on every tick.
    # This scope is platform-internal, not user-facing.
    "poller._select_due_rows",
}


# ── helpers ───────────────────────────────────────────────────────────────────


def _source_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def _enclosing_statement_src(lines: list[str], node: ast.AST) -> str:
    """Return the source text of the statement that contains `node`.

    We walk upward from `node.lineno` collecting the lines of the statement.
    For multiline statements we include lines until the next statement starts
    (heuristic: stop when a non-continuation line at the same or lower indent
    level appears after the first line).
    """
    start = node.lineno - 1  # 0-indexed
    # Grab a generous window; the where() chain won't be longer than 30 lines.
    window = lines[start : start + 30]
    return "\n".join(window)


def _find_unscoped_selects(path: Path) -> list[str]:
    """Return a list of human-readable violation messages for `path`."""
    src = path.read_text(encoding="utf-8")
    lines = src.splitlines()
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError as exc:
        return [f"SyntaxError: {exc}"]

    module_stem = path.stem  # e.g. "service"
    violations: list[str] = []

    for node in ast.walk(tree):
        # Look for Call nodes: select(SomeModel)
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # select(...) — bare name
        if isinstance(func, ast.Name) and func.id == "select":
            pass
        # Could be sqlalchemy.select(...) — attribute access
        elif isinstance(func, ast.Attribute) and func.attr == "select":
            pass
        else:
            continue

        # Does any argument name match a scoped model?
        for arg in node.args:
            model_name: str | None = None
            if isinstance(arg, ast.Name):
                model_name = arg.id
            elif isinstance(arg, ast.Attribute):
                model_name = arg.attr
            if model_name not in TENANT_SCOPED_MODELS:
                continue

            # Determine enclosing function name for exemption check.
            # Walk parents (Python 3.8+: use ast.walk on the tree and match
            # by lineno range — simpler: scan the function defs in the module).
            enclosing_func = _find_enclosing_function(tree, node.lineno)
            exemption_key = f"{module_stem}.{enclosing_func}"
            if exemption_key in CROSS_TENANT_EXEMPTIONS:
                continue

            # Check that the containing statement references tenant_id.
            stmt_src = _enclosing_statement_src(lines, node)
            if "tenant_id" not in stmt_src:
                violations.append(
                    f"{path.relative_to(REPO_ROOT)}:{node.lineno} — "
                    f"select({model_name}) in `{enclosing_func}` "
                    f"has no tenant_id filter"
                )

    return violations


def _find_enclosing_function(tree: ast.Module, lineno: int) -> str:
    """Return the name of the innermost function/method containing `lineno`."""
    best: str = "<module>"
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", node.lineno)
            if node.lineno <= lineno <= end:
                best = node.name
    return best


# ── test ──────────────────────────────────────────────────────────────────────


def collect_service_files() -> list[Path]:
    files: list[Path] = []
    for svc_dir in SERVICE_DIRS:
        svc_path = BACKEND_SRC / svc_dir
        if svc_path.is_dir():
            files.extend(svc_path.glob("**/*.py"))
    return files


def test_all_scoped_selects_have_tenant_filter():
    """Every select(Connection) in service dirs must filter by tenant_id."""
    service_files = collect_service_files()
    assert service_files, f"No .py files found under {SERVICE_DIRS} in {BACKEND_SRC}"

    all_violations: list[str] = []
    for path in service_files:
        all_violations.extend(_find_unscoped_selects(path))

    if all_violations:
        report = "\n".join(all_violations)
        pytest.fail(
            f"Found {len(all_violations)} unscoped select(s) on tenant-scoped models:\n"
            + textwrap.indent(report, "  ")
        )
