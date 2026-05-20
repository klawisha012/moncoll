"""Tests for the static-site directory upload + broadened static try_files.

Covers the routes fix shipped 2026-05-20: ``static_generate`` connections
must accept a *directory* upload (so blog/about subroutes work for Astro/Vite
builds), and the generated Angie ``try_files`` chain must handle both
directory-format and file-format static site generators.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.connections import service as cs


# ── save_uploaded_static_dir ────────────────────────────────────


def test_save_uploaded_static_dir_preserves_subdirs(tmp_path, monkeypatch):
    monkeypatch.setattr(cs, "UPLOADS_DIR", tmp_path)

    files = [
        ("index.html", b"<html>root</html>"),
        ("blog/index.html", b"<html>blog</html>"),
        ("blog/first-post/index.html", b"<html>first</html>"),
        ("about/index.html", b"<html>about</html>"),
        ("_astro/style.css", b"body{}"),
    ]
    result = cs.save_uploaded_static_dir(files)

    assert result["path"].startswith("uploads/static_")
    assert result["filename"] == result["path"].removeprefix("uploads/")
    target = tmp_path / result["filename"]
    assert (target / "index.html").read_bytes() == b"<html>root</html>"
    assert (target / "blog" / "index.html").read_bytes() == b"<html>blog</html>"
    assert (
        target / "blog" / "first-post" / "index.html"
    ).read_bytes() == b"<html>first</html>"
    assert (target / "about" / "index.html").read_bytes() == b"<html>about</html>"
    assert (target / "_astro" / "style.css").read_bytes() == b"body{}"


def test_save_uploaded_static_dir_rejects_empty():
    with pytest.raises(ValueError):
        cs.save_uploaded_static_dir([])


def test_save_uploaded_static_dir_skips_macosx_and_dot_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(cs, "UPLOADS_DIR", tmp_path)

    files = [
        ("index.html", b"<html></html>"),
        ("__MACOSX/._index.html", b"junk"),
        (".DS_Store", b"junk"),
    ]
    result = cs.save_uploaded_static_dir(files)
    target = tmp_path / result["filename"]
    assert (target / "index.html").exists()
    assert not (target / "__MACOSX").exists()
    assert not (target / ".DS_Store").exists()


def test_save_uploaded_static_dir_blocks_path_traversal(tmp_path, monkeypatch):
    monkeypatch.setattr(cs, "UPLOADS_DIR", tmp_path)

    files = [
        ("../escape.html", b"nope"),
        ("good.html", b"<html></html>"),
    ]
    result = cs.save_uploaded_static_dir(files)
    target = tmp_path / result["filename"]
    # ``..`` segments are stripped, so ``../escape.html`` collapses to ``escape.html``
    # written *inside* the upload dir — never above it.
    assert (target / "escape.html").exists() or (target / "good.html").exists()
    assert not (tmp_path / "escape.html").exists()


def test_save_uploaded_static_dir_all_skipped_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(cs, "UPLOADS_DIR", tmp_path)
    with pytest.raises(ValueError):
        cs.save_uploaded_static_dir(
            [
                ("__MACOSX/foo", b"junk"),
                (".DS_Store", b"junk"),
            ]
        )


# ── _emit_static_body try_files chain ───────────────────────────


def test_emit_static_body_includes_html_and_dir_fallbacks():
    body = cs._emit_static_body(42)
    joined = "\n".join(body)
    # Root and index unchanged
    assert "root /etc/angie/http.d/conn_42/site;" in joined
    assert "index index.html index.htm;" in joined
    # Broadened fallback chain handles both file-format and directory-format SSGs
    assert "try_files $uri $uri.html $uri/ =404;" in joined


# ── _smart_flatten_site_dir ─────────────────────────────────────


def test_smart_flatten_hoists_dist_wrapper(tmp_path):
    site = tmp_path / "site"
    (site / "dist" / "blog").mkdir(parents=True)
    (site / "dist" / "index.html").write_text("<root>")
    (site / "dist" / "blog" / "index.html").write_text("<blog>")

    cs._smart_flatten_site_dir(site)

    assert (site / "index.html").read_text() == "<root>"
    assert (site / "blog" / "index.html").read_text() == "<blog>"
    assert not (site / "dist").exists()


def test_smart_flatten_no_op_when_flat_layout(tmp_path):
    site = tmp_path / "site"
    site.mkdir()
    (site / "index.html").write_text("<root>")
    (site / "blog").mkdir()
    (site / "blog" / "index.html").write_text("<blog>")

    cs._smart_flatten_site_dir(site)

    assert (site / "index.html").read_text() == "<root>"
    assert (site / "blog" / "index.html").read_text() == "<blog>"


def test_smart_flatten_no_op_for_unknown_wrapper(tmp_path):
    site = tmp_path / "site"
    (site / "mything").mkdir(parents=True)
    (site / "mything" / "index.html").write_text("<root>")

    cs._smart_flatten_site_dir(site)

    # ``mything`` isn't in the recognized SSG wrappers — leave it alone.
    assert (site / "mything" / "index.html").exists()
    assert not (site / "index.html").exists()


def test_smart_flatten_no_op_when_wrapper_has_no_index(tmp_path):
    site = tmp_path / "site"
    (site / "dist").mkdir(parents=True)
    (site / "dist" / "style.css").write_text("body{}")

    cs._smart_flatten_site_dir(site)

    # No index.html inside the wrapper — don't reshape; the user may have
    # uploaded an assets-only sub-package.
    assert (site / "dist" / "style.css").exists()
    assert not (site / "style.css").exists()


def test_smart_flatten_ignores_hidden_siblings(tmp_path):
    # A `.DS_Store` or `.git` next to `dist/` should not block the hoist.
    site = tmp_path / "site"
    (site / "dist").mkdir(parents=True)
    (site / "dist" / "index.html").write_text("<root>")
    (site / ".DS_Store").write_text("junk")

    cs._smart_flatten_site_dir(site)

    assert (site / "index.html").exists()
    assert (site / ".DS_Store").exists()  # hidden sibling preserved


# ── write_static_dir_to_conn ────────────────────────────────────


def test_write_static_dir_to_conn_lands_directly_in_site(tmp_path, monkeypatch):
    monkeypatch.setattr(cs, "CONNECTIONS_D_DIR", tmp_path)
    monkeypatch.setattr(cs, "_reload_angie", lambda: None)

    files = [
        ("index.html", b"<root>"),
        ("blog/index.html", b"<blog>"),
        ("about/index.html", b"<about>"),
        ("_astro/style.css", b"body{}"),
    ]
    result = cs.write_static_dir_to_conn(99, files)

    site = tmp_path / "conn_99" / "site"
    assert result["files"] == 4
    assert result["path"] == str(site)
    assert (site / "index.html").read_bytes() == b"<root>"
    assert (site / "blog" / "index.html").read_bytes() == b"<blog>"
    assert (site / "about" / "index.html").read_bytes() == b"<about>"
    assert (site / "_astro" / "style.css").read_bytes() == b"body{}"


def test_write_static_dir_to_conn_smart_flattens_dist_wrapper(tmp_path, monkeypatch):
    monkeypatch.setattr(cs, "CONNECTIONS_D_DIR", tmp_path)
    monkeypatch.setattr(cs, "_reload_angie", lambda: None)

    files = [
        ("dist/index.html", b"<root>"),
        ("dist/blog/index.html", b"<blog>"),
    ]
    cs.write_static_dir_to_conn(100, files)

    site = tmp_path / "conn_100" / "site"
    assert (site / "index.html").read_bytes() == b"<root>"
    assert (site / "blog" / "index.html").read_bytes() == b"<blog>"
    assert not (site / "dist").exists()


def test_write_static_dir_to_conn_replaces_existing_content(tmp_path, monkeypatch):
    monkeypatch.setattr(cs, "CONNECTIONS_D_DIR", tmp_path)
    monkeypatch.setattr(cs, "_reload_angie", lambda: None)

    site = tmp_path / "conn_101" / "site"
    site.mkdir(parents=True)
    (site / "stale.html").write_text("OLD")

    cs.write_static_dir_to_conn(101, [("index.html", b"NEW")])

    assert (site / "index.html").read_bytes() == b"NEW"
    # Stale files from a previous build must not survive the upload.
    assert not (site / "stale.html").exists()


def test_write_static_dir_to_conn_rejects_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(cs, "CONNECTIONS_D_DIR", tmp_path)
    monkeypatch.setattr(cs, "_reload_angie", lambda: None)
    with pytest.raises(ValueError):
        cs.write_static_dir_to_conn(102, [])


def test_generate_config_static_emits_broadened_try_files():
    conn = {
        "id": 7,
        "name": "astro-site",
        "domains": ["example.com"],
        "source_type": "static_generate",
        "ssl_cert_path": None,
        "ssl_key_path": None,
        "http_versions": "h1,h2",
        "compression_algo": "auto",
    }
    config = cs._generate_nginx_config(conn)
    assert "try_files $uri $uri.html $uri/ =404;" in config
