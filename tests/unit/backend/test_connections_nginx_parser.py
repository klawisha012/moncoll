"""Regression tests for the nginx_config parser fixes.

The two bugs these tests pin down were both discovered while wiring up the
real-world h5bp example under examples/mode1_h5bp/:

1. ``_extract_nginx_server_blocks`` was comment-blind — a literal ``server {``
   appearing inside a ``# …`` comment line triggered a false-positive block,
   yielding malformed generated configs.

2. ``_resolve_nginx_includes`` resolved nested includes against the *including
   file's* directory, but real nginx resolves them against the nginx prefix
   (one root dir). h5bp's modular partials assume the latter — e.g.
   ``h5bp/basic.conf`` itself contains ``include h5bp/security/foo.conf;``
   expecting the same prefix anchor.
"""

from __future__ import annotations

from pathlib import Path

from backend.src.connections import service as cs


def test_extract_server_blocks_skips_comment_only_match():
    text = """
    # Example: server { proxy_pass http://upstream; }
    server {
        listen 80;
        root /var/www;
    }
    """
    blocks = cs._extract_nginx_server_blocks(text)
    assert len(blocks) == 1
    assert "proxy_pass" not in blocks[0]
    assert "listen 80;" in blocks[0]
    assert "root /var/www;" in blocks[0]


def test_extract_server_blocks_preserves_inline_regex_with_hash(tmp_path):
    # h5bp's security_file_access.conf uses a regex with # in it. The parser
    # must not be confused by `#` inside a location regex.
    text = """
    server {
        listen 80;
        location ~* (?:#.*#|\\.bak)$ {
            deny all;
        }
        root /var/www;
    }
    """
    blocks = cs._extract_nginx_server_blocks(text)
    assert len(blocks) == 1
    body = blocks[0]
    # The full block was extracted (including the regex location + the root).
    assert "deny all;" in body
    assert "root /var/www;" in body


def test_resolve_includes_uses_prefix_for_nested_paths(tmp_path: Path):
    # Reproduce h5bp's layout: top-level nginx.conf and nested partials that
    # `include` siblings via the same prefix-relative path.
    (tmp_path / "h5bp").mkdir()
    (tmp_path / "h5bp" / "security").mkdir()

    (tmp_path / "h5bp" / "security" / "referrer-policy.conf").write_text(
        "add_header Referrer-Policy strict-origin-when-cross-origin always;\n"
    )
    (tmp_path / "h5bp" / "basic.conf").write_text(
        "include h5bp/security/referrer-policy.conf;\n"
    )
    main_conf = tmp_path / "nginx.conf"
    main_conf.write_text(
        """\
server {
    listen 80;
    include h5bp/basic.conf;
}
"""
    )

    expanded = cs._resolve_nginx_includes(main_conf)
    # Both the basic partial AND its nested include should have been expanded.
    assert "Referrer-Policy" in expanded
    # And we should NOT see a doubled `h5bp/h5bp/security/...` path in the
    # expansion markers — that was the pre-fix failure mode.
    assert "h5bp/h5bp/security" not in expanded


def test_resolve_includes_falls_back_to_including_dir(tmp_path: Path):
    # Flat layout where partials live next to nginx.conf and use bare
    # filenames — the old "relative to including file" behavior. This
    # must still work after the prefix-anchored refactor.
    (tmp_path / "snippet.conf").write_text("add_header X-Test on always;\n")
    main_conf = tmp_path / "nginx.conf"
    main_conf.write_text(
        """\
server {
    listen 80;
    include snippet.conf;
}
"""
    )
    expanded = cs._resolve_nginx_includes(main_conf)
    assert "X-Test" in expanded
