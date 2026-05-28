"""Unit tests for connections.dns — domain validation + SSRF deny-list + resolver.

The resolver tests use real `dns.asyncresolver` patched at the class level so
we don't reach for the network in CI. Validation and is_blocked_ip are pure
helpers and don't need patching.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.connections import dns as conn_dns
from src.connections.dns import DnsResolutionError, is_blocked_ip, validate_domain


@pytest.fixture(autouse=True)
def mock_doh_query():
    with patch.object(conn_dns, "_doh_query", AsyncMock(return_value=None)), \
         patch("httpx.AsyncClient.post", AsyncMock(side_effect=Exception("Blocked in tests"))):
        yield


# ── validate_domain ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("acme.com", "acme.com"),
        ("ACME.com", "acme.com"),
        ("  Acme.com.  ", "acme.com"),
        ("sub.example.org", "sub.example.org"),
        ("a.b.co", "a.b.co"),
    ],
)
def test_validate_domain_accepts_normal(raw, expected):
    assert validate_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "localhost",
        "host.local",
        "server.internal",
        "node.corp",
        "x.lan",
        "a.intranet",
        "h.home",
        "x.test",
        "192.168.1.1",
        "10.0.0.1",
        "::1",
        "1.2.3.4",
        "https://acme.com",
        "acme.com/path",
        "acme.com:8080",
        "*.acme.com",
        "ac me.com",
        "a" * 254,  # exceeds 253 length cap
    ],
)
def test_validate_domain_rejects(raw):
    with pytest.raises(ValueError):
        validate_domain(raw)


def test_validate_domain_idna_unicode():
    # Cyrillic domain → IDNA encoded form. Real-world: домен.рф
    out = validate_domain("xn--d1acufc.xn--p1ai")
    assert out == "xn--d1acufc.xn--p1ai"


# ── is_blocked_ip ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "ip,blocked",
    [
        # Public — allowed
        ("1.1.1.1", False),
        ("8.8.8.8", False),
        ("93.184.216.34", False),  # example.com
        ("2606:4700:4700::1111", False),  # Cloudflare IPv6
        # RFC 1918 — blocked
        ("10.0.0.1", True),
        ("10.255.255.255", True),
        ("172.16.0.5", True),
        ("172.31.255.255", True),
        ("192.168.1.1", True),
        # Loopback
        ("127.0.0.1", True),
        ("127.5.5.5", True),
        ("::1", True),
        # Link-local
        ("169.254.169.254", True),  # AWS IMDS — the canonical SSRF target
        ("fe80::1", True),
        # Reserved / unspecified / multicast
        ("0.0.0.0", True),
        ("224.0.0.1", True),
        ("ff00::1", True),
        # IPv6 ULA
        ("fc00::1", True),
        # Malformed
        ("not-an-ip", True),
        ("", True),
    ],
)
def test_is_blocked_ip(ip, blocked):
    assert is_blocked_ip(ip) is blocked


# ── resolve_a ────────────────────────────────────────────────────────────────


def _fake_a_answer(addresses: list[str], ttl: int = 300):
    """Build a duck-typed dns.resolver.Answer-like object."""
    answer = MagicMock()
    answer.__iter__.return_value = iter([MagicMock(address=a) for a in addresses])
    answer.rrset = MagicMock(ttl=ttl)
    return answer


@pytest.mark.asyncio
async def test_resolve_a_happy():
    with patch.object(conn_dns.dns.asyncresolver, "Resolver") as Resolver:
        Resolver.return_value.resolve = AsyncMock(
            return_value=_fake_a_answer(["1.1.1.1", "1.0.0.1"], ttl=600)
        )
        ips, ttl = await conn_dns.resolve_a("cloudflare.com")
        assert ips == ["1.1.1.1", "1.0.0.1"]
        assert ttl == 600


@pytest.mark.asyncio
async def test_resolve_a_filters_blocked():
    with patch.object(conn_dns.dns.asyncresolver, "Resolver") as Resolver:
        Resolver.return_value.resolve = AsyncMock(
            return_value=_fake_a_answer(["10.0.0.5", "1.1.1.1"], ttl=300)
        )
        ips, ttl = await conn_dns.resolve_a("mixed.example.com")
        assert ips == ["1.1.1.1"]  # private IP stripped
        assert ttl == 300


@pytest.mark.asyncio
async def test_resolve_a_all_blocked_raises():
    with patch.object(conn_dns.dns.asyncresolver, "Resolver") as Resolver:
        Resolver.return_value.resolve = AsyncMock(
            return_value=_fake_a_answer(["10.0.0.5", "169.254.169.254"])
        )
        with pytest.raises(DnsResolutionError, match="private/reserved"):
            await conn_dns.resolve_a("evil.example.com")


@pytest.mark.asyncio
async def test_resolve_a_ttl_floor_30s():
    # Tiny TTLs (e.g. 5s for dynamic GeoDNS) get floored so the poller doesn't
    # busy-loop on records that change faster than we can react.
    with patch.object(conn_dns.dns.asyncresolver, "Resolver") as Resolver:
        Resolver.return_value.resolve = AsyncMock(
            return_value=_fake_a_answer(["1.1.1.1"], ttl=5)
        )
        _, ttl = await conn_dns.resolve_a("fast.example.com")
        assert ttl == 30


@pytest.mark.asyncio
async def test_resolve_a_nxdomain_raises():
    import dns.exception as dns_exc

    with patch.object(conn_dns.dns.asyncresolver, "Resolver") as Resolver:
        Resolver.return_value.resolve = AsyncMock(
            side_effect=dns_exc.DNSException("NXDOMAIN: not found")
        )
        with pytest.raises(DnsResolutionError, match="failed"):
            await conn_dns.resolve_a("does-not-exist.example.test")


# ── verify_txt_token ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_verify_txt_token_match():
    with patch.object(conn_dns, "resolve_txt", new=AsyncMock(return_value=["abc123token", "v=spf1 -all"])):
        assert await conn_dns.verify_txt_token("acme.com", "abc123token") is True


@pytest.mark.asyncio
async def test_verify_txt_token_substring_match():
    # Some DNS providers wrap TXT values in extra quotes or whitespace; we
    # do a substring search, not exact-equal, so common shapes still match.
    with patch.object(conn_dns, "resolve_txt", new=AsyncMock(return_value=['"abc123token"'])):
        assert await conn_dns.verify_txt_token("acme.com", "abc123token") is True


@pytest.mark.asyncio
async def test_verify_txt_token_no_match():
    with patch.object(conn_dns, "resolve_txt", new=AsyncMock(return_value=["other-value"])):
        assert await conn_dns.verify_txt_token("acme.com", "abc123token") is False


@pytest.mark.asyncio
async def test_verify_txt_token_empty_token_rejects():
    assert await conn_dns.verify_txt_token("acme.com", "") is False


# ── resolve_txt & _doh_query_all ─────────────────────────────────────────────


def _fake_txt_message(txt_values: list[str], rcode: int = 0):
    import dns.message
    import dns.rdatatype
    import dns.rrset

    msg = dns.message.Message()
    msg.set_rcode(rcode)
    if txt_values and rcode == 0:
        rr = dns.rrset.from_text("example.com.", 300, "IN", "TXT", *[f'"{v}"' for v in txt_values])
        msg.answer.append(rr)
    return msg


@pytest.mark.asyncio
async def test_doh_query_all_success():
    msg1 = _fake_txt_message(["token123"])
    msg2 = _fake_txt_message([])

    async def mock_single(url, content, headers):
        class FakeResponse:
            status_code = 200
            content = msg1.to_wire() if "dns.google" in url else msg2.to_wire()
            def raise_for_status(self):
                pass
        return FakeResponse()

    with patch("httpx.AsyncClient.post", new=AsyncMock(side_effect=mock_single)):
        res = await conn_dns._doh_query_all("example.com", 16)
        assert len(res) == len(conn_dns._verification_doh_urls())
        # Ensure it successfully returned parsed messages
        rcodes = [r.rcode() for r in res]
        assert all(rc == 0 for rc in rcodes)


@pytest.mark.asyncio
async def test_resolve_txt_parallel_merges_results():
    msg_cached = _fake_txt_message([], rcode=3)  # NXDOMAIN
    msg_fresh = _fake_txt_message(["fresh_token"])

    # Mock authoritative nameservers returning error (refused/timeout)
    with patch.object(conn_dns, "_get_ns_ips", AsyncMock(return_value=[])):
        # Mock _doh_query_all returning both cached NXDOMAIN and fresh record
        mocked_msgs = [msg_cached, msg_fresh, msg_cached, msg_fresh]
        with patch.object(conn_dns, "_doh_query_all", AsyncMock(return_value=mocked_msgs)):
            txt_vals = await conn_dns.resolve_txt("example.com")
            # Should successfully merge and return the fresh token
            assert txt_vals == ["fresh_token"]


@pytest.mark.asyncio
async def test_resolve_a_parallel_merges_results():
    import dns.message
    import dns.rrset

    def _fake_a_message(ips: list[str], rcode: int = 0):
        msg = dns.message.Message()
        msg.set_rcode(rcode)
        if ips and rcode == 0:
            rr = dns.rrset.from_text("example.com.", 300, "IN", "A", *ips)
            msg.answer.append(rr)
        return msg

    msg_cached = _fake_a_message([], rcode=3)  # NXDOMAIN
    msg_fresh = _fake_a_message(["1.1.1.1", "1.0.0.1"])

    mocked_msgs = [msg_cached, msg_fresh, msg_cached, msg_fresh]
    with patch.object(conn_dns, "_doh_query_all", AsyncMock(return_value=mocked_msgs)):
        ips, ttl = await conn_dns.resolve_a("example.com")
        # Should successfully merge, deduplicate, filter, and return the fresh IPs
        assert ips == ["1.1.1.1", "1.0.0.1"]
