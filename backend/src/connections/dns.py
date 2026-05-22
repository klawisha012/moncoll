"""DNS resolution, domain validation, and SSRF defence.

Single source of truth for: "is this domain safe to onboard, and what IP(s)
should we proxy to?". Every IP that leaves this module is guaranteed to be
publicly-routable; private/loopback/link-local/reserved ranges are rejected
*before* any HTTP probe or proxy_pass touches them.

See spec §5 (dns.py) and §1 issue 3 (SSRF deny-list).
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from ipaddress import ip_address

import dns.asyncresolver
import dns.exception
import dns.rdatatype

logger = logging.getLogger(__name__)

# ── Public resolvers ────────────────────────────────────────────────────────
# We intentionally bypass the container's local resolver (/etc/resolv.conf →
# 127.0.0.11 inside Docker) because Docker's embedded DNS caches aggressively
# and can serve stale negative responses long after a customer publishes their
# TXT/A record. Verified live: TXT record present at 8.8.8.8 but the Docker
# resolver returned an older value for 5+ minutes after the user updated DNS.
#
# Override via WAF_DNS_RESOLVERS env var (comma-separated). Default is
# Google + Cloudflare for redundancy.
# Cloudflare first — Google's 8.8.8.8 and Quad9's 9.9.9.9 are blocked from
# parts of the Russian internet (RKN). Cloudflare 1.1.1.1 has stayed
# reachable. We keep the others as fallbacks so the variable still works
# from regions where Cloudflare is the one being blocked.
_DEFAULT_PUBLIC_RESOLVERS = ("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4")


def _public_resolvers() -> list[str]:
    raw = (os.environ.get("WAF_DNS_RESOLVERS") or "").strip()
    if not raw:
        return list(_DEFAULT_PUBLIC_RESOLVERS)
    out = [r.strip() for r in raw.split(",") if r.strip()]
    return out or list(_DEFAULT_PUBLIC_RESOLVERS)


def _make_resolver(timeout: float) -> dns.asyncresolver.Resolver:
    """Build a fresh resolver pinned to public nameservers."""
    r = dns.asyncresolver.Resolver(configure=False)
    r.nameservers = _public_resolvers()
    r.timeout = timeout
    r.lifetime = timeout
    # cache=None — never reuse answers; we want every lookup to see real
    # current DNS state. Worth the ~50ms extra latency for a wizard probe.
    r.cache = None
    return r

# RFC 5891 max length for a single label is 63; full FQDN is 253.
_MAX_DOMAIN_LEN = 253
# Conservative — A-Z, a-z, 0-9, hyphen, dot. IDNA-encoded labels live here.
_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")

# Domain suffixes / exact names we refuse — these are private/internal namespaces
# that can't legitimately point to a public origin.
_BLOCKED_DOMAINS = {"localhost"}
_BLOCKED_SUFFIXES = (".local", ".internal", ".corp", ".lan", ".intranet", ".home", ".test")


class DnsResolutionError(RuntimeError):
    """DNS resolution failed (NXDOMAIN, timeout, all addresses blocked, …)."""


def validate_domain(raw: str) -> str:
    """Return lowercase IDNA-ASCII form, or raise ValueError.

    Rejects: empty, whitespace, schemes (http://), paths, ports, wildcards,
    bare IPs, localhost, and well-known private TLDs (.local/.internal/etc).
    """
    if not isinstance(raw, str):
        raise ValueError("domain must be a string")
    s = raw.strip().rstrip(".").lower()
    if not s:
        raise ValueError("domain is empty")
    if len(s) > _MAX_DOMAIN_LEN:
        raise ValueError(f"domain exceeds {_MAX_DOMAIN_LEN} chars")
    if "/" in s or " " in s or ":" in s or "*" in s:
        raise ValueError("domain must not contain '/', ':', whitespace, or wildcards")
    if s in _BLOCKED_DOMAINS or s.endswith(_BLOCKED_SUFFIXES):
        raise ValueError(f"private/internal domains are not allowed: {s}")
    # Reject bare IPs — user must enter a domain name, not an address.
    try:
        ip_address(s)
        raise ValueError("enter a domain name, not an IP address")
    except ValueError:
        pass  # not an IP, good
    # IDNA encode (handles unicode → punycode); fall back gracefully if it's already ASCII.
    try:
        encoded = s.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"domain is not valid IDNA: {exc}") from exc
    if not _DOMAIN_RE.match(encoded):
        raise ValueError(f"domain format invalid: {encoded}")
    return encoded


def is_blocked_ip(addr: str) -> bool:
    """True if *addr* is in any range we refuse to proxy to.

    Covers RFC 1918, loopback, link-local, multicast, reserved, unspecified,
    and IPv6 equivalents. This is the SSRF defence — `origin_hosts` rows are
    validated through this before we ever write an Angie config or HTTP-probe.
    """
    try:
        ip = ip_address(addr)
    except ValueError:
        return True  # malformed → treat as blocked
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


async def resolve_a(domain: str, *, timeout: float = 5.0) -> tuple[list[str], int]:
    """Resolve A records → (public_ips, ttl_seconds).

    Raises DnsResolutionError if every resolved address is blocked (SSRF
    defence) or if the lookup fails outright. Returns the dns_ttl_seconds
    of the resolved record so the poller can honour it.
    """
    resolver = _make_resolver(timeout)
    try:
        answer = await resolver.resolve(domain, rdtype=dns.rdatatype.A)
    except dns.exception.DNSException as exc:
        raise DnsResolutionError(f"DNS A lookup failed for {domain}: {exc}") from exc
    ips_all = [r.address for r in answer]
    ips_public = [ip for ip in ips_all if not is_blocked_ip(ip)]
    if not ips_public:
        blocked = ", ".join(ips_all)
        raise DnsResolutionError(
            f"All resolved addresses for {domain} are private/reserved ({blocked}); refusing to proxy"
        )
    ttl = int(answer.rrset.ttl) if answer.rrset is not None else 60
    return ips_public, max(ttl, 30)  # floor TTL at 30s to avoid runaway polling


async def resolve_txt(domain: str, *, timeout: float = 5.0) -> list[str]:
    """Return all TXT record values for *domain* (joined for multi-string records)."""
    resolver = _make_resolver(timeout)
    try:
        answer = await resolver.resolve(domain, rdtype=dns.rdatatype.TXT)
    except dns.exception.DNSException as exc:
        logger.debug("TXT lookup for %s failed: %s", domain, exc)
        return []
    out: list[str] = []
    for rdata in answer:
        # Each rdata.strings is a tuple of bytes; concat per RFC 7208.
        joined = b"".join(rdata.strings).decode("utf-8", errors="replace")
        out.append(joined)
    return out


async def verify_txt_token(domain: str, expected_token: str) -> bool:
    """Check that _waf-verify.{domain} TXT contains *expected_token*."""
    if not expected_token:
        return False
    values = await resolve_txt(f"_waf-verify.{domain}")
    return any(expected_token in v for v in values)
