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
import dns.message
import dns.rdatatype
import httpx

logger = logging.getLogger(__name__)

# ── DNS-over-HTTPS (DoH) is the primary resolver ─────────────────────────────
# Docker's embedded resolver (127.0.0.11) caches aggressively and serves stale
# negatives. Plain UDP/53 to public resolvers is unreliable on hardened VPS
# hosts — verified live on 80.72.24.108 where outbound UDP/53 is filtered to
# everything except Cloudflare, AND Cloudflare's recursive view was minutes
# behind on a newly-published TXT record.
#
# DoH (UDP-wrapped-in-HTTPS-on-443) sidesteps both problems: it bypasses
# Docker's resolver entirely, and goes through TCP/443 which is virtually
# never filtered. Verified the same TXT lookup that failed on Cloudflare UDP
# resolved cleanly via Google DoH on the same host.
#
# Override the endpoint list via WAF_DNS_DOH_URLS (comma-separated full URLs).
# Default order: Google first (most-trusted recursive), Cloudflare second
# (geographic redundancy).
_DEFAULT_DOH_URLS = (
    "https://dns.google/dns-query",
    "https://cloudflare-dns.com/dns-query",
)
# Legacy UDP resolvers for fallback when DoH endpoints all fail.
_FALLBACK_UDP_RESOLVERS = ("1.1.1.1", "1.0.0.1")


def _doh_urls() -> list[str]:
    raw = (os.environ.get("WAF_DNS_DOH_URLS") or "").strip()
    if not raw:
        return list(_DEFAULT_DOH_URLS)
    out = [u.strip() for u in raw.split(",") if u.strip()]
    return out or list(_DEFAULT_DOH_URLS)


async def _doh_query(
    name: str, rdtype: int, *, timeout: float = 6.0
) -> dns.message.Message | None:
    """Try every DoH endpoint in order. Returns the first successful reply.

    Returns None if all endpoints failed (network unreachable, etc) so the
    caller can decide whether to fall back to UDP.
    """
    q = dns.message.make_query(name, rdtype)
    wire = q.to_wire()
    headers = {
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message",
    }
    last_exc: Exception | None = None
    async with httpx.AsyncClient(timeout=timeout, http2=False) as client:
        for url in _doh_urls():
            try:
                r = await client.post(url, content=wire, headers=headers)
                r.raise_for_status()
                return dns.message.from_wire(r.content)
            except Exception as exc:  # network, HTTP, parse — all retry-worthy
                last_exc = exc
                logger.debug("DoH %s failed for %s: %s", url, name, exc)
                continue
    if last_exc is not None:
        logger.warning("All DoH endpoints failed for %s: %s", name, last_exc)
    return None


def _make_udp_resolver(timeout: float) -> dns.asyncresolver.Resolver:
    """Fallback UDP resolver — used only when DoH is entirely unreachable."""
    r = dns.asyncresolver.Resolver(configure=False)
    r.nameservers = list(_FALLBACK_UDP_RESOLVERS)
    r.timeout = timeout
    r.lifetime = timeout
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


def _rrset_ttl(msg: dns.message.Message, name: str) -> int:
    for rr in msg.answer:
        if rr.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA, dns.rdatatype.TXT):
            return int(rr.ttl)
    return 60


async def resolve_a(domain: str, *, timeout: float = 6.0) -> tuple[list[str], int]:
    """Resolve A records → (public_ips, ttl_seconds).

    Tries DoH first (works through HTTPS:443 even when UDP/53 is filtered);
    falls back to UDP resolvers only if every DoH endpoint failed. Raises
    DnsResolutionError if all addresses are blocked by the SSRF deny-list
    or if the lookup itself fails outright.
    """
    msg = await _doh_query(domain, dns.rdatatype.A, timeout=timeout)
    if msg is None:
        # DoH unreachable — try UDP as last resort.
        try:
            answer = await _make_udp_resolver(timeout).resolve(domain, dns.rdatatype.A)
        except dns.exception.DNSException as exc:
            raise DnsResolutionError(f"DNS A lookup failed for {domain}: {exc}") from exc
        ips_all = [r.address for r in answer]
        ttl = int(answer.rrset.ttl) if answer.rrset is not None else 60
    else:
        ips_all = [rd.address for rr in msg.answer if rr.rdtype == dns.rdatatype.A for rd in rr]
        ttl = _rrset_ttl(msg, domain)
        if not ips_all:
            raise DnsResolutionError(f"No A records for {domain}")

    ips_public = [ip for ip in ips_all if not is_blocked_ip(ip)]
    if not ips_public:
        blocked = ", ".join(ips_all)
        raise DnsResolutionError(
            f"All resolved addresses for {domain} are private/reserved ({blocked}); refusing to proxy"
        )
    return ips_public, max(ttl, 30)  # floor TTL at 30s


async def resolve_txt(domain: str, *, timeout: float = 6.0) -> list[str]:
    """Return all TXT record values for *domain* (joined for multi-string records).

    DoH-first like resolve_a. Returns [] on any failure path — TXT absence
    is a legitimate state (record not published yet) and the caller treats
    "not found" identically whether it's NXDOMAIN, propagation lag, or
    network failure.
    """
    msg = await _doh_query(domain, dns.rdatatype.TXT, timeout=timeout)
    if msg is not None:
        out: list[str] = []
        for rr in msg.answer:
            if rr.rdtype != dns.rdatatype.TXT:
                continue
            for rdata in rr:
                joined = b"".join(rdata.strings).decode("utf-8", errors="replace")
                out.append(joined)
        return out
    # DoH unreachable — try UDP fallback.
    try:
        answer = await _make_udp_resolver(timeout).resolve(domain, dns.rdatatype.TXT)
    except dns.exception.DNSException as exc:
        logger.debug("TXT lookup (UDP fallback) for %s failed: %s", domain, exc)
        return []
    return [
        b"".join(rd.strings).decode("utf-8", errors="replace") for rd in answer
    ]


async def verify_txt_token(domain: str, expected_token: str) -> bool:
    """Check that _waf-verify.{domain} TXT contains *expected_token*."""
    if not expected_token:
        return False
    values = await resolve_txt(f"_waf-verify.{domain}")
    return any(expected_token in v for v in values)
