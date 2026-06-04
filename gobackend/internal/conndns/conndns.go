// Package conndns ports the DNS verification helpers from
// backend/src/connections/dns.py.
//
// Two public operations are exposed:
//
//   - VerifyTXTToken – checks that a TXT record at _waf-verify.<domain>
//     contains the expected ownership token (substring match, mirroring
//     Python's `any(expected_token in v for v in values)`).
//
//   - PointsToEdge – resolves the A/AAAA records of <domain> and checks
//     whether the edge IP (WAF_EDGE_IPV4 env var, as used by the Python
//     poller in _tick_pending_dns) is among them.
//
// Both are free of live DNS calls; the Resolver interface lets tests inject
// a fake.  The default NetResolver wraps net.DefaultResolver.
package conndns

import (
	"context"
	"net"
	"os"
	"strings"
)

// ─── Resolver interface ───────────────────────────────────────────────────────

// Resolver abstracts DNS lookups so the logic is testable without live DNS.
type Resolver interface {
	// LookupTXT returns all TXT record strings for the given name.
	// It should return (nil, nil) — not an error — when the record is absent
	// (NXDOMAIN / NODATA), mirroring dns.py's resolve_txt which returns []
	// on any failure path.
	LookupTXT(ctx context.Context, name string) ([]string, error)

	// LookupHost returns all addresses (A and AAAA) for the given host,
	// mirroring dns.py's resolve_a.
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// ─── Default (production) implementation ─────────────────────────────────────

// NetResolver is the production Resolver backed by net.DefaultResolver.
type NetResolver struct{}

// LookupTXT implements Resolver using the system resolver.
// NXDOMAIN / no-records errors are silenced and return nil, nil — consistent
// with dns.py resolve_txt which returns [] on any failure path.
func (NetResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	records, err := net.DefaultResolver.LookupTXT(ctx, name)
	if err != nil {
		// dns.py returns [] on any failure (NXDOMAIN, timeout, …); match that.
		return nil, nil //nolint:nilerr
	}
	return records, nil
}

// LookupHost implements Resolver using the system resolver.
func (NetResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// ─── TXT name helper ─────────────────────────────────────────────────────────

// TXTVerifyName returns the TXT record name used for ownership verification.
//
// Format (from dns.py verify_txt_token and service.py VerifyInstructions):
//
//	_waf-verify.<domain>
func TXTVerifyName(domain string) string {
	return "_waf-verify." + domain
}

// ─── VerifyTXTToken ──────────────────────────────────────────────────────────

// VerifyTXTToken checks that the TXT record at _waf-verify.<domain> contains
// expectedToken as a substring of at least one record value.
//
// Faithfully ports dns.py:
//
//	async def verify_txt_token(domain: str, expected_token: str) -> bool:
//	    if not expected_token:
//	        return False
//	    values = await resolve_txt(f"_waf-verify.{domain}")
//	    return any(expected_token in v for v in values)
//
// Returns (false, nil) when the record is absent — the caller interprets
// absence as "propagation still in progress".
func VerifyTXTToken(ctx context.Context, r Resolver, domain, expectedToken string) (bool, error) {
	if expectedToken == "" {
		return false, nil
	}
	name := TXTVerifyName(domain)
	values, err := r.LookupTXT(ctx, name)
	if err != nil {
		// dns.py treats all failures as "not yet" (returns False implicitly
		// via empty list); mirror that — the poller will retry.
		return false, nil //nolint:nilerr
	}
	for _, v := range values {
		if strings.Contains(v, expectedToken) {
			return true, nil
		}
	}
	return false, nil
}

// ─── EdgeIPv4 ────────────────────────────────────────────────────────────────

// EdgeIPv4 returns the configured WAF edge IPv4 address from the environment.
//
// Mirrors Python (poller.py):
//
//	EDGE_IPV4 = (os.environ.get("WAF_EDGE_IPV4") or "").strip()
func EdgeIPv4() string {
	return strings.TrimSpace(os.Getenv("WAF_EDGE_IPV4"))
}

// ─── PointsToEdge ────────────────────────────────────────────────────────────

// PointsToEdgeResult is the structured return of PointsToEdge.
type PointsToEdgeResult struct {
	// FlippedToEdge is true when the domain currently resolves to the WAF
	// edge IP — i.e. DNS has been pointed at the WAF.  Mirrors the
	// `if EDGE_IPV4 in ips` check in poller.py _tick_pending_dns.
	FlippedToEdge bool

	// ResolvedIPs is the set of addresses returned by LookupHost.
	// Populated even when FlippedToEdge is false so callers can surface
	// "A-record points to X; expecting Y" messages (see poller.py line 125).
	ResolvedIPs []string

	// EdgeIP is the value of WAF_EDGE_IPV4 that was compared against.
	EdgeIP string

	// Err is set when LookupHost failed.  Mirrors dns.py's
	// DnsResolutionError path in _tick_pending_dns.
	Err error
}

// PointsToEdge resolves the A/AAAA records for domain and checks whether
// edgeIP appears in the result.
//
// Faithfully ports the logic in poller.py _tick_pending_dns:
//
//	if not EDGE_IPV4:
//	    row.status = "error"
//	    row.status_detail = "WAF_EDGE_IPV4 env var not set; cannot detect DNS flip."
//	    return
//	ips, ttl = await dns.resolve_a(row.domain)
//	if EDGE_IPV4 in ips:
//	    row.status = "provisioning_cert"
//	else:
//	    row.status_detail = f"A-record points to {','.join(ips)}; expecting {EDGE_IPV4}."
//
// edgeIP is passed explicitly so callers that already called EdgeIPv4() can
// reuse the value; pass "" to have the function return FlippedToEdge=false
// immediately (edge not configured).
func PointsToEdge(ctx context.Context, r Resolver, domain, edgeIP string) PointsToEdgeResult {
	if edgeIP == "" {
		return PointsToEdgeResult{EdgeIP: edgeIP}
	}
	addrs, err := r.LookupHost(ctx, domain)
	if err != nil {
		return PointsToEdgeResult{EdgeIP: edgeIP, Err: err}
	}
	for _, a := range addrs {
		if a == edgeIP {
			return PointsToEdgeResult{
				FlippedToEdge: true,
				ResolvedIPs:   addrs,
				EdgeIP:        edgeIP,
			}
		}
	}
	return PointsToEdgeResult{
		FlippedToEdge: false,
		ResolvedIPs:   addrs,
		EdgeIP:        edgeIP,
	}
}
