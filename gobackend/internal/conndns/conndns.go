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

// ─── Verifier interface ───────────────────────────────────────────────────────

// Verifier abstracts DNS verification invariants.
type Verifier interface {
	VerifyTXT(ctx context.Context, domain, expectedToken string) (bool, error)
	VerifyEdge(ctx context.Context, domain string, edgeIPs []string) PointsToEdgeResult
	LookupOriginHosts(ctx context.Context, domain string) ([]string, error)
}

// DNSVerifier is a stateful implementation of Verifier wrapping a Resolver.
type DNSVerifier struct {
	resolver Resolver
}

// NewVerifier constructs a DNSVerifier wrapping a Resolver.
func NewVerifier(r Resolver) *DNSVerifier {
	return &DNSVerifier{resolver: r}
}

// VerifyTXT wraps VerifyTXTToken.
func (v *DNSVerifier) VerifyTXT(ctx context.Context, domain, expectedToken string) (bool, error) {
	return VerifyTXTToken(ctx, v.resolver, domain, expectedToken)
}

// VerifyEdge wraps PointsToAnyEdge.
func (v *DNSVerifier) VerifyEdge(ctx context.Context, domain string, edgeIPs []string) PointsToEdgeResult {
	return PointsToAnyEdge(ctx, v.resolver, domain, edgeIPs)
}

// LookupOriginHosts wraps LookupHost.
func (v *DNSVerifier) LookupOriginHosts(ctx context.Context, domain string) ([]string, error) {
	return v.resolver.LookupHost(ctx, domain)
}

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

// NetResolver is the production Resolver. By default it is backed by
// net.DefaultResolver (the container's local resolver); when constructed via
// NewNetResolverFromEnv with WAF_DNS_SERVERS set, it routes lookups to the
// configured public resolvers instead. The zero value remains valid and uses
// net.DefaultResolver, preserving existing callers and tests.
type NetResolver struct {
	// r is the underlying resolver. A nil r means net.DefaultResolver.
	r *net.Resolver
}

// resolver returns the configured resolver, or net.DefaultResolver when unset.
func (n NetResolver) resolver() *net.Resolver {
	if n.r != nil {
		return n.r
	}
	return net.DefaultResolver
}

// NewNetResolverFromEnv builds a NetResolver from the environment.
//
// When WAF_DNS_SERVERS is set to a comma-separated list of resolvers (bare IPs
// or host:port, e.g. "1.1.1.1,8.8.8.8:53"), TXT/host lookups are sent to those
// public resolvers via Go's pure-Go resolver. This bypasses the container's
// local resolver, which can negatively cache _waf-verify.<domain> — that name
// is queried the instant a connection is created, before the operator publishes
// the record, so the local resolver caches the NXDOMAIN/NODATA and keeps
// returning "not found" long after public resolvers (the ones a "DNS checker"
// uses) already see the TXT. An empty/unset env keeps net.DefaultResolver.
func NewNetResolverFromEnv() NetResolver {
	servers := parseDNSServers(os.Getenv("WAF_DNS_SERVERS"))
	if len(servers) == 0 {
		return NetResolver{}
	}
	return NetResolver{r: publicResolver(servers)}
}

// parseDNSServers splits a comma-separated resolver list, trimming blanks and
// defaulting bare IPs to port 53.
func parseDNSServers(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		s := strings.TrimSpace(part)
		if s == "" {
			continue
		}
		if !strings.Contains(s, ":") {
			s += ":53"
		}
		out = append(out, s)
	}
	return out
}

// publicResolver returns a pure-Go resolver that dials the given servers in
// order (first reachable wins), honouring the network the stdlib asks for so
// UDP→TCP truncation fallback keeps working.
func publicResolver(servers []string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			var lastErr error
			for _, s := range servers {
				conn, err := d.DialContext(ctx, network, s)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
}

// LookupTXT implements Resolver using the configured resolver.
// NXDOMAIN / no-records errors are silenced and return nil, nil — consistent
// with dns.py resolve_txt which returns [] on any failure path.
func (n NetResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	records, err := n.resolver().LookupTXT(ctx, name)
	if err != nil {
		// dns.py returns [] on any failure (NXDOMAIN, timeout, …); match that.
		return nil, nil //nolint:nilerr
	}
	return records, nil
}

// LookupHost implements Resolver using the configured resolver.
//
// The system resolver can return the same address more than once (e.g. when a
// host is reachable via multiple resolution paths), so duplicates are removed
// while preserving first-seen order.
func (n NetResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	addrs, err := n.resolver().LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(addrs))
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	return out, nil
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

// PointsToAnyEdge resolves domain's A/AAAA records and reports whether any of
// them appears in edgeIPs (the domain has been pointed at the WAF edge). Empty
// edgeIPs → FlippedToEdge=false immediately (edge not configured). The set
// variant of PointsToEdge, for multi-IP / CNAME-to-edge verification.
func PointsToAnyEdge(ctx context.Context, r Resolver, domain string, edgeIPs []string) PointsToEdgeResult {
	joined := strings.Join(edgeIPs, ",")
	if len(edgeIPs) == 0 {
		return PointsToEdgeResult{EdgeIP: joined}
	}
	addrs, err := r.LookupHost(ctx, domain)
	if err != nil {
		return PointsToEdgeResult{EdgeIP: joined, Err: err}
	}
	set := make(map[string]struct{}, len(edgeIPs))
	for _, e := range edgeIPs {
		set[e] = struct{}{}
	}
	for _, a := range addrs {
		if _, ok := set[a]; ok {
			return PointsToEdgeResult{FlippedToEdge: true, ResolvedIPs: addrs, EdgeIP: joined}
		}
	}
	return PointsToEdgeResult{FlippedToEdge: false, ResolvedIPs: addrs, EdgeIP: joined}
}
