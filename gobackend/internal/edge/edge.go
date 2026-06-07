// Package edge resolves how clients reach the WAF edge: a stable per-tenant
// CNAME hostname plus the IP set used internally to detect that a client's
// domain has been pointed at the edge.
package edge

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Targets struct {
	BaseHostname string
	IPs          []string
}

func (t Targets) HostnameFor(slug string) string {
	if t.BaseHostname == "" || slug == "" {
		return ""
	}
	return slug + "." + t.BaseHostname
}

type HostLookuper interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

type Resolver interface {
	Resolve(ctx context.Context) Targets
}

const defaultEchoURL = "https://api.ipify.org"

type CachedResolver struct {
	dns     HostLookuper
	base    string
	ipv4s   []string
	echoURL string
	httpc   *http.Client
	ttl     time.Duration

	mu     sync.Mutex
	cached Targets
	exp    time.Time
}

func NewResolverFromEnv(dns HostLookuper) *CachedResolver {
	echo := strings.TrimSpace(os.Getenv("WAF_EDGE_ECHO_URL"))
	if echo == "" {
		echo = defaultEchoURL
	}
	return &CachedResolver{
		dns:     dns,
		base:    strings.TrimSpace(os.Getenv("WAF_EDGE_HOSTNAME_BASE")),
		ipv4s:   ParseIPv4List(os.Getenv("WAF_EDGE_IPV4")),
		echoURL: echo,
		httpc:   &http.Client{Timeout: 5 * time.Second},
		ttl:     5 * time.Minute,
	}
}

func ParseIPv4List(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	out := make([]string, 0, len(fields))
	seen := map[string]struct{}{}
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if _, ok := seen[f]; ok {
			continue
		}
		seen[f] = struct{}{}
		out = append(out, f)
	}
	return out
}

func (r *CachedResolver) Resolve(ctx context.Context) Targets {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Now().Before(r.exp) {
		return r.cached
	}
	r.cached = r.compute(ctx)
	r.exp = time.Now().Add(r.ttl)
	return r.cached
}

func (r *CachedResolver) compute(ctx context.Context) Targets {
	if r.base != "" {
		ips, err := r.dns.LookupHost(ctx, r.base)
		if err != nil {
			ips = nil
		}
		return Targets{BaseHostname: r.base, IPs: dedupe(ips)}
	}
	if len(r.ipv4s) > 0 {
		return Targets{IPs: r.ipv4s}
	}
	if ip := r.fetchEcho(ctx); ip != "" {
		return Targets{IPs: []string{ip}}
	}
	return Targets{}
}

func (r *CachedResolver) fetchEcho(ctx context.Context) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.echoURL, nil)
	if err != nil {
		return ""
	}
	resp, err := r.httpc.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

func dedupe(in []string) []string {
	if len(in) == 0 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
