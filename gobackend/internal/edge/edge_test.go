package edge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fakeLookuper struct {
	ips map[string][]string
	err error
}

func (f *fakeLookuper) LookupHost(_ context.Context, host string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.ips[host], nil
}

func TestHostnameFor(t *testing.T) {
	if got := (Targets{BaseHostname: "edge.waf.example"}).HostnameFor("acme"); got != "acme.edge.waf.example" {
		t.Fatalf("HostnameFor = %q", got)
	}
	if got := (Targets{}).HostnameFor("acme"); got != "" {
		t.Fatalf("IP mode HostnameFor = %q, want empty", got)
	}
}

func TestParseIPv4List(t *testing.T) {
	got := ParseIPv4List(" 1.1.1.1, 2.2.2.2 1.1.1.1 ")
	if len(got) != 2 || got[0] != "1.1.1.1" || got[1] != "2.2.2.2" {
		t.Fatalf("ParseIPv4List = %v", got)
	}
}

func TestResolveHostnameMode(t *testing.T) {
	r := &CachedResolver{dns: &fakeLookuper{ips: map[string][]string{"edge.x": {"9.9.9.9", "9.9.9.9"}}}, base: "edge.x", ttl: time.Hour}
	tg := r.Resolve(context.Background())
	if tg.BaseHostname != "edge.x" || len(tg.IPs) != 1 || tg.IPs[0] != "9.9.9.9" {
		t.Fatalf("hostname mode = %+v", tg)
	}
}

func TestResolveEnvFallback(t *testing.T) {
	r := &CachedResolver{ipv4s: []string{"5.5.5.5"}, ttl: time.Hour}
	tg := r.Resolve(context.Background())
	if tg.BaseHostname != "" || len(tg.IPs) != 1 || tg.IPs[0] != "5.5.5.5" {
		t.Fatalf("env fallback = %+v", tg)
	}
}

func TestResolveEchoFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("7.7.7.7\n"))
	}))
	defer srv.Close()
	r := &CachedResolver{echoURL: srv.URL, httpc: srv.Client(), ttl: time.Hour}
	tg := r.Resolve(context.Background())
	if len(tg.IPs) != 1 || tg.IPs[0] != "7.7.7.7" {
		t.Fatalf("echo fallback = %+v", tg)
	}
}

func TestResolveCaches(t *testing.T) {
	fl := &fakeLookuper{ips: map[string][]string{"edge.x": {"1.2.3.4"}}}
	r := &CachedResolver{dns: fl, base: "edge.x", ttl: time.Hour}
	_ = r.Resolve(context.Background())
	fl.ips["edge.x"] = []string{"changed"}
	tg := r.Resolve(context.Background())
	if tg.IPs[0] != "1.2.3.4" {
		t.Fatalf("expected cached 1.2.3.4, got %v", tg.IPs)
	}
}
