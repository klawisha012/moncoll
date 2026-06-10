package conndns

import (
	"reflect"
	"testing"
)

// TestParseDNSServers covers blank-trimming and the bare-IP → :53 default that
// lets operators set WAF_DNS_SERVERS="1.1.1.1,8.8.8.8" without ports.
func TestParseDNSServers(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"1.1.1.1", []string{"1.1.1.1:53"}},
		{"1.1.1.1,8.8.8.8", []string{"1.1.1.1:53", "8.8.8.8:53"}},
		{" 1.1.1.1:5353 , 8.8.8.8 ", []string{"1.1.1.1:5353", "8.8.8.8:53"}},
		{"9.9.9.9,,", []string{"9.9.9.9:53"}},
	}
	for _, c := range cases {
		got := parseDNSServers(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseDNSServers(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestNewNetResolverFromEnv verifies the wiring decision: with no WAF_DNS_SERVERS
// the resolver stays nil (net.DefaultResolver — the legacy behaviour), and with
// servers set it installs a custom pure-Go resolver that bypasses the
// container's local resolver. This is the regression guard for the
// "public DNS checker sees the TXT but the backend doesn't" bug.
func TestNewNetResolverFromEnv(t *testing.T) {
	t.Setenv("WAF_DNS_SERVERS", "")
	if r := NewNetResolverFromEnv(); r.r != nil {
		t.Fatalf("empty env: expected nil resolver (net.DefaultResolver), got %v", r.r)
	}

	t.Setenv("WAF_DNS_SERVERS", "1.1.1.1,8.8.8.8:53")
	r := NewNetResolverFromEnv()
	if r.r == nil {
		t.Fatal("with servers set: expected a custom resolver, got nil")
	}
	if !r.r.PreferGo {
		t.Error("custom resolver must set PreferGo so the Dial hook is used")
	}
	if r.r.Dial == nil {
		t.Error("custom resolver must install a Dial hook routing to the configured servers")
	}
	// resolver() must hand back the configured resolver, not the default.
	if r.resolver() != r.r {
		t.Error("resolver() should return the configured custom resolver when set")
	}
}
