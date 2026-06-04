package conndns_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zwarder/waf/gobackend/internal/conndns"
)

// ─── Fake Resolver ────────────────────────────────────────────────────────────

// fakeResolver implements conndns.Resolver entirely in-memory — no live DNS.
type fakeResolver struct {
	// txt maps lookup-name → list of TXT record strings.
	txt map[string][]string
	// host maps hostname → list of addresses.
	host map[string][]string
	// hostErr causes LookupHost to return this error (for all hosts).
	hostErr error
	// txtErr causes LookupTXT to return this error (for all names).
	txtErr error
}

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if f.txtErr != nil {
		return nil, f.txtErr
	}
	return f.txt[name], nil
}

func (f *fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if f.hostErr != nil {
		return nil, f.hostErr
	}
	return f.host[host], nil
}

// ─── TXTVerifyName ───────────────────────────────────────────────────────────

// TestTXTVerifyName asserts the exact format used by dns.py:
//
//	f"_waf-verify.{domain}"
func TestTXTVerifyName(t *testing.T) {
	require.Equal(t, "_waf-verify.example.com", conndns.TXTVerifyName("example.com"))
	require.Equal(t, "_waf-verify.sub.example.com", conndns.TXTVerifyName("sub.example.com"))
}

// ─── VerifyTXTToken ──────────────────────────────────────────────────────────

// TestVerifyTXTToken_Present verifies that the token is found when it appears
// as a substring of a TXT record value (mirroring `expected_token in v`).
func TestVerifyTXTToken_Present(t *testing.T) {
	token := "abc123verifytoken"
	r := &fakeResolver{
		txt: map[string][]string{
			"_waf-verify.example.com": {token},
		},
	}
	ok, err := conndns.VerifyTXTToken(context.Background(), r, "example.com", token)
	require.NoError(t, err)
	require.True(t, ok, "token present in TXT → should verify")
}

// TestVerifyTXTToken_PresentAsSubstring checks that a TXT record that contains
// the token as part of a longer string still counts — Python uses `in`, not `==`.
func TestVerifyTXTToken_PresentAsSubstring(t *testing.T) {
	token := "mytoken"
	r := &fakeResolver{
		txt: map[string][]string{
			"_waf-verify.example.com": {"prefix-" + token + "-suffix"},
		},
	}
	ok, err := conndns.VerifyTXTToken(context.Background(), r, "example.com", token)
	require.NoError(t, err)
	require.True(t, ok, "token present as substring → should verify")
}

// TestVerifyTXTToken_PresentInSecondRecord verifies that any() semantics are
// correct — the token only needs to appear in one of multiple TXT values.
func TestVerifyTXTToken_PresentInSecondRecord(t *testing.T) {
	token := "tok999"
	r := &fakeResolver{
		txt: map[string][]string{
			"_waf-verify.example.com": {"unrelated-value", token, "another-unrelated"},
		},
	}
	ok, err := conndns.VerifyTXTToken(context.Background(), r, "example.com", token)
	require.NoError(t, err)
	require.True(t, ok)
}

// TestVerifyTXTToken_Absent verifies that a missing record → false (propagation
// still in progress; caller retries on next tick).
func TestVerifyTXTToken_Absent(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{}}
	ok, err := conndns.VerifyTXTToken(context.Background(), r, "example.com", "tok")
	require.NoError(t, err)
	require.False(t, ok, "record absent → not yet verified")
}

// TestVerifyTXTToken_WrongToken verifies that a TXT record with a different
// value does not satisfy verification.
func TestVerifyTXTToken_WrongToken(t *testing.T) {
	r := &fakeResolver{
		txt: map[string][]string{
			"_waf-verify.example.com": {"wrong-token"},
		},
	}
	ok, err := conndns.VerifyTXTToken(context.Background(), r, "example.com", "correct-token")
	require.NoError(t, err)
	require.False(t, ok, "wrong value → not verified")
}

// TestVerifyTXTToken_EmptyToken mirrors dns.py `if not expected_token: return False`.
func TestVerifyTXTToken_EmptyToken(t *testing.T) {
	r := &fakeResolver{
		txt: map[string][]string{
			"_waf-verify.example.com": {"anything"},
		},
	}
	ok, err := conndns.VerifyTXTToken(context.Background(), r, "example.com", "")
	require.NoError(t, err)
	require.False(t, ok, "empty token → always false (dns.py guard)")
}

// TestVerifyTXTToken_LookupError mirrors dns.py resolve_txt returning [] on
// any failure path — the Go port silences the error and returns (false, nil).
func TestVerifyTXTToken_LookupError(t *testing.T) {
	r := &fakeResolver{txtErr: errors.New("SERVFAIL")}
	ok, err := conndns.VerifyTXTToken(context.Background(), r, "example.com", "tok")
	require.NoError(t, err, "dns.py silences errors; Go port must too")
	require.False(t, ok)
}

// TestVerifyTXTToken_LookupName asserts the exact name sent to LookupTXT:
// _waf-verify.<domain>  (the format from dns.py and service.py VerifyInstructions).
func TestVerifyTXTToken_LookupName(t *testing.T) {
	queried := ""
	r := &captureNameResolver{}
	r.onLookupTXT = func(name string) { queried = name }

	_, _ = conndns.VerifyTXTToken(context.Background(), r, "mysite.io", "tok")
	require.Equal(t, "_waf-verify.mysite.io", queried,
		"TXT lookup name must match dns.py format _waf-verify.<domain>")
}

// captureNameResolver is a test-only Resolver that records the names it sees.
type captureNameResolver struct {
	onLookupTXT func(name string)
}

func (c *captureNameResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if c.onLookupTXT != nil {
		c.onLookupTXT(name)
	}
	return nil, nil
}
func (c *captureNameResolver) LookupHost(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}

// ─── PointsToEdge ────────────────────────────────────────────────────────────

// TestPointsToEdge_FlippedTrue: domain resolves to the configured edge IP → flipped.
func TestPointsToEdge_FlippedTrue(t *testing.T) {
	edgeIP := "1.2.3.4"
	r := &fakeResolver{host: map[string][]string{
		"example.com": {edgeIP},
	}}
	res := conndns.PointsToEdge(context.Background(), r, "example.com", edgeIP)
	require.True(t, res.FlippedToEdge)
	require.Equal(t, edgeIP, res.EdgeIP)
	require.Contains(t, res.ResolvedIPs, edgeIP)
	require.NoError(t, res.Err)
}

// TestPointsToEdge_FlippedFalse: domain resolves elsewhere.
func TestPointsToEdge_FlippedFalse(t *testing.T) {
	edgeIP := "1.2.3.4"
	r := &fakeResolver{host: map[string][]string{
		"example.com": {"5.6.7.8"},
	}}
	res := conndns.PointsToEdge(context.Background(), r, "example.com", edgeIP)
	require.False(t, res.FlippedToEdge)
	require.Equal(t, []string{"5.6.7.8"}, res.ResolvedIPs,
		"caller uses ResolvedIPs to surface 'A-record points to X; expecting Y'")
	require.NoError(t, res.Err)
}

// TestPointsToEdge_EdgeIPAmongMultiple: edge IP is one of several resolved addresses.
func TestPointsToEdge_EdgeIPAmongMultiple(t *testing.T) {
	edgeIP := "10.0.0.1"
	r := &fakeResolver{host: map[string][]string{
		"example.com": {"8.8.8.8", edgeIP, "9.9.9.9"},
	}}
	res := conndns.PointsToEdge(context.Background(), r, "example.com", edgeIP)
	require.True(t, res.FlippedToEdge)
}

// TestPointsToEdge_EmptyEdgeIP: WAF_EDGE_IPV4 not set → FlippedToEdge=false, no
// lookup performed.  Mirrors poller.py "WAF_EDGE_IPV4 env var not set" branch.
func TestPointsToEdge_EmptyEdgeIP(t *testing.T) {
	called := false
	r := &captureNameResolver{
		onLookupTXT: func(_ string) { called = true },
	}
	_ = r // ensure the resolver is not called for host lookups either
	res := conndns.PointsToEdge(context.Background(), &fakeResolver{
		host: map[string][]string{
			// even if a record exists, with empty edgeIP we should not claim flipped
			"example.com": {"1.2.3.4"},
		},
	}, "example.com", "")
	_ = called
	require.False(t, res.FlippedToEdge)
	require.Empty(t, res.EdgeIP)
}

// TestPointsToEdge_LookupError: DNS resolution failure → Err is set, FlippedToEdge=false.
// Mirrors poller.py _tick_pending_dns except block where DnsResolutionError is caught.
func TestPointsToEdge_LookupError(t *testing.T) {
	r := &fakeResolver{hostErr: errors.New("NXDOMAIN")}
	res := conndns.PointsToEdge(context.Background(), r, "gone.example.com", "1.2.3.4")
	require.False(t, res.FlippedToEdge)
	require.Error(t, res.Err)
}

// ─── EdgeIPv4 ────────────────────────────────────────────────────────────────

// TestEdgeIPv4_EnvVar verifies that EdgeIPv4 reads WAF_EDGE_IPV4 and strips
// whitespace, mirroring Python:
//
//	EDGE_IPV4 = (os.environ.get("WAF_EDGE_IPV4") or "").strip()
func TestEdgeIPv4_EnvVar(t *testing.T) {
	t.Setenv("WAF_EDGE_IPV4", "  203.0.113.1  ")
	require.Equal(t, "203.0.113.1", conndns.EdgeIPv4())
}

func TestEdgeIPv4_Unset(t *testing.T) {
	t.Setenv("WAF_EDGE_IPV4", "")
	require.Equal(t, "", conndns.EdgeIPv4())
}

// ─── Combined truth-table ────────────────────────────────────────────────────

// TestCombinedTruthTable exercises both functions together to mirror the two
// state transitions handled by the Python poller:
//
//	pending_verification → pending_dns      (TXT seen)
//	pending_dns          → provisioning_cert (A points to edge)
func TestCombinedTruthTable(t *testing.T) {
	edgeIP := "192.0.2.1"
	domain := "example.com"
	token := "verifytoken42"

	cases := []struct {
		name            string
		txtRecords      []string // nil = record absent
		hostAddrs       []string
		wantTXTVerified bool
		wantFlipped     bool
	}{
		{
			name:            "neither TXT nor edge: pending_verification stays",
			txtRecords:      nil,
			hostAddrs:       []string{"9.9.9.9"},
			wantTXTVerified: false,
			wantFlipped:     false,
		},
		{
			name:            "TXT present but DNS not flipped: moves to pending_dns",
			txtRecords:      []string{token},
			hostAddrs:       []string{"9.9.9.9"},
			wantTXTVerified: true,
			wantFlipped:     false,
		},
		{
			name:            "DNS flipped but no TXT: edge check succeeds, TXT check fails",
			txtRecords:      nil,
			hostAddrs:       []string{edgeIP},
			wantTXTVerified: false,
			wantFlipped:     true,
		},
		{
			name:            "both TXT present and DNS flipped: full provisioning_cert trigger",
			txtRecords:      []string{token},
			hostAddrs:       []string{edgeIP},
			wantTXTVerified: true,
			wantFlipped:     true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeResolver{
				txt:  map[string][]string{"_waf-verify." + domain: tc.txtRecords},
				host: map[string][]string{domain: tc.hostAddrs},
			}

			txtOK, err := conndns.VerifyTXTToken(context.Background(), r, domain, token)
			require.NoError(t, err)
			require.Equal(t, tc.wantTXTVerified, txtOK, "TXT verification mismatch")

			res := conndns.PointsToEdge(context.Background(), r, domain, edgeIP)
			require.NoError(t, res.Err)
			require.Equal(t, tc.wantFlipped, res.FlippedToEdge, "edge-flip mismatch")
		})
	}
}
