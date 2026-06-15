package captcha

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeTurnstile spins up an httptest server that returns a fixed JSON body.
func fakeTurnstile(t *testing.T, success bool, errorCodes []string) (*httptest.Server, *http.Client) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := map[string]any{"success": success}
		if len(errorCodes) > 0 {
			body["error-codes"] = errorCodes
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(body) //nolint:errcheck
	}))
	// Point the verifier at the fake server by patching the URL constant — we
	// can't change the const at test time, so we instead pass a custom
	// http.Client with a transport that rewrites the host.
	client := &http.Client{
		Transport: &rewriteTransport{target: srv.URL},
	}
	return srv, client
}

// rewriteTransport rewrites all requests to point at target (the test server).
type rewriteTransport struct {
	target string
	base   http.RoundTripper
}

func (rt *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	base := rt.target
	// replace scheme+host, keep path+query
	clone.URL.Scheme = "http"
	clone.URL.Host = rt.target[len("http://"):]
	_ = base
	if rt.base != nil {
		return rt.base.RoundTrip(clone)
	}
	return http.DefaultTransport.RoundTrip(clone)
}

func TestVerify_Success(t *testing.T) {
	srv, client := fakeTurnstile(t, true, nil)
	defer srv.Close()

	v := newVerifierWithClient("test-secret", client)
	ok, err := v.Verify(context.Background(), "valid-token", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected Verify to return true for success=true response")
	}
}

func TestVerify_Failure(t *testing.T) {
	srv, client := fakeTurnstile(t, false, []string{"invalid-input-response"})
	defer srv.Close()

	v := newVerifierWithClient("test-secret", client)
	ok, err := v.Verify(context.Background(), "bad-token", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected Verify to return false for success=false response")
	}
}

func TestVerify_NotConfigured_Passes(t *testing.T) {
	// No secret → always true (dev pass-through), mirrors captcha.py
	v := newVerifierWithClient("", nil)
	ok, err := v.Verify(context.Background(), "anything", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected Verify to return true when unconfigured (dev no-op)")
	}
}

func TestVerify_BypassTokenNoLongerMagic(t *testing.T) {
	// The old hardcoded "e2e-test-bypass" backdoor is removed: with a secret
	// configured, that token is verified against Cloudflare like any other and
	// is rejected when siteverify says success=false. e2e suites instead rely on
	// the unconfigured (empty-secret) pass-through above.
	srv, client := fakeTurnstile(t, false, []string{"invalid-input-response"})
	defer srv.Close()

	v := newVerifierWithClient("some-secret", client)
	ok, err := v.Verify(context.Background(), "e2e-test-bypass", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("e2e-test-bypass must NOT be honored as a bypass when a secret is configured")
	}
}

func TestVerify_EmptyToken_Fails(t *testing.T) {
	v := newVerifierWithClient("some-secret", nil)
	ok, err := v.Verify(context.Background(), "", "1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected empty token to fail when secret is configured")
	}
}

func TestIsPrivateIP(t *testing.T) {
	cases := []struct {
		ip      string
		private bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.18.0.2", true},
		{"169.254.0.1", true},
		{"1.2.3.4", false},
		{"8.8.8.8", false},
		{"not-an-ip", true},
	}
	for _, tc := range cases {
		got := isPrivateIP(tc.ip)
		if got != tc.private {
			t.Errorf("isPrivateIP(%q) = %v, want %v", tc.ip, got, tc.private)
		}
	}
}

func TestVerify_PrivateRemoteIP_NotForwarded(t *testing.T) {
	// Private IP should not be forwarded to Cloudflare.
	// We verify this by checking the form values in the fake server.
	var gotRemoteIP string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm() //nolint:errcheck
		gotRemoteIP = r.FormValue("remoteip")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"success": true}) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{Transport: &rewriteTransport{target: srv.URL}}
	v := newVerifierWithClient("secret", client)
	v.Verify(context.Background(), "token", "172.18.0.2") //nolint:errcheck

	if gotRemoteIP != "" {
		t.Errorf("private IP should not be forwarded to Cloudflare, got remoteip=%q", gotRemoteIP)
	}
}

func TestVerify_PublicRemoteIP_Forwarded(t *testing.T) {
	var gotRemoteIP string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm() //nolint:errcheck
		gotRemoteIP = r.FormValue("remoteip")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"success": true}) //nolint:errcheck
	}))
	defer srv.Close()

	client := &http.Client{Transport: &rewriteTransport{target: srv.URL}}
	v := newVerifierWithClient("secret", client)
	v.Verify(context.Background(), "token", "1.2.3.4") //nolint:errcheck

	if gotRemoteIP != "1.2.3.4" {
		t.Errorf("public IP should be forwarded to Cloudflare, got remoteip=%q", gotRemoteIP)
	}
}
