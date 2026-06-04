package testsapi

import "crypto/tls"

// tlsConfigInsecure returns a TLS config that skips certificate verification —
// intentional for probing the local WAF (Angie) which uses a self-signed cert.
func tlsConfigInsecure() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} // #nosec G402
}
