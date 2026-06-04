package connectionsapi

import "github.com/zwarder/waf/gobackend/internal/certs"

// CertsManagerAdapter wraps *certs.Manager to satisfy the CertManager interface.
// It uses the correct signatures from manager.go.
type CertsManagerAdapter struct {
	M *certs.Manager
}

func (a CertsManagerAdapter) TriggerACME(connID int64, domains []string, tenantID *int64) certs.Result {
	return a.M.TriggerACME(connID, domains, tenantID)
}

func (a CertsManagerAdapter) GenerateSelfSigned(connID int64, domains []string, tenantID *int64) (certs.Result, error) {
	r, err := a.M.GenerateSelfSigned(connID, domains, tenantID)
	return r, err
}
