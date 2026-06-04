package testsapi

import (
	"context"

	"github.com/zwarder/waf/gobackend/internal/store"
)

// StoreAdapter adapts *store.Store to the ConnStore interface used by Service.
type StoreAdapter struct {
	s *store.Store
}

// NewStoreAdapter wraps a *store.Store.
func NewStoreAdapter(s *store.Store) *StoreAdapter {
	return &StoreAdapter{s: s}
}

func (a *StoreAdapter) ListConnectionsForTenant(ctx context.Context, tenantID int64) ([]ConnectionRow, error) {
	rows, err := a.s.ListConnectionsFull(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]ConnectionRow, 0, len(rows))
	for _, r := range rows {
		cr := ConnectionRow{
			ID:       r.ID,
			TenantID: r.TenantID,
			Domain:   r.Domain,
			Enabled:  r.Enabled,
			Status:   r.Status,
		}
		if r.SSLCertPath != nil {
			cr.SSLCertPath = r.SSLCertPath
		}
		if r.SSLKeyPath != nil {
			cr.SSLKeyPath = r.SSLKeyPath
		}
		out = append(out, cr)
	}
	return out, nil
}

func (a *StoreAdapter) GetConnectionForTenant(ctx context.Context, connID, tenantID int64) (*ConnectionRow, error) {
	r, err := a.s.GetConnectionFull(ctx, tenantID, connID)
	if err != nil {
		// NotFoundError → return nil, nil (caller falls back to default target)
		var nf *store.NotFoundError
		if isNotFoundErr(err, &nf) {
			return nil, nil
		}
		return nil, err
	}
	cr := &ConnectionRow{
		ID:       r.ID,
		TenantID: r.TenantID,
		Domain:   r.Domain,
		Enabled:  r.Enabled,
		Status:   r.Status,
	}
	if r.SSLCertPath != nil {
		cr.SSLCertPath = r.SSLCertPath
	}
	if r.SSLKeyPath != nil {
		cr.SSLKeyPath = r.SSLKeyPath
	}
	return cr, nil
}

// isNotFoundErr checks if err is a *store.NotFoundError, writing to target if so.
func isNotFoundErr(err error, target **store.NotFoundError) bool {
	if err == nil {
		return false
	}
	nf, ok := err.(*store.NotFoundError)
	if ok {
		*target = nf
	}
	return ok
}
