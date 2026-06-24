package connectionsapi

import (
	"context"

	"github.com/zwarder/waf/gobackend/internal/angiecfg"
	"github.com/zwarder/waf/gobackend/internal/storage"
)

// AngiecfgAdapter routes angiecfg writes through the shared store + publisher so
// they satisfy the CfgWriter interface (and stay injectable in tests).
type AngiecfgAdapter struct {
	Store storage.Store
	Pub   *storage.Publisher
}

func (a AngiecfgAdapter) Write(ctx context.Context, cfg angiecfg.ConnConfig) error {
	return angiecfg.Write(ctx, a.Store, a.Pub, cfg)
}

func (a AngiecfgAdapter) Delete(ctx context.Context, tenantID, connID int64) error {
	return angiecfg.Delete(ctx, a.Store, a.Pub, tenantID, connID)
}
