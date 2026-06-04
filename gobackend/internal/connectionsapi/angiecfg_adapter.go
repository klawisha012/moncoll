package connectionsapi

import "github.com/zwarder/waf/gobackend/internal/angiecfg"

// AngiecfgAdapter wraps the angiecfg package-level functions as methods so
// they satisfy the CfgWriter interface (needed for test injection).
type AngiecfgAdapter struct{}

func (AngiecfgAdapter) Write(baseDir string, cfg angiecfg.ConnConfig) error {
	return angiecfg.Write(baseDir, cfg)
}

func (AngiecfgAdapter) Delete(baseDir string, connID int64) error {
	return angiecfg.Delete(baseDir, connID)
}
