package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"google.golang.org/grpc"

	adminv1 "github.com/zwarder/waf/gobackend/gen/admin/v1"
	crowdsecv1 "github.com/zwarder/waf/gobackend/gen/crowdsec/v1"
	dashboardv1 "github.com/zwarder/waf/gobackend/gen/dashboard/v1"
	modsecurityv1 "github.com/zwarder/waf/gobackend/gen/modsecurity/v1"
	monitoringv1 "github.com/zwarder/waf/gobackend/gen/monitoring/v1"
	sslv1 "github.com/zwarder/waf/gobackend/gen/ssl/v1"
	"github.com/zwarder/waf/gobackend/internal/admin"
	"github.com/zwarder/waf/gobackend/internal/angie"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/certs"
	"github.com/zwarder/waf/gobackend/internal/chdash"
	"github.com/zwarder/waf/gobackend/internal/config"
	"github.com/zwarder/waf/gobackend/internal/crowdsec"
	"github.com/zwarder/waf/gobackend/internal/crowdsecapi"
	"github.com/zwarder/waf/gobackend/internal/cscli"
	"github.com/zwarder/waf/gobackend/internal/dashboardapi"
	"github.com/zwarder/waf/gobackend/internal/sslapi"
	"github.com/zwarder/waf/gobackend/internal/modsec"
	"github.com/zwarder/waf/gobackend/internal/modsecurity"
	"github.com/zwarder/waf/gobackend/internal/monitoring"
	"github.com/zwarder/waf/gobackend/internal/observability"
	"github.com/zwarder/waf/gobackend/internal/server"
	"github.com/zwarder/waf/gobackend/internal/store"
	"github.com/zwarder/waf/gobackend/internal/tenantfs"
)

func main() {
	log := observability.NewLogger()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		log.Error("config load failed", "err", err)
		os.Exit(1)
	}

	st, err := store.New(ctx, cfg.PostgresDSN)
	if err != nil {
		log.Error("postgres connect failed", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	engine, err := monitoring.NewDockerEngine()
	if err != nil {
		log.Error("docker client failed", "err", err)
		os.Exit(1)
	}

	// ── CrowdSec runner + syncer ──────────────────────────────────────────────
	csRunner, err := cscli.New()
	if err != nil {
		// Non-fatal: the sync loop will log errors gracefully.
		log.Warn("cscli runner init failed (crowdsec features will be degraded)", "err", err)
		csRunner = nil
	}
	if csRunner != nil {
		defer csRunner.Close()
	}

	syncer := crowdsec.NewSyncer(csRunnerOrNoop(csRunner), angieReloader{log: log}, storeConnSource{st})
	var csSvc *crowdsecapi.Service
	if csRunner != nil {
		csSvc = crowdsecapi.New(csRunner, syncer)
	} else {
		csSvc = crowdsecapi.New(noopRunner{}, syncer)
	}

	// ── Auth + gRPC ───────────────────────────────────────────────────────────
	dec := auth.NewDecoder(cfg.PasetoKey)
	policy := auth.NewPolicy(st)

	const grpcAddr = "127.0.0.1:9090"
	grpcLis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		log.Error("grpc listen failed", "err", err)
		os.Exit(1)
	}
	authLevels := map[string]auth.Level{
		// modsecurity: require_verified (any non-suspended user; not admin-only)
		modsecurityv1.ModSecurityService_GetConfig_FullMethodName:    auth.LevelVerified,
		modsecurityv1.ModSecurityService_GetRules_FullMethodName:     auth.LevelVerified,
		modsecurityv1.ModSecurityService_ListRules_FullMethodName:    auth.LevelVerified,
		modsecurityv1.ModSecurityService_UpdateConfig_FullMethodName: auth.LevelVerified,
		modsecurityv1.ModSecurityService_UpdateRules_FullMethodName:  auth.LevelVerified,
		modsecurityv1.ModSecurityService_AddRule_FullMethodName:      auth.LevelVerified,
		modsecurityv1.ModSecurityService_DeleteRule_FullMethodName:   auth.LevelVerified,
		modsecurityv1.ModSecurityService_Reload_FullMethodName:       auth.LevelVerified,
		// crowdsec: require_verified (matches Python's require_verified dependency)
		crowdsecv1.CrowdSecService_GetStatus_FullMethodName:          auth.LevelVerified,
		crowdsecv1.CrowdSecService_GetDecisions_FullMethodName:       auth.LevelVerified,
		crowdsecv1.CrowdSecService_AddDecision_FullMethodName:        auth.LevelVerified,
		crowdsecv1.CrowdSecService_DeleteDecision_FullMethodName:     auth.LevelVerified,
		crowdsecv1.CrowdSecService_DeleteAllDecisions_FullMethodName: auth.LevelVerified,
		crowdsecv1.CrowdSecService_GetManualBlocks_FullMethodName:    auth.LevelVerified,
		crowdsecv1.CrowdSecService_GetScenarios_FullMethodName:       auth.LevelVerified,
		crowdsecv1.CrowdSecService_GetScenarioHub_FullMethodName:     auth.LevelVerified,
		crowdsecv1.CrowdSecService_InstallScenario_FullMethodName:    auth.LevelVerified,
		crowdsecv1.CrowdSecService_RemoveScenario_FullMethodName:     auth.LevelVerified,
		crowdsecv1.CrowdSecService_GetServiceStatus_FullMethodName:   auth.LevelVerified,
		crowdsecv1.CrowdSecService_ToggleService_FullMethodName:      auth.LevelVerified,
		crowdsecv1.CrowdSecService_ToggleScenario_FullMethodName:     auth.LevelVerified,
		crowdsecv1.CrowdSecService_GetAlerts_FullMethodName:          auth.LevelVerified,
		crowdsecv1.CrowdSecService_Reload_FullMethodName:             auth.LevelVerified,
		// dashboard: require_verified (tenants see their own data via host-filter scoping)
		dashboardv1.DashboardService_GetMetrics_FullMethodName:              auth.LevelVerified,
		dashboardv1.DashboardService_GetTraffic_FullMethodName:              auth.LevelVerified,
		dashboardv1.DashboardService_GetGeoipMap_FullMethodName:             auth.LevelVerified,
		dashboardv1.DashboardService_GetGeoipUnresolved_FullMethodName:      auth.LevelVerified,
		dashboardv1.DashboardService_GetThreatOrigins_FullMethodName:        auth.LevelVerified,
		dashboardv1.DashboardService_GetEvents_FullMethodName:               auth.LevelVerified,
		dashboardv1.DashboardService_GetWafEventsTimeline_FullMethodName:    auth.LevelVerified,
		dashboardv1.DashboardService_GetTopRules_FullMethodName:             auth.LevelVerified,
		dashboardv1.DashboardService_GetSeverityDistribution_FullMethodName: auth.LevelVerified,
		dashboardv1.DashboardService_GetTopAttackingIps_FullMethodName:      auth.LevelVerified,
		dashboardv1.DashboardService_GetAnomalyScore_FullMethodName:         auth.LevelVerified,
		dashboardv1.DashboardService_GetTopTags_FullMethodName:              auth.LevelVerified,
		dashboardv1.DashboardService_GetTopUris_FullMethodName:              auth.LevelVerified,
		dashboardv1.DashboardService_GetTopRuleFiles_FullMethodName:         auth.LevelVerified,
		dashboardv1.DashboardService_GetStatusCodes_FullMethodName:          auth.LevelVerified,
		dashboardv1.DashboardService_GetTopUserAgents_FullMethodName:        auth.LevelVerified,
		dashboardv1.DashboardService_GetTrafficVolume_FullMethodName:        auth.LevelVerified,
		dashboardv1.DashboardService_GetRequestsPerSecond_FullMethodName:    auth.LevelVerified,
		dashboardv1.DashboardService_GetRequestsByCountry_FullMethodName:    auth.LevelVerified,
		dashboardv1.DashboardService_GetTopClientIps_FullMethodName:         auth.LevelVerified,
		dashboardv1.DashboardService_GetTestTraffic_FullMethodName:          auth.LevelVerified,
		// ssl: require_verified (tenant-scoped; service enforces current_tenant)
		sslv1.SSLService_GetCertificateStatus_FullMethodName:  auth.LevelVerified,
		sslv1.SSLService_RequestCertificate_FullMethodName:    auth.LevelVerified,
		sslv1.SSLService_RegenerateCertificate_FullMethodName: auth.LevelVerified,
		// monitoring + admin: absent from map → default LevelAdmin (fail closed)
	}
	grpcSrv := grpc.NewServer(grpc.ChainUnaryInterceptor(auth.NewInterceptor(dec, policy, authLevels)))
	monitoringv1.RegisterMonitoringServiceServer(grpcSrv, monitoring.NewService(engine))
	tfs := tenantfs.New(getenvOr("WAF_TENANTS_DIR", "/var/lib/waf/tenants"))
	adminv1.RegisterAdminServiceServer(grpcSrv, admin.NewService(st, tfs, angieReloader{log: log}))
	msCfg := modsec.New(getenvOr("WAF_MODSEC_DIR", "/app/etc/angie/modsecurity"))
	modsecurityv1.RegisterModSecurityServiceServer(grpcSrv, modsecurity.NewService(msCfg, modsecReloader{}))
	crowdsecv1.RegisterCrowdSecServiceServer(grpcSrv, csSvc)
	// ── Dashboard (ClickHouse analytics) ─────────────────────────────────────
	// chdash.NewClient is non-fatal: Redis unavailability is logged but not
	// fatal. ClickHouse is opened per-query, so boot succeeds without CH.
	chClient := chdash.NewClient()
	dashboardv1.RegisterDashboardServiceServer(grpcSrv, dashboardapi.New(chClient, st))
	// ── SSL / certificates ────────────────────────────────────────────────────
	certManager := certs.New()
	sslv1.RegisterSSLServiceServer(grpcSrv, sslapi.New(st, certManager))

	go func() {
		log.Info("grpc serving", "addr", grpcAddr)
		if err := grpcSrv.Serve(grpcLis); err != nil {
			log.Error("grpc serve failed", "err", err)
		}
	}()

	mux, err := server.NewGatewayMux(ctx, grpcAddr)
	if err != nil {
		log.Error("gateway init failed", "err", err)
		os.Exit(1)
	}

	rest := &http.Server{Addr: cfg.GRPCAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		log.Info("rest gateway serving", "addr", cfg.GRPCAddr)
		if err := rest.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("rest serve failed", "err", err)
		}
	}()

	metrics := &http.Server{Addr: cfg.MetricsAddr, Handler: observability.MetricsHandler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = metrics.ListenAndServe() }()

	// ── Background CrowdSec blocked-IPs sync loop ─────────────────────────────
	// Mirrors Python run_blocked_ips_sync_forever. Best-effort: never crashes
	// the server on docker/cscli errors.
	go runBlockedIPsSyncLoop(ctx, log, syncer, storeConnSource{st})

	<-ctx.Done()
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = rest.Shutdown(shutdownCtx)
	_ = metrics.Shutdown(shutdownCtx)
	grpcSrv.GracefulStop()
}

// runBlockedIPsSyncLoop is a faithful Go port of Python run_blocked_ips_sync_forever.
// It runs until ctx is cancelled, ticking every WAF_CROWDSEC_SYNC_INTERVAL seconds
// (default 15). Each tick:
//  1. Loads the live connection list from the DB.
//  2. Writes the connections registry (connections.json) so the syncer can read it.
//  3. Calls SyncBlockedIPsConf to refresh per-connection blocked_ips.conf files.
//
// Errors are logged and the loop continues (best-effort).
func runBlockedIPsSyncLoop(ctx context.Context, log *slog.Logger, syncer *crowdsec.Syncer, src storeConnSource) {
	interval := 15 * time.Second
	if s := os.Getenv("WAF_CROWDSEC_SYNC_INTERVAL"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			interval = time.Duration(n) * time.Second
		}
	}
	log.Info("crowdsec blocked-IPs sync starting", "interval", interval)

	for {
		select {
		case <-ctx.Done():
			log.Info("crowdsec blocked-IPs sync stopped")
			return
		default:
		}

		func() {
			csConns, err := src.ListConnections(ctx)
			if err != nil {
				log.Warn("crowdsec sync: ListConnections failed", "err", err)
				return
			}

			if err := syncer.WriteConnectionsRegistry(csConns); err != nil {
				log.Warn("crowdsec sync: WriteConnectionsRegistry failed", "err", err)
				return
			}

			if err := syncer.SyncBlockedIPsConf(ctx); err != nil {
				log.Warn("crowdsec sync: SyncBlockedIPsConf failed", "err", err)
				// Non-fatal: cscli/docker may be unreachable. Loop continues.
			}
		}()

		select {
		case <-ctx.Done():
			log.Info("crowdsec blocked-IPs sync stopped")
			return
		case <-time.After(interval):
		}
	}
}

// ── Adapters ─────────────────────────────────────────────────────────────────

// storeConnSource adapts *store.Store to crowdsec.ConnectionSource.
// store.Connection and crowdsec.Connection have identical fields; we convert
// between them here to avoid an import cycle between store and crowdsec packages.
type storeConnSource struct{ s *store.Store }

func (a storeConnSource) ListConnections(ctx context.Context) ([]crowdsec.Connection, error) {
	rows, err := a.s.ListConnections(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]crowdsec.Connection, 0, len(rows))
	for _, r := range rows {
		out = append(out, crowdsec.Connection{
			ID:       r.ID,
			TenantID: r.TenantID,
			Name:     r.Name,
			Domain:   r.Domain,
			Enabled:  r.Enabled,
			Status:   r.Status,
		})
	}
	return out, nil
}

//

// angieReloader wraps angie.Reload to satisfy admin.Reloader and crowdsec.AngieReloader.
type angieReloader struct{ log *slog.Logger }

func (a angieReloader) Reload(ctx context.Context) { angie.Reload(ctx, a.log) }

// modsecReloader wraps angie.ReloadVerbose to satisfy modsecurity.Reloader.
type modsecReloader struct{}

func (modsecReloader) ReloadVerbose(ctx context.Context) (bool, string) {
	return angie.ReloadVerbose(ctx)
}

// csRunnerOrNoop returns r as a crowdsec.CSCLIRunner (nil-safe via noopCSRunner).
func csRunnerOrNoop(r *cscli.Runner) crowdsec.CSCLIRunner {
	if r == nil {
		return noopCSRunner{}
	}
	return r
}

// noopCSRunner is used when cscli.New() fails (Docker not available in dev).
type noopCSRunner struct{}

func (noopCSRunner) RunJSON(_ context.Context, _ ...string) (json.RawMessage, error) {
	return nil, nil
}

// noopRunner satisfies crowdsecapi.Runner with no-ops.
type noopRunner struct{}

func (noopRunner) Run(_ context.Context, _ ...string) (int, string, string, error) {
	return 1, "", "crowdsec runner not available", nil
}
func (noopRunner) RunJSON(_ context.Context, _ ...string) (json.RawMessage, error) {
	return nil, nil
}

// getenvOr returns the environment variable k or def if it is empty/unset.
func getenvOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
