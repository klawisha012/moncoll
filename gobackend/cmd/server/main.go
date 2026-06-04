package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"

	adminv1 "github.com/zwarder/waf/gobackend/gen/admin/v1"
	authv1 "github.com/zwarder/waf/gobackend/gen/auth/v1"
	connectionsv1 "github.com/zwarder/waf/gobackend/gen/connections/v1"
	crowdsecv1 "github.com/zwarder/waf/gobackend/gen/crowdsec/v1"
	dashboardv1 "github.com/zwarder/waf/gobackend/gen/dashboard/v1"
	modsecurityv1 "github.com/zwarder/waf/gobackend/gen/modsecurity/v1"
	monitoringv1 "github.com/zwarder/waf/gobackend/gen/monitoring/v1"
	realtimev1 "github.com/zwarder/waf/gobackend/gen/realtime/v1"
	sslv1 "github.com/zwarder/waf/gobackend/gen/ssl/v1"
	testsv1 "github.com/zwarder/waf/gobackend/gen/tests/v1"
	"github.com/zwarder/waf/gobackend/internal/admin"
	"github.com/zwarder/waf/gobackend/internal/angie"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/authapi"
	"github.com/zwarder/waf/gobackend/internal/bootstrap"
	"github.com/zwarder/waf/gobackend/internal/captcha"
	"github.com/zwarder/waf/gobackend/internal/centrifugo"
	"github.com/zwarder/waf/gobackend/internal/certs"
	"github.com/zwarder/waf/gobackend/internal/chdash"
	"github.com/zwarder/waf/gobackend/internal/config"
	"github.com/zwarder/waf/gobackend/internal/conndns"
	"github.com/zwarder/waf/gobackend/internal/connectionsapi"
	"github.com/zwarder/waf/gobackend/internal/crowdsec"
	"github.com/zwarder/waf/gobackend/internal/crowdsecapi"
	"github.com/zwarder/waf/gobackend/internal/cscli"
	"github.com/zwarder/waf/gobackend/internal/dashboardapi"
	"github.com/zwarder/waf/gobackend/internal/email"
	"github.com/zwarder/waf/gobackend/internal/migrate"
	"github.com/zwarder/waf/gobackend/internal/modsec"
	"github.com/zwarder/waf/gobackend/internal/modsecurity"
	"github.com/zwarder/waf/gobackend/internal/monitoring"
	"github.com/zwarder/waf/gobackend/internal/oauth"
	"github.com/zwarder/waf/gobackend/internal/observability"
	"github.com/zwarder/waf/gobackend/internal/realtime"
	"github.com/zwarder/waf/gobackend/internal/realtimeapi"
	"github.com/zwarder/waf/gobackend/internal/server"
	"github.com/zwarder/waf/gobackend/internal/sslapi"
	"github.com/zwarder/waf/gobackend/internal/store"
	"github.com/zwarder/waf/gobackend/internal/tenantfs"
	"github.com/zwarder/waf/gobackend/internal/testsapi"
)

func main() {
	log := observability.NewLogger()

	// ── Subcommand dispatch ───────────────────────────────────────────────────
	// Usage: server create-admin [flags]
	//        server [normal server flags — currently none]
	if len(os.Args) >= 2 && os.Args[1] == "create-admin" {
		runCreateAdmin(log, os.Args[2:])
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	runServer(ctx, log)
}

// runCreateAdmin implements the "server create-admin" subcommand.
//
// Flags:
//
//	-email    admin email  (also: WAF_ADMIN_EMAIL env)
//	-password admin password (also: WAF_ADMIN_PASSWORD env)
//
// Mirrors Python's create_admin_cmd behaviour:
//   - raises error (exit 1) if the email already exists (no upsert)
//   - prints "Created admin id=<id> email=<email>" on success
func runCreateAdmin(log *slog.Logger, args []string) {
	fs := flag.NewFlagSet("create-admin", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: server create-admin -email EMAIL -password PASSWORD\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nEnvironment:\n")
		fmt.Fprintf(os.Stderr, "  WAF_ADMIN_EMAIL      admin email (fallback when -email is not given)\n")
		fmt.Fprintf(os.Stderr, "  WAF_ADMIN_PASSWORD   admin password (fallback when -password is not given)\n")
		fmt.Fprintf(os.Stderr, "  WAF_POSTGRES_DSN     postgres connection string (required)\n")
	}

	emailFlag := fs.String("email", "", "Admin email address")
	passwordFlag := fs.String("password", "", "Admin password")

	if err := fs.Parse(args); err != nil {
		// ContinueOnError: fs.Parse prints the error and returns it.
		os.Exit(2)
	}

	// Fall back to env vars (mirrors Python: typer.Option default + env lookup).
	email := *emailFlag
	if email == "" {
		email = os.Getenv("WAF_ADMIN_EMAIL")
	}
	password := *passwordFlag
	if password == "" {
		password = os.Getenv("WAF_ADMIN_PASSWORD")
	}

	if email == "" {
		fmt.Fprintln(os.Stderr, "Error: -email or WAF_ADMIN_EMAIL is required")
		fs.Usage()
		os.Exit(2)
	}
	if password == "" {
		fmt.Fprintln(os.Stderr, "Error: -password or WAF_ADMIN_PASSWORD is required")
		fs.Usage()
		os.Exit(2)
	}

	// Load only the DSN — PASETO key is not needed for this subcommand.
	dsn := os.Getenv("WAF_POSTGRES_DSN")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "Error: WAF_POSTGRES_DSN is required")
		os.Exit(1)
	}

	ctx := context.Background()

	// Ensure schema before touching any tables.
	if err := migrate.Run(dsn, log); err != nil {
		fmt.Fprintf(os.Stderr, "Error: DB migration failed: %v\n", err)
		os.Exit(1)
	}

	st, err := store.New(ctx, dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: postgres connect failed: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()

	res, err := bootstrap.CreateAdmin(ctx, st, email, password)
	if err != nil {
		if errors.Is(err, bootstrap.ErrEmailTaken) {
			fmt.Fprintf(os.Stderr, "Error: email %q is already in use.\n", email)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Created admin id=%d email=%s\n", res.ID, res.Email)
}

// runServer is the normal server startup path, extracted so main() stays clean.
func runServer(ctx context.Context, log *slog.Logger) {
	cfg, err := config.Load()
	if err != nil {
		log.Error("config load failed", "err", err)
		os.Exit(1)
	}

	// ── DB migrations ─────────────────────────────────────────────────────────
	// Run before opening the store so the schema is guaranteed to exist.
	// Set WAF_SKIP_MIGRATE=1 to bypass (for environments where migrations are
	// managed externally, e.g. CI, helm pre-install jobs).
	if os.Getenv("WAF_SKIP_MIGRATE") != "1" {
		if err := migrate.Run(cfg.PostgresDSN, log); err != nil {
			log.Error("DB migration failed", "err", err)
			os.Exit(1)
		}
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
	issuer := auth.NewIssuer(cfg.PasetoKey)
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
		// connections: require_verified (tenant-scoped; service enforces TenantID)
		// GetEdgeInfo is also public-ish (no sensitive data) but we keep it
		// consistent with the other 10 methods.
		connectionsv1.ConnectionsService_GetEdgeInfo_FullMethodName:      auth.LevelVerified,
		connectionsv1.ConnectionsService_ListConnections_FullMethodName:  auth.LevelVerified,
		connectionsv1.ConnectionsService_GetConnection_FullMethodName:    auth.LevelVerified,
		connectionsv1.ConnectionsService_CreateConnection_FullMethodName: auth.LevelVerified,
		connectionsv1.ConnectionsService_UpdateConnection_FullMethodName: auth.LevelVerified,
		connectionsv1.ConnectionsService_DeleteConnection_FullMethodName: auth.LevelVerified,
		connectionsv1.ConnectionsService_ProbeConnection_FullMethodName:  auth.LevelVerified,
		// reload_connections is require_admin in the Python router — keep it
		// admin-only (LevelAdmin) rather than letting any verified tenant trigger
		// a global Angie config regen + reload.
		connectionsv1.ConnectionsService_ReloadConnections_FullMethodName:        auth.LevelAdmin,
		connectionsv1.ConnectionsService_GetConnectionSecurity_FullMethodName:    auth.LevelVerified,
		connectionsv1.ConnectionsService_UpdateConnectionSecurity_FullMethodName: auth.LevelVerified,
		// realtime: GetToken is require_verified (mirrors Python require_verified dep).
		realtimev1.RealtimeService_GetToken_FullMethodName: auth.LevelVerified,
		// tests: all 4 methods are require_verified (clients only; tenant enforced in-handler)
		testsv1.TestsService_GetCatalog_FullMethodName:          auth.LevelVerified,
		testsv1.TestsService_RunTest_FullMethodName:             auth.LevelVerified,
		testsv1.TestsService_GetCrowdsecCatalog_FullMethodName:  auth.LevelVerified,
		testsv1.TestsService_RunCrowdsecScenario_FullMethodName: auth.LevelVerified,
		// auth: all methods are LevelPublic — public endpoints (login/signup/...)
		// have no session yet, and the cookie-validating endpoints (me, totp/setup,
		// totp/confirm) read + verify their OWN cookie inside the handler.
		authv1.AuthService_GetProviders_FullMethodName:   auth.LevelPublic,
		authv1.AuthService_Signup_FullMethodName:         auth.LevelPublic,
		authv1.AuthService_VerifyEmail_FullMethodName:    auth.LevelPublic,
		authv1.AuthService_Login_FullMethodName:          auth.LevelPublic,
		authv1.AuthService_Logout_FullMethodName:         auth.LevelPublic,
		authv1.AuthService_Me_FullMethodName:             auth.LevelPublic,
		authv1.AuthService_ForgotPassword_FullMethodName: auth.LevelPublic,
		authv1.AuthService_ResetPassword_FullMethodName:  auth.LevelPublic,
		authv1.AuthService_TotpSetup_FullMethodName:      auth.LevelPublic,
		authv1.AuthService_TotpConfirm_FullMethodName:    auth.LevelPublic,
		authv1.AuthService_OauthStart_FullMethodName:     auth.LevelPublic,
		authv1.AuthService_OauthCallback_FullMethodName:  auth.LevelPublic,
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

	// ── Connections (domain proxy lifecycle + ACME orchestration) ─────────────
	connSvc := connectionsapi.New(
		connStoreAdapter{st},
		conndns.NetResolver{},
		connectionsapi.AngiecfgAdapter{},
		connectionsapi.CertsManagerAdapter{M: certManager},
		angieReloader{log: log},
		log,
	)
	connectionsv1.RegisterConnectionsServiceServer(grpcSrv, connSvc)

	// ── Auth service (11 endpoints) ───────────────────────────────────────────
	authCfg := authapi.Config{
		PasetoKey:      cfg.PasetoKey,
		CookieSecure:   envBool("WAF_COOKIE_SECURE", true),
		PublicBaseURL:  os.Getenv("WAF_PUBLIC_BASE_URL"),
		GoogleEnabled:  oauthEnabled("GOOGLE"),
		GitHubEnabled:  oauthEnabled("GITHUB"),
		CaptchaSiteKey: os.Getenv("WAF_TURNSTILE_SITE_KEY"),
		CaptchaConfig:  os.Getenv("WAF_TURNSTILE_SECRET_KEY") != "",
		SMTPConfigured: os.Getenv("WAF_SMTP_HOST") != "",
		GoogleRedirect: os.Getenv("WAF_OAUTH_GOOGLE_REDIRECT_URI"),
		GitHubRedirect: os.Getenv("WAF_OAUTH_GITHUB_REDIRECT_URI"),
	}
	authSvc := authapi.New(
		st,
		issuer,
		dec,
		email.NewSender(),
		captcha.NewVerifier(),
		oauthFactory{},
		authCfg,
		log,
	)
	authv1.RegisterAuthServiceServer(grpcSrv, authSvc)

	// ── Realtime (Centrifugo token endpoint) ──────────────────────────────────
	centPub := centrifugo.NewPublisher()
	realtimeSvc := realtimeapi.New(centrifugo.MintConnectionToken)
	realtimev1.RegisterRealtimeServiceServer(grpcSrv, realtimeSvc)

	// ── Tests (WAF probe runner) ──────────────────────────────────────────────
	// manifest.json lives next to the binary in the container (/app/manifest.json)
	// or can be overridden via WAF_TESTS_MANIFEST_PATH.
	testsCatalog := testsapi.NewFileCatalogLoader(getenvOr("WAF_TESTS_MANIFEST_PATH", "/app/manifest.json"))
	testsStore := testsapi.NewStoreAdapter(st)
	testsProber := testsapi.NewHTTPProber(3 * time.Second)
	testsCHPoller := testsapi.NewCHClickHousePoller("") // resolves from env
	var testsCSRunner testsapi.CSRunner
	if csRunner != nil {
		testsCSRunner = testsapi.NewCscliCSRunner(csRunner)
	} else {
		testsCSRunner = testsapi.NewCscliCSRunner(noopRunner{})
	}
	testsSvc := testsapi.New(testsCatalog, testsStore, testsProber, testsCHPoller, testsCSRunner, log)
	testsv1.RegisterTestsServiceServer(grpcSrv, testsSvc)

	// Start the background connections poller (best-effort, never crashes server)
	connPoller := connectionsapi.NewPoller(
		connStoreAdapter{st},
		conndns.NetResolver{},
		connectionsapi.AngiecfgAdapter{},
		connectionsapi.CertsManagerAdapter{M: certManager},
		angieReloader{log: log},
		log,
	)
	go connPoller.Run(ctx)

	// ── Realtime consumer (Redis pub/sub → aggregator → Centrifugo) ───────────
	// Best-effort: Redis/Centrifugo errors are logged and retried; the consumer
	// never crashes the server. Single-instance: the Python backend is being
	// removed so there is exactly one subscriber.
	rtRedis := realtime.NewRedisClient()
	rtConsumer := realtime.New(rtRedis, centPub, log)
	go rtConsumer.RunForever(ctx)

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

// envBool parses a boolean env var (true/1/yes), defaulting to def when unset.
// Mirrors pydantic's bool coercion for WAF_COOKIE_SECURE.
func envBool(k string, def bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

// oauthEnabled reports whether all three WAF_OAUTH_<P>_* env vars are set,
// mirroring config.py oauth_<provider>_enabled.
func oauthEnabled(p string) bool {
	prefix := "WAF_OAUTH_" + p + "_"
	return os.Getenv(prefix+"CLIENT_ID") != "" &&
		os.Getenv(prefix+"CLIENT_SECRET") != "" &&
		os.Getenv(prefix+"REDIRECT_URI") != ""
}

// oauthFactory adapts oauth.NewProvider to authapi.OAuthProviderFactory.
type oauthFactory struct{}

func (oauthFactory) Provider(name string) (authapi.OAuthProvider, bool) {
	p, ok := oauth.NewProvider(name)
	if !ok {
		return nil, false
	}
	return p, true
}

// connStoreAdapter adapts *store.Store to connectionsapi.Store.
// The adapter just delegates — both use identical method signatures.
type connStoreAdapter struct{ s *store.Store }

func (a connStoreAdapter) ListConnectionsFull(ctx context.Context, tenantID int64) ([]store.Connection, error) {
	return a.s.ListConnectionsFull(ctx, tenantID)
}
func (a connStoreAdapter) GetConnectionFull(ctx context.Context, tenantID, connID int64) (*store.Connection, error) {
	return a.s.GetConnectionFull(ctx, tenantID, connID)
}
func (a connStoreAdapter) GetConnectionInternal(ctx context.Context, connID int64) (*store.Connection, error) {
	return a.s.GetConnectionInternal(ctx, connID)
}
func (a connStoreAdapter) CreateConnection(ctx context.Context, c *store.Connection) (*store.Connection, error) {
	return a.s.CreateConnection(ctx, c)
}
func (a connStoreAdapter) UpdateConnection(ctx context.Context, tenantID, connID int64, upd store.ConnectionUpdate) (*store.Connection, error) {
	return a.s.UpdateConnection(ctx, tenantID, connID, upd)
}
func (a connStoreAdapter) DeleteConnection(ctx context.Context, tenantID, connID int64) error {
	return a.s.DeleteConnection(ctx, tenantID, connID)
}
func (a connStoreAdapter) UpdateSecurity(ctx context.Context, tenantID, connID int64, modsecState string, geoipDenied []string, crowdsecActive bool) (*store.Connection, error) {
	return a.s.UpdateSecurity(ctx, tenantID, connID, modsecState, geoipDenied, crowdsecActive)
}
func (a connStoreAdapter) UpdateProbeState(ctx context.Context, tenantID, connID int64, p store.PollerState) (*store.Connection, error) {
	return a.s.UpdateProbeState(ctx, tenantID, connID, p)
}
func (a connStoreAdapter) ListConnectionsForPoll(ctx context.Context) ([]store.Connection, error) {
	return a.s.ListConnectionsForPoll(ctx)
}
func (a connStoreAdapter) UpdatePollerState(ctx context.Context, connID int64, p store.PollerState) (*store.Connection, error) {
	return a.s.UpdatePollerState(ctx, connID, p)
}
