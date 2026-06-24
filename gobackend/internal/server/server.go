package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/grpc"

	adminv1 "github.com/zwarder/waf/gobackend/gen/admin/v1"
	authv1 "github.com/zwarder/waf/gobackend/gen/auth/v1"
	connectionsv1 "github.com/zwarder/waf/gobackend/gen/connections/v1"
	crowdsecv1 "github.com/zwarder/waf/gobackend/gen/crowdsec/v1"
	dashboardv1 "github.com/zwarder/waf/gobackend/gen/dashboard/v1"
	modsecurityv1 "github.com/zwarder/waf/gobackend/gen/modsecurity/v1"
	monitoringv1 "github.com/zwarder/waf/gobackend/gen/monitoring/v1"
	notificationsv1 "github.com/zwarder/waf/gobackend/gen/notifications/v1"
	realtimev1 "github.com/zwarder/waf/gobackend/gen/realtime/v1"
	sslv1 "github.com/zwarder/waf/gobackend/gen/ssl/v1"
	teamsv1 "github.com/zwarder/waf/gobackend/gen/teams/v1"
	testsv1 "github.com/zwarder/waf/gobackend/gen/tests/v1"
	"github.com/zwarder/waf/gobackend/internal/admin"
	"github.com/zwarder/waf/gobackend/internal/angie"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/authapi"
	"github.com/zwarder/waf/gobackend/internal/bootstrap"
	"github.com/zwarder/waf/gobackend/internal/captcha"
	"github.com/zwarder/waf/gobackend/internal/centrifugo"
	"github.com/zwarder/waf/gobackend/internal/certexpiry"
	"github.com/zwarder/waf/gobackend/internal/certs"
	"github.com/zwarder/waf/gobackend/internal/chdash"
	"github.com/zwarder/waf/gobackend/internal/config"
	"github.com/zwarder/waf/gobackend/internal/conndns"
	"github.com/zwarder/waf/gobackend/internal/connectionsapi"
	"github.com/zwarder/waf/gobackend/internal/crowdsec"
	"github.com/zwarder/waf/gobackend/internal/crowdsecapi"
	"github.com/zwarder/waf/gobackend/internal/cscli"
	"github.com/zwarder/waf/gobackend/internal/dashboardapi"
	"github.com/zwarder/waf/gobackend/internal/edge"
	"github.com/zwarder/waf/gobackend/internal/email"
	"github.com/zwarder/waf/gobackend/internal/migrate"
	"github.com/zwarder/waf/gobackend/internal/modsec"
	"github.com/zwarder/waf/gobackend/internal/modsecurity"
	"github.com/zwarder/waf/gobackend/internal/monitoring"
	"github.com/zwarder/waf/gobackend/internal/notificationsapi"
	"github.com/zwarder/waf/gobackend/internal/notify"
	"github.com/zwarder/waf/gobackend/internal/oauth"
	"github.com/zwarder/waf/gobackend/internal/observability"
	"github.com/zwarder/waf/gobackend/internal/realtime"
	"github.com/zwarder/waf/gobackend/internal/realtimeapi"
	"github.com/zwarder/waf/gobackend/internal/sslapi"
	"github.com/zwarder/waf/gobackend/internal/storage"
	"github.com/zwarder/waf/gobackend/internal/store"
	"github.com/zwarder/waf/gobackend/internal/teamsapi"
	"github.com/zwarder/waf/gobackend/internal/tenantfs"
	"github.com/zwarder/waf/gobackend/internal/testsapi"
)

// Server coordinates the lifecycle of WAF services, gRPC server, and REST gateway.
type Server struct {
	cfg        *config.Config
	log        *slog.Logger
	store      *store.Store
	csRunner   *cscli.Runner
	grpcSrv    *grpc.Server
	restSrv    *http.Server
	metricsSrv *http.Server
	metrics    *observability.Metrics
	tp         *sdktrace.TracerProvider
}

// New constructs a Server instance.
func New(cfg *config.Config, log *slog.Logger) *Server {
	return &Server{cfg: cfg, log: log}
}

// Start boots the database, runs migrations, registers services, and starts listeners.
func (s *Server) Start(ctx context.Context) error {
	// 0. Observability: RED metrics registry + OpenTelemetry tracer. The tracer
	// is off (never-sample) unless an OTLP endpoint is configured, so this adds
	// no mandatory external dependency.
	s.metrics = observability.NewMetrics()
	if tp, err := observability.InitTracer(ctx, "waf-gobackend"); err != nil {
		s.log.Warn("otel tracer init failed; continuing without tracing", "err", err)
	} else {
		s.tp = tp
	}

	// 1. Run migrations unless explicitly skipped.
	if os.Getenv("WAF_SKIP_MIGRATE") != "1" {
		if err := migrate.Run(s.cfg.PostgresDSN, s.log); err != nil {
			return fmt.Errorf("DB migration failed: %w", err)
		}
	}

	// 2. Connect to the store.
	st, err := store.New(ctx, s.cfg.PostgresDSN, s.metrics)
	if err != nil {
		return fmt.Errorf("postgres connect failed: %w", err)
	}
	s.store = st

	// 2b. Idempotent system provisioning (non-fatal): ensure the system tenant,
	// make every platform admin an owner-member of it, and — only when
	// WAF_SELF_SITE_DOMAIN is set — ensure the self-connection row. The returned
	// systemTenantID scopes admins' client tabs in the auth interceptor. A
	// failure here logs and continues: the platform must still boot.
	systemTenantID, provErr := bootstrap.EnsureSystemProvisioning(ctx, s.log, st, bootstrap.LoadSelfSiteConfig())
	if provErr != nil {
		s.log.Error("system provisioning failed (continuing)", "err", provErr)
	}
	// Connections in the system tenant (the WAF's own self-connection) exclude
	// their control-plane traffic (panel /api + realtime WS) from dashboards.
	connectionsapi.SetSelfTenantID(systemTenantID)

	// 3. Docker connection for monitoring.
	engine, err := monitoring.NewDockerEngine()
	if err != nil {
		return fmt.Errorf("docker client failed: %w", err)
	}

	// 4. Initialize cscli runner & syncer.
	csRunner, err := cscli.New()
	if err != nil {
		s.log.Warn("cscli runner init failed (crowdsec features will be degraded)", "err", err)
		csRunner = nil
	}
	s.csRunner = csRunner

	var csCliRunner cscli.Runnable = cscli.NoopRunner{}
	if csRunner != nil {
		csCliRunner = csRunner
	}

	// Storage seam for shared file state (FR-001, specs/001-horizontal-scaling).
	// local (default) maps canonical keys to live Angie paths (behaviour
	// unchanged); s3 enables horizontal scaling. Publisher records each change
	// set as a manifest generation.
	storageStore, err := buildStore(s.cfg.Storage)
	if err != nil {
		return fmt.Errorf("storage backend init failed: %w", err)
	}
	statePublisher := storage.NewPublisher(storageStore)
	statePublisher.OnPublish = s.metrics.SetPublishedGeneration // SC-007 convergence gauge
	s.log.Info("storage backend selected", "mode", s.cfg.Storage.Backend)

	// Local tenants base for filesystem-coupled guards/renames (empty in s3 mode).
	s3Mode := s.cfg.Storage.Backend == "s3"
	localTenantsBase := ""
	if !s3Mode {
		localTenantsBase = getenvOr("WAF_TENANTS_DIR", "/var/lib/waf/tenants")
	}

	syncer := crowdsec.NewSyncer(csCliRunner, angie.Reloader{Log: s.log, S3Mode: s3Mode}, crowdsec.StoreConnSource{Store: st}, storageStore, statePublisher, localTenantsBase)

	// 5. Initialize services.
	monitorSvc := monitoring.NewService(engine)

	tfs := tenantfs.New(storageStore, statePublisher, localTenantsBase)
	adminSvc := admin.NewService(st, tfs, angie.Reloader{Log: s.log, S3Mode: s3Mode})
	msCfg := modsec.New(storageStore, statePublisher)
	modsecSvc := modsecurity.NewService(msCfg, angie.Reloader{Log: s.log, S3Mode: s3Mode})

	centPub := centrifugo.NewPublisher()
	teamsNotifier := notify.New(st, centPub, s.log)
	teamsSvc := teamsapi.New(st, email.NewSender(), os.Getenv("WAF_PUBLIC_BASE_URL"), s.log, teamsNotifier)

	var csSvc *crowdsecapi.Service
	if csRunner != nil {
		csSvc = crowdsecapi.New(csRunner, syncer, teamsNotifier)
	} else {
		csSvc = crowdsecapi.New(cscli.NoopRunner{}, syncer, teamsNotifier)
	}

	chClient := chdash.NewClient(s.metrics)
	dashSvc := dashboardapi.New(chClient, st)

	certManager := certs.New(storageStore, statePublisher)
	sslSvc := sslapi.New(st, certManager)

	// One DNS resolver, shared by the edge resolver, the connections service,
	// and the background poller. WAF_DNS_SERVERS routes TXT/A lookups to public
	// resolvers so verification sees freshly published records (the container's
	// local resolver can negatively cache _waf-verify.<domain>).
	dnsResolver := conndns.NewNetResolverFromEnv()
	edgeResolver := edge.NewResolverFromEnv(dnsResolver)
	connSvc := connectionsapi.New(
		st,
		conndns.NewVerifier(dnsResolver),
		edgeResolver,
		connectionsapi.AngiecfgAdapter{Store: storageStore, Pub: statePublisher},
		connectionsapi.CertsManagerAdapter{M: certManager},
		angie.Reloader{Log: s.log, S3Mode: s3Mode},
		s.log,
	)

	authCfg := authapi.Config{
		PasetoKey:      s.cfg.PasetoKey,
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
	dec := auth.NewDecoder(s.cfg.PasetoKey)
	issuer := auth.NewIssuer(s.cfg.PasetoKey)
	policy := auth.NewPolicy(st)
	authSvc := authapi.New(
		st,
		issuer,
		dec,
		email.NewSender(),
		captcha.NewVerifier(),
		oauthFactory{},
		authCfg,
		s.log,
	)

	realtimeSvc := realtimeapi.New(centrifugo.MintConnectionToken)

	testsCatalog := testsapi.NewFileCatalogLoader(getenvOr("WAF_TESTS_MANIFEST_PATH", "/app/manifest.json"))
	if cat, err := testsCatalog.Load(); err == nil {
		s.log.Info("testsapi: catalog loaded", "tests", len(cat.Tests))
	}
	testsStore := testsapi.NewStoreAdapter(st)
	testsProber := testsapi.NewHTTPProber(3 * time.Second)
	testsCHPoller := testsapi.NewCHClickHousePoller("")
	var testsCSRunner testsapi.CSRunner
	if csRunner != nil {
		testsCSRunner = testsapi.NewCscliCSRunner(csRunner)
	} else {
		testsCSRunner = testsapi.NewCscliCSRunner(cscli.NoopRunner{})
	}
	testsSvc := testsapi.New(testsCatalog, testsStore, testsProber, testsCHPoller, testsCSRunner, s.log)

	notifSvc := notificationsapi.New(st, s.log)

	// 6. Build dynamic authLevels map from registered services.
	authLevels := make(map[string]auth.Level)
	services := []any{
		monitorSvc,
		adminSvc,
		modsecSvc,
		csSvc,
		dashSvc,
		sslSvc,
		connSvc,
		teamsSvc,
		authSvc,
		realtimeSvc,
		testsSvc,
		notifSvc,
	}
	for _, svc := range services {
		if auther, ok := svc.(auth.AuthorizableService); ok {
			for method, level := range auther.AuthLevels() {
				authLevels[method] = level
			}
		}
	}

	// 7. Setup gRPC server.
	const grpcAddr = "127.0.0.1:9090"
	grpcLis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		return fmt.Errorf("grpc listen failed: %w", err)
	}

	s.grpcSrv = grpc.NewServer(grpc.ChainUnaryInterceptor(auth.NewInterceptor(dec, policy, authLevels, systemTenantID)))
	monitoringv1.RegisterMonitoringServiceServer(s.grpcSrv, monitorSvc)
	adminv1.RegisterAdminServiceServer(s.grpcSrv, adminSvc)
	modsecurityv1.RegisterModSecurityServiceServer(s.grpcSrv, modsecSvc)
	crowdsecv1.RegisterCrowdSecServiceServer(s.grpcSrv, csSvc)
	dashboardv1.RegisterDashboardServiceServer(s.grpcSrv, dashSvc)
	sslv1.RegisterSSLServiceServer(s.grpcSrv, sslSvc)
	connectionsv1.RegisterConnectionsServiceServer(s.grpcSrv, connSvc)
	teamsv1.RegisterTeamsServiceServer(s.grpcSrv, teamsSvc)
	authv1.RegisterAuthServiceServer(s.grpcSrv, authSvc)
	realtimev1.RegisterRealtimeServiceServer(s.grpcSrv, realtimeSvc)
	testsv1.RegisterTestsServiceServer(s.grpcSrv, testsSvc)
	notificationsv1.RegisterNotificationsServiceServer(s.grpcSrv, notifSvc)

	go func() {
		s.log.Info("grpc serving", "addr", grpcAddr)
		if err := s.grpcSrv.Serve(grpcLis); err != nil {
			s.log.Error("grpc serve failed", "err", err)
		}
	}()

	// 8. Start background connections poller.
	connPoller := connectionsapi.NewPoller(
		st,
		conndns.NewVerifier(dnsResolver),
		edgeResolver,
		connectionsapi.AngiecfgAdapter{Store: storageStore, Pub: statePublisher},
		connectionsapi.CertsManagerAdapter{M: certManager},
		angie.Reloader{Log: s.log, S3Mode: s3Mode},
		s.log,
		teamsNotifier,
	)
	go connPoller.Run(ctx)

	certChecker := certexpiry.NewChecker(st, teamsNotifier, s.log)
	go certChecker.Run(ctx)

	// 9. Start background Realtime consumer.
	rtRedis := realtime.NewRedisClient()
	rtConsumer := realtime.New(rtRedis, centPub, s.log, s.metrics)
	go rtConsumer.RunForever(ctx)

	// 10. Start REST gateway server.
	mux, err := NewGatewayMux(ctx, grpcAddr)
	if err != nil {
		return fmt.Errorf("gateway init failed: %w", err)
	}

	// Instrument the whole gateway at the highest seam, outermost-first: an
	// end-to-end request deadline (inherited by every downstream hop), then a
	// trace span, then RED metrics, then the mux.
	gatewayHandler := withRequestTimeout(s.cfg.Timeouts.HTTPRequest,
		observability.TraceHandler(s.metrics.Middleware(mux)))
	s.restSrv = &http.Server{Addr: s.cfg.GRPCAddr, Handler: gatewayHandler, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		s.log.Info("rest gateway serving", "addr", s.cfg.GRPCAddr)
		if err := s.restSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("rest serve failed", "err", err)
		}
	}()

	// 11. Start Metrics server.
	s.metricsSrv = &http.Server{Addr: s.cfg.MetricsAddr, Handler: s.metrics.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = s.metricsSrv.ListenAndServe() }()

	// 12. Start CrowdSec blocked-IPs sync loop.
	go runBlockedIPsSyncLoop(ctx, s.log, syncer, st, s.cfg.Timeouts.CrowdSecSync)

	return nil
}

// Stop gracefully shuts down all listeners and databases.
func (s *Server) Stop() {
	s.log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if s.restSrv != nil {
		_ = s.restSrv.Shutdown(shutdownCtx)
	}
	if s.metricsSrv != nil {
		_ = s.metricsSrv.Shutdown(shutdownCtx)
	}
	if s.grpcSrv != nil {
		s.grpcSrv.GracefulStop()
	}
	if s.tp != nil {
		_ = s.tp.Shutdown(shutdownCtx)
	}
	if s.csRunner != nil {
		s.csRunner.Close()
	}
	if s.store != nil {
		s.store.Close()
	}
}

// ── Private Helpers ──────────────────────────────────────────────────────────

func getenvOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// buildStore selects the source-of-truth backend (FR-001). local (default) maps
// canonical keys onto the live Angie volume paths so single-node behaviour is
// unchanged; s3 enables horizontal scaling.
func buildStore(c config.StorageConfig) (storage.Store, error) {
	if c.Backend == "s3" {
		return storage.NewS3(storage.S3Options{
			Endpoint:  c.S3Endpoint,
			AccessKey: c.S3AccessKey,
			SecretKey: c.S3SecretKey,
			Bucket:    c.S3Bucket,
			Region:    c.S3Region,
			UseTLS:    c.S3UseTLS,
			Scope:     "default",
		})
	}
	layout := storage.LocalLayout{
		Tenants: getenvOr("WAF_TENANTS_DIR", "/var/lib/waf/tenants"),
		HTTPD:   "/var/lib/angie/http.d",
		State:   getenvOr("WAF_STATE_DIR", "/var/lib/angie/data"),
		Modsec:  getenvOr("WAF_MODSEC_DIR", "/app/etc/angie/modsecurity"),
	}
	return storage.NewLocalFSMapped(layout, "default"), nil
}

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

func oauthEnabled(p string) bool {
	prefix := "WAF_OAUTH_" + p + "_"
	return os.Getenv(prefix+"CLIENT_ID") != "" &&
		os.Getenv(prefix+"CLIENT_SECRET") != "" &&
		os.Getenv(prefix+"REDIRECT_URI") != ""
}

type oauthFactory struct{}

func (oauthFactory) Provider(name string) (authapi.OAuthProvider, bool) {
	p, ok := oauth.NewProvider(name)
	if !ok {
		return nil, false
	}
	return p, true
}

func runBlockedIPsSyncLoop(ctx context.Context, log *slog.Logger, syncer *crowdsec.Syncer, st *store.Store, syncTimeout time.Duration) {
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
			// Bound one sync iteration so a stuck DB/file op cannot wedge the loop.
			iterCtx, cancel := context.WithTimeout(ctx, syncTimeout)
			defer cancel()

			rows, err := st.ListConnections(iterCtx)
			if err != nil {
				log.Warn("crowdsec sync: ListConnections failed", "err", err)
				return
			}
			csConns := make([]crowdsec.Connection, 0, len(rows))
			for _, r := range rows {
				csConns = append(csConns, crowdsec.Connection{
					ID:       r.ID,
					TenantID: r.TenantID,
					Name:     r.Name,
					Domain:   r.Domain,
					Enabled:  r.Enabled,
					Status:   r.Status,
				})
			}

			if err := syncer.WriteConnectionsRegistry(csConns); err != nil {
				log.Warn("crowdsec sync: WriteConnectionsRegistry failed", "err", err)
				return
			}

			if err := syncer.SyncBlockedIPsConf(iterCtx); err != nil {
				log.Warn("crowdsec sync: SyncBlockedIPsConf failed", "err", err)
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
