package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"

	adminv1 "github.com/zwarder/waf/gobackend/gen/admin/v1"
	modsecurityv1 "github.com/zwarder/waf/gobackend/gen/modsecurity/v1"
	monitoringv1 "github.com/zwarder/waf/gobackend/gen/monitoring/v1"
	"github.com/zwarder/waf/gobackend/internal/admin"
	"github.com/zwarder/waf/gobackend/internal/angie"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/config"
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
		// monitoring + admin: absent from map → default LevelAdmin (fail closed)
	}
	grpcSrv := grpc.NewServer(grpc.ChainUnaryInterceptor(auth.NewInterceptor(dec, policy, authLevels)))
	monitoringv1.RegisterMonitoringServiceServer(grpcSrv, monitoring.NewService(engine))
	tfs := tenantfs.New(getenvOr("WAF_TENANTS_DIR", "/var/lib/waf/tenants"))
	adminv1.RegisterAdminServiceServer(grpcSrv, admin.NewService(st, tfs, angieReloader{log: log}))
	msCfg := modsec.New(getenvOr("WAF_MODSEC_DIR", "/app/etc/angie/modsecurity"))
	modsecurityv1.RegisterModSecurityServiceServer(grpcSrv, modsecurity.NewService(msCfg, modsecReloader{}))
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

	<-ctx.Done()
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = rest.Shutdown(shutdownCtx)
	_ = metrics.Shutdown(shutdownCtx)
	grpcSrv.GracefulStop()
}

// angieReloader wraps angie.Reload to satisfy admin.Reloader.
type angieReloader struct{ log *slog.Logger }

func (a angieReloader) Reload(ctx context.Context) { angie.Reload(ctx, a.log) }

// modsecReloader wraps angie.ReloadVerbose to satisfy modsecurity.Reloader.
type modsecReloader struct{}

func (modsecReloader) ReloadVerbose(ctx context.Context) (bool, string) {
	return angie.ReloadVerbose(ctx)
}

// getenvOr returns the environment variable k or def if it is empty/unset.
func getenvOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
