package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"

	monitoringv1 "github.com/zwarder/waf/gobackend/gen/monitoring/v1"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/config"
	"github.com/zwarder/waf/gobackend/internal/monitoring"
	"github.com/zwarder/waf/gobackend/internal/observability"
	"github.com/zwarder/waf/gobackend/internal/server"
	"github.com/zwarder/waf/gobackend/internal/store"
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
	grpcSrv := grpc.NewServer(grpc.ChainUnaryInterceptor(auth.AdminInterceptor(dec, policy)))
	monitoringv1.RegisterMonitoringServiceServer(grpcSrv, monitoring.NewService(engine))
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
