package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/zwarder/waf/gobackend/internal/bootstrap"
	"github.com/zwarder/waf/gobackend/internal/config"
	"github.com/zwarder/waf/gobackend/internal/migrate"
	"github.com/zwarder/waf/gobackend/internal/observability"
	"github.com/zwarder/waf/gobackend/internal/server"
	"github.com/zwarder/waf/gobackend/internal/store"
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
		os.Exit(2)
	}

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

	dsn := os.Getenv("WAF_POSTGRES_DSN")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "Error: WAF_POSTGRES_DSN is required")
		os.Exit(1)
	}

	ctx := context.Background()

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

// runServer instantiates and runs the Server module.
func runServer(ctx context.Context, log *slog.Logger) {
	cfg, err := config.Load()
	if err != nil {
		log.Error("config load failed", "err", err)
		os.Exit(1)
	}

	// Refuse to boot with an insecure secret configuration (empty ClickHouse
	// password, half-configured SMTP/OAuth/Turnstile). Fail-fast and uniform
	// regardless of how the process is launched.
	if err := config.ValidateSecrets(); err != nil {
		log.Error("insecure secret configuration", "err", err)
		os.Exit(1)
	}

	srv := server.New(cfg, log)
	if err := srv.Start(ctx); err != nil {
		log.Error("server start failed", "err", err)
		os.Exit(1)
	}

	<-ctx.Done()
	srv.Stop()
}
