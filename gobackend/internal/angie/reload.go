// Package angie reloads the Angie reverse proxy via docker exec, mirroring
// connections.service._reload_angie. Best-effort: every error is logged, never
// returned fatally.
package angie

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/zwarder/waf/gobackend/internal/dockerexec"
)

func containerName() string {
	if v := os.Getenv("WAF_ANGIE_CONTAINER"); v != "" {
		return v
	}
	return "waf-angie-1" // matches ANGIE_CONTAINER_NAME in connections/service.py
}

// Reload runs `angie -t` then `angie -s reload` inside the Angie container.
// Best-effort: logs and returns on any failure.
func Reload(ctx context.Context, log *slog.Logger) {
	execClient, err := dockerexec.New()
	if err != nil {
		log.Warn("angie reload: dockerexec client", "err", err)
		return
	}
	defer execClient.Close()
	name := containerName()
	exitCode, out, _, err := execClient.Exec(ctx, name, []string{"angie", "-t"})
	if err != nil || exitCode != 0 {
		log.Warn("angie -t failed", "err", err, "exitCode", exitCode, "out", out)
		return
	}
	exitCode, out, _, err = execClient.Exec(ctx, name, []string{"angie", "-s", "reload"})
	if err != nil || exitCode != 0 {
		log.Warn("angie reload failed", "err", err, "exitCode", exitCode, "out", out)
	}
}

// ReloadVerbose runs `angie -t` then `angie -s reload`, returning a success
// flag + human message (mirrors backend/src/modsecurity/router.py reload_angie).
func ReloadVerbose(ctx context.Context) (bool, string) {
	execClient, err := dockerexec.New()
	if err != nil {
		return false, "Container '" + containerName() + "' not found"
	}
	defer execClient.Close()
	name := containerName()

	// Verify the container is reachable by attempting the exec; a missing
	// container returns an error here, matching Python's "Container not found".
	exitCode, out, _, err := execClient.Exec(ctx, name, []string{"angie", "-t"})
	if err != nil {
		// Distinguish "container not found" from a config-test failure.
		if isNotFound(err) {
			return false, "Container '" + name + "' not found"
		}
		return false, "Config test failed: " + err.Error()
	}
	if exitCode != 0 {
		return false, "Config test failed: " + out
	}

	exitCode, out, _, err = execClient.Exec(ctx, name, []string{"angie", "-s", "reload"})
	if err != nil {
		return false, "Reload failed: " + err.Error()
	}
	if exitCode != 0 {
		return false, "Reload failed: " + out
	}
	return true, "Angie reloaded successfully"
}

// isNotFound returns true when the docker error indicates the container does not exist.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "No such container") || strings.Contains(msg, "not found")
}

// Reloader adapts Angie reload calls.
type Reloader struct {
	Log *slog.Logger
}

func (r Reloader) Reload(ctx context.Context) {
	Reload(ctx, r.Log)
}

func (r Reloader) ReloadVerbose(ctx context.Context) (bool, string) {
	return ReloadVerbose(ctx)
}
