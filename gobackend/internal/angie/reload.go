// Package angie reloads the Angie reverse proxy via docker exec, mirroring
// connections.service._reload_angie. Best-effort: every error is logged, never
// returned fatally.
package angie

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
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
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Warn("angie reload: docker client", "err", err)
		return
	}
	defer cli.Close()
	name := containerName()
	if out, err := runExec(ctx, cli, name, []string{"angie", "-t"}); err != nil {
		log.Warn("angie -t failed", "err", err, "out", out)
		return
	}
	if out, err := runExec(ctx, cli, name, []string{"angie", "-s", "reload"}); err != nil {
		log.Warn("angie reload failed", "err", err, "out", out)
	}
}

// ReloadVerbose runs `angie -t` then `angie -s reload`, returning a success
// flag + human message (mirrors backend/src/modsecurity/router.py reload_angie).
func ReloadVerbose(ctx context.Context) (bool, string) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return false, "Container '" + containerName() + "' not found"
	}
	defer cli.Close()
	name := containerName()

	// Verify the container is reachable by attempting the exec create; a missing
	// container returns an error here, matching Python's "Container not found".
	out, err := runExec(ctx, cli, name, []string{"angie", "-t"})
	if err != nil {
		// Distinguish "container not found" from a config-test failure.
		if isNotFound(err) {
			return false, "Container '" + name + "' not found"
		}
		return false, "Config test failed: " + out
	}

	out, err = runExec(ctx, cli, name, []string{"angie", "-s", "reload"})
	if err != nil {
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

func runExec(ctx context.Context, cli *client.Client, name string, cmd []string) (string, error) {
	id, err := cli.ContainerExecCreate(ctx, name, container.ExecOptions{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return "", err
	}
	att, err := cli.ContainerExecAttach(ctx, id.ID, container.ExecStartOptions{})
	if err != nil {
		return "", err
	}
	defer att.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(att.Reader)
	insp, err := cli.ContainerExecInspect(ctx, id.ID)
	if err != nil {
		return buf.String(), err
	}
	if insp.ExitCode != 0 {
		return buf.String(), errors.New("non-zero exit from docker exec")
	}
	return buf.String(), nil
}
