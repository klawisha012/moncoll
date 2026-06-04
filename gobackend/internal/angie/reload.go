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
