// Package cscli executes cscli commands inside the CrowdSec Docker container,
// mirroring Python _run_cscli / _run_cscli_json in backend/src/crowdsec/service.py.
package cscli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// Runner executes cscli inside the CrowdSec container.
// The container name defaults to "waf-crowdsec-1" and can be overridden
// via the WAF_CROWDSEC_CONTAINER environment variable.
type Runner struct {
	cli           *client.Client
	containerName string
}

// New creates a Runner backed by the Docker daemon from the environment.
func New() (*Runner, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("cscli: docker client: %w", err)
	}
	name := os.Getenv("WAF_CROWDSEC_CONTAINER")
	if name == "" {
		name = "waf-crowdsec-1"
	}
	return &Runner{cli: cli, containerName: name}, nil
}

// Close releases the underlying docker client.
func (r *Runner) Close() { r.cli.Close() }

// Run execs ["cscli", args...] in the CrowdSec container and returns the exit
// code, combined stdout, and an error string (stderr equivalent).
// Mirrors Python _run_cscli: stdout contains the output, errors surface via
// exitCode != 0 or err != nil.
func (r *Runner) Run(ctx context.Context, args ...string) (exitCode int, stdout, stderr string, err error) {
	cmd := append([]string{"cscli"}, args...)
	id, execErr := r.cli.ContainerExecCreate(ctx, r.containerName, container.ExecOptions{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
	})
	if execErr != nil {
		return 1, "", execErr.Error(), execErr
	}

	att, execErr := r.cli.ContainerExecAttach(ctx, id.ID, container.ExecStartOptions{})
	if execErr != nil {
		return 1, "", execErr.Error(), execErr
	}
	defer att.Close()

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(att.Reader)
	combined := buf.String()

	insp, execErr := r.cli.ContainerExecInspect(ctx, id.ID)
	if execErr != nil {
		return 1, combined, execErr.Error(), execErr
	}

	return insp.ExitCode, combined, "", nil
}

// RunJSON appends "-o json" to args, calls Run, then locates the first '{' or
// '[' in stdout and parses from there — exactly like Python _run_cscli_json
// which skips status lines such as "Loaded: …" printed by some cscli sub-commands
// (e.g. "hub list -a").
//
// Returns nil on non-zero exit or if the output is empty / unparseable; the
// caller must treat nil as "empty result".
func (r *Runner) RunJSON(ctx context.Context, args ...string) (json.RawMessage, error) {
	exitCode, stdout, _, runErr := r.Run(ctx, append(args, "-o", "json")...)
	if runErr != nil {
		return nil, runErr
	}
	if exitCode != 0 {
		slog.Warn("cscli returned non-zero exit", "exit", exitCode, "args", args)
		return nil, nil
	}

	text := strings.TrimSpace(stdout)
	if text == "" {
		return nil, nil
	}

	// Find first JSON-start character, skipping any leading status/info lines.
	start := -1
	for i, ch := range text {
		if ch == '{' || ch == '[' {
			start = i
			break
		}
	}
	if start < 0 {
		slog.Warn("cscli returned non-JSON output", "preview", truncate(text, 200))
		return nil, nil
	}

	raw := json.RawMessage(text[start:])
	if !json.Valid(raw) {
		slog.Warn("cscli returned invalid JSON", "preview", truncate(text, 200))
		return nil, nil
	}
	return raw, nil
}

// isNotFound reports whether the docker error indicates the container is missing.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "No such container") || strings.Contains(msg, "not found")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// Runnable is the interface the crowdsec package depends on.
// *Runner satisfies it; tests can inject a fake.
type Runnable interface {
	Run(ctx context.Context, args ...string) (exitCode int, stdout, stderr string, err error)
	RunJSON(ctx context.Context, args ...string) (json.RawMessage, error)
}

// Errors
var ErrContainerNotFound = errors.New("cscli: container not found")
