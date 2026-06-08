// Package cscli executes cscli commands inside the CrowdSec Docker container,
// mirroring Python _run_cscli / _run_cscli_json in backend/src/crowdsec/service.py.
package cscli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/zwarder/waf/gobackend/internal/dockerexec"
)

// Runner executes cscli inside the CrowdSec container.
// The container name defaults to "waf-crowdsec-1" and can be overridden
// via the WAF_CROWDSEC_CONTAINER environment variable.
type Runner struct {
	client        *dockerexec.Client
	containerName string
}

// New creates a Runner backed by the Docker daemon from the environment.
func New() (*Runner, error) {
	cli, err := dockerexec.New()
	if err != nil {
		return nil, fmt.Errorf("cscli: docker client: %w", err)
	}
	name := os.Getenv("WAF_CROWDSEC_CONTAINER")
	if name == "" {
		name = "waf-crowdsec-1"
	}
	return &Runner{client: cli, containerName: name}, nil
}

// Close releases the underlying docker client.
func (r *Runner) Close() { r.client.Close() }

// Run execs ["/usr/local/bin/cscli", args...] in the CrowdSec container and returns the exit
// code, combined stdout, and an error string (stderr equivalent).
func (r *Runner) Run(ctx context.Context, args ...string) (exitCode int, stdout, stderr string, err error) {
	cmd := append([]string{"/usr/local/bin/cscli"}, args...)
	return r.client.Exec(ctx, r.containerName, cmd)
}

// RunJSON appends "-o json" to args, calls ExecJSON with cscli prefix, then locates the first '{' or
// '[' in stdout and parses from there.
func (r *Runner) RunJSON(ctx context.Context, args ...string) (json.RawMessage, error) {
	cmd := append([]string{"/usr/local/bin/cscli"}, args...)
	cmd = append(cmd, "-o", "json")
	return r.client.ExecJSON(ctx, r.containerName, cmd)
}

// Runnable is the interface the crowdsec package depends on.
// *Runner satisfies it; tests can inject a fake.
type Runnable interface {
	Run(ctx context.Context, args ...string) (exitCode int, stdout, stderr string, err error)
	RunJSON(ctx context.Context, args ...string) (json.RawMessage, error)
}

// Errors
var ErrContainerNotFound = errors.New("cscli: container not found")

// NoopRunner is a runner that does nothing, satisfying cscli.Runnable and crowdsecapi.Runner.
type NoopRunner struct{}

func (NoopRunner) Run(_ context.Context, _ ...string) (int, string, string, error) {
	return 1, "", "crowdsec runner not available", nil
}

func (NoopRunner) RunJSON(_ context.Context, _ ...string) (json.RawMessage, error) {
	return nil, nil
}
