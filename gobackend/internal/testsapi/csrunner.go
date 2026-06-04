package testsapi

// CscliCSRunner implements CSRunner using internal/cscli.Runner.
// It mirrors what crowdsec_runner.py calls:
//   1. crowdsec_service.get_decisions() → cscli decisions list -o json
//   2. crowdsec_service.add_decision()  → cscli decisions add --ip ... --duration ... --reason ... --type ban

import (
	"context"
	"encoding/json"
	"fmt"
)

// CscliRunner is the interface the cscli package provides (matches cscli.Runnable).
type CscliRunner interface {
	Run(ctx context.Context, args ...string) (exitCode int, stdout, stderr string, err error)
	RunJSON(ctx context.Context, args ...string) (json.RawMessage, error)
}

// CscliCSRunner adapts a cscli.Runner to the CSRunner interface.
type CscliCSRunner struct {
	r CscliRunner
}

// NewCscliCSRunner wraps a CscliRunner.
func NewCscliCSRunner(r CscliRunner) *CscliCSRunner {
	return &CscliCSRunner{r: r}
}

// GetDecisions calls `cscli decisions list -o json` and returns the raw JSON
// items (each item is one alertShape object).
func (c *CscliCSRunner) GetDecisions(ctx context.Context) ([]json.RawMessage, error) {
	raw, err := c.r.RunJSON(ctx, "decisions", "list")
	if err != nil || raw == nil {
		return nil, err
	}
	// decisions list returns an array of alertShape objects.
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		// Some cscli versions wrap it: {"decisions": [...]}
		var wrapped map[string]json.RawMessage
		if err2 := json.Unmarshal(raw, &wrapped); err2 == nil {
			if arr, ok := wrapped["decisions"]; ok {
				if err3 := json.Unmarshal(arr, &items); err3 == nil {
					return items, nil
				}
			}
		}
		return nil, fmt.Errorf("csrunner: parse decisions: %w", err)
	}
	return items, nil
}

// AddDecision calls `cscli decisions add --ip <ip> --duration <d> --reason <r> --type <t>`.
func (c *CscliCSRunner) AddDecision(ctx context.Context, ip, duration, reason, decisionType string) error {
	if duration == "" {
		duration = "5m"
	}
	if decisionType == "" {
		decisionType = "ban"
	}
	exitCode, _, stderr, err := c.r.Run(ctx,
		"decisions", "add",
		"--ip", ip,
		"--duration", duration,
		"--reason", reason,
		"--type", decisionType,
	)
	if err != nil {
		return fmt.Errorf("csrunner: cscli exec: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("csrunner: cscli decisions add failed (exit %d): %s", exitCode, stderr)
	}
	return nil
}
