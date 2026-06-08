package dockerexec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

// Container represents a simple view of a docker container.
type Container struct {
	ID     string
	Name   string
	Status string
	Image  string
	Labels map[string]string
}

// Client wraps the Docker Client SDK.
type Client struct {
	cli *client.Client
}

// New constructs a Client from the environment with API version negotiation.
func New() (*Client, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("dockerexec: client: %w", err)
	}
	return &Client{cli: cli}, nil
}

// Close releases the underlying Docker client resources.
func (c *Client) Close() {
	if c.cli != nil {
		c.cli.Close()
	}
}

// Exec executes a command inside a running container.
func (c *Client) Exec(ctx context.Context, containerName string, cmd []string) (exitCode int, stdout, stderr string, err error) {
	id, err := c.cli.ContainerExecCreate(ctx, containerName, container.ExecOptions{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return 1, "", err.Error(), err
	}

	att, err := c.cli.ContainerExecAttach(ctx, id.ID, container.ExecStartOptions{})
	if err != nil {
		return 1, "", err.Error(), err
	}
	defer att.Close()

	// Without a TTY, Docker multiplexes stdout and stderr into a single stream
	// framed with 8-byte headers. stdcopy.StdCopy demultiplexes it back into the
	// two clean streams; reading att.Reader directly would leave binary frame
	// headers interleaved in the output (corrupting large JSON payloads and
	// injecting invalid UTF-8 into text output).
	var outBuf, errBuf bytes.Buffer
	if _, err := stdcopy.StdCopy(&outBuf, &errBuf, att.Reader); err != nil {
		return 1, outBuf.String(), errBuf.String(), err
	}

	insp, err := c.cli.ContainerExecInspect(ctx, id.ID)
	if err != nil {
		return 1, outBuf.String(), errBuf.String(), err
	}

	return insp.ExitCode, outBuf.String(), errBuf.String(), nil
}

// ExecJSON runs a command and parses its output as JSON, skipping leading non-JSON lines.
func (c *Client) ExecJSON(ctx context.Context, containerName string, cmd []string) (json.RawMessage, error) {
	exitCode, stdout, _, err := c.Exec(ctx, containerName, cmd)
	if err != nil {
		return nil, err
	}
	if exitCode != 0 {
		return nil, fmt.Errorf("dockerexec: non-zero exit %d", exitCode)
	}

	text := strings.TrimSpace(stdout)
	if text == "" {
		return nil, nil
	}

	start := -1
	for i, ch := range text {
		if ch == '{' || ch == '[' {
			start = i
			break
		}
	}
	if start < 0 {
		return nil, nil
	}

	raw := json.RawMessage(text[start:])
	if !json.Valid(raw) {
		return nil, nil
	}
	return raw, nil
}

// ContainerLabels inspects a container and returns its labels map.
func (c *Client) ContainerLabels(ctx context.Context, containerID string) (map[string]string, error) {
	insp, err := c.cli.ContainerInspect(ctx, containerID)
	if err != nil {
		return nil, err
	}
	if insp.Config == nil {
		return nil, nil
	}
	return insp.Config.Labels, nil
}

// ListContainers lists all containers.
func (c *Client) ListContainers(ctx context.Context) ([]Container, error) {
	list, err := c.cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		return nil, err
	}
	out := make([]Container, len(list))
	for i, item := range list {
		out[i] = Container{
			ID:     item.ID,
			Name:   normalizeName(item.Names),
			Status: item.State,
			Image:  item.Image,
			Labels: item.Labels,
		}
	}
	return out, nil
}

// ContainerStats performs a one-shot stats read and returns the raw JSON bytes.
func (c *Client) ContainerStats(ctx context.Context, containerID string) ([]byte, error) {
	resp, err := c.cli.ContainerStatsOneShot(ctx, containerID)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func normalizeName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return strings.TrimPrefix(names[0], "/")
}
