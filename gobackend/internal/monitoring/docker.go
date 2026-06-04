package monitoring

import (
	"context"
	"io"
	"os"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

const composeProjectLabel = "com.docker.compose.project"

// DockerEngine implements dockerSource using the Docker SDK.
type DockerEngine struct {
	cli *client.Client
}

// NewDockerEngine constructs a DockerEngine from the environment (DOCKER_HOST,
// DOCKER_TLS_VERIFY, etc.) with automatic API version negotiation.
func NewDockerEngine() (*DockerEngine, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	return &DockerEngine{cli: cli}, nil
}

// composeProject detects the compose project label of our own container.
// The hostname inside a Docker container equals the short container ID, which
// mirrors _get_compose_project's primary detection path in the Python backend.
func (d *DockerEngine) composeProject(ctx context.Context) string {
	host, _ := os.Hostname()
	if host == "" {
		return ""
	}
	insp, err := d.cli.ContainerInspect(ctx, host)
	if err != nil {
		return ""
	}
	if insp.Config == nil {
		return ""
	}
	return insp.Config.Labels[composeProjectLabel]
}

// listProjectContainers returns containers belonging to our compose project.
// If the project cannot be detected, all RUNNING containers are returned
// (mirroring the Python fallback).
func (d *DockerEngine) listProjectContainers(ctx context.Context) ([]containerSummary, error) {
	// ContainerList in v28 returns []types.Container (not container.Summary).
	list, err := d.cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		return nil, err
	}

	project := d.composeProject(ctx)

	var out []containerSummary
	for _, c := range list {
		if project != "" {
			if c.Labels[composeProjectLabel] != project {
				continue
			}
		} else if c.State != "running" {
			continue
		}
		out = append(out, containerSummary{
			ID:     c.ID,
			Name:   normalizeName(c.Names),
			Status: c.State,
			Image:  c.Image,
		})
	}
	return out, nil
}

// listRunningContainers returns ALL running containers on the host with no
// compose-project filter, mirroring the Python client.containers.list() call
// (which by default returns only running containers).
func (d *DockerEngine) listRunningContainers(ctx context.Context) ([]containerSummary, error) {
	// ContainerList with default options already returns only running containers.
	list, err := d.cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		return nil, err
	}
	out := make([]containerSummary, 0, len(list))
	for _, c := range list {
		out = append(out, containerSummary{
			ID:     c.ID,
			Name:   normalizeName(c.Names),
			Status: c.State,
			Image:  c.Image,
		})
	}
	return out, nil
}

// containerStats performs a one-shot stats read and returns the raw JSON bytes.
// The caller (statsToMetrics) is responsible for parsing the payload.
func (d *DockerEngine) containerStats(ctx context.Context, id string) ([]byte, error) {
	resp, err := d.cli.ContainerStatsOneShot(ctx, id)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// normalizeName strips the leading "/" that Docker prefixes on container names
// (e.g. ["/web"] → "web"), matching Python's c.name attribute.
func normalizeName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return strings.TrimPrefix(names[0], "/")
}

