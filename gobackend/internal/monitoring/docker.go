package monitoring

import (
	"context"
	"os"

	"github.com/zwarder/waf/gobackend/internal/dockerexec"
)

const composeProjectLabel = "com.docker.compose.project"

// DockerEngine implements dockerSource using the dockerexec package.
type DockerEngine struct {
	client *dockerexec.Client
}

// NewDockerEngine constructs a DockerEngine from the environment.
func NewDockerEngine() (*DockerEngine, error) {
	cli, err := dockerexec.New()
	if err != nil {
		return nil, err
	}
	return &DockerEngine{client: cli}, nil
}

// composeProject detects the compose project label of our own container.
func (d *DockerEngine) composeProject(ctx context.Context) string {
	host, _ := os.Hostname()
	if host == "" {
		return ""
	}
	labels, err := d.client.ContainerLabels(ctx, host)
	if err != nil {
		return ""
	}
	if labels == nil {
		return ""
	}
	return labels[composeProjectLabel]
}

// listProjectContainers returns containers belonging to our compose project.
func (d *DockerEngine) listProjectContainers(ctx context.Context) ([]containerSummary, error) {
	list, err := d.client.ListContainers(ctx)
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
		} else if c.Status != "running" {
			continue
		}
		out = append(out, containerSummary{
			ID:     c.ID,
			Name:   c.Name,
			Status: c.Status,
			Image:  c.Image,
		})
	}
	return out, nil
}

// listRunningContainers returns ALL running containers on the host with no
// compose-project filter.
func (d *DockerEngine) listRunningContainers(ctx context.Context) ([]containerSummary, error) {
	list, err := d.client.ListContainers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]containerSummary, 0, len(list))
	for _, c := range list {
		out = append(out, containerSummary{
			ID:     c.ID,
			Name:   c.Name,
			Status: c.Status,
			Image:  c.Image,
		})
	}
	return out, nil
}

// containerStats performs a one-shot stats read and returns the raw JSON bytes.
func (d *DockerEngine) containerStats(ctx context.Context, id string) ([]byte, error) {
	return d.client.ContainerStats(ctx, id)
}
