package monitoring

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	monitoringv1 "github.com/zwarder/waf/gobackend/gen/monitoring/v1"
)

type fakeDocker struct {
	// projectContainers is returned by listProjectContainers (used by GetMetrics).
	projectContainers []containerSummary
	// runningContainers is returned by listRunningContainers (used by ListContainers).
	runningContainers []containerSummary
	stats             map[string][]byte
}

func (f *fakeDocker) listProjectContainers(_ context.Context) ([]containerSummary, error) {
	return f.projectContainers, nil
}
func (f *fakeDocker) listRunningContainers(_ context.Context) ([]containerSummary, error) {
	return f.runningContainers, nil
}
func (f *fakeDocker) containerStats(_ context.Context, id string) ([]byte, error) {
	return f.stats[id], nil
}

// TestGetMetricsUsesProjectFilter verifies GetMetrics calls listProjectContainers
// (compose-project-filtered), NOT the unfiltered running list.
func TestGetMetricsUsesProjectFilter(t *testing.T) {
	fd := &fakeDocker{
		projectContainers: []containerSummary{{ID: "a", Name: "web", Status: "running", Image: "nginx:1"}},
		runningContainers: []containerSummary{
			{ID: "a", Name: "web", Status: "running", Image: "nginx:1"},
			{ID: "b", Name: "other", Status: "running", Image: "redis:7"},
		},
		stats: map[string][]byte{"a": []byte(`{"memory_stats":{"usage":1048576,"limit":2097152}}`)},
	}
	svc := NewService(fd)
	resp, err := svc.GetMetrics(context.Background(), &monitoringv1.GetMetricsRequest{})
	require.NoError(t, err)
	// Must only see project containers, not the unfiltered running list.
	require.Len(t, resp.Containers, 1)
	require.Equal(t, "web", resp.Containers[0].Name)
	require.InDelta(t, 1.0, resp.Containers[0].Memory, 0.001)
	require.InDelta(t, 50.0, resp.Containers[0].MemoryPercent, 0.001)
}

// TestListContainersUsesRunningUnfiltered verifies ListContainers calls
// listRunningContainers (no compose-project filter), matching the Python
// client.containers.list() behaviour that returns all running containers.
func TestListContainersUsesRunningUnfiltered(t *testing.T) {
	fd := &fakeDocker{
		// projectContainers is intentionally shorter — ListContainers must NOT use it.
		projectContainers: []containerSummary{{ID: "a", Name: "web", Status: "running", Image: "nginx:1"}},
		runningContainers: []containerSummary{
			{ID: "a", Name: "web", Status: "running", Image: "nginx:1"},
			{ID: "b", Name: "other", Status: "running", Image: "redis:7"},
		},
	}
	svc := NewService(fd)
	resp, err := svc.ListContainers(context.Background(), &monitoringv1.ListContainersRequest{})
	require.NoError(t, err)
	// Must return ALL running containers, not just project ones.
	require.Len(t, resp.Containers, 2)
	require.Equal(t, "nginx:1", resp.Containers[0].Image)
	require.Equal(t, "web", resp.Containers[0].Name)
	require.Equal(t, "redis:7", resp.Containers[1].Image)
	require.Equal(t, "other", resp.Containers[1].Name)
}
