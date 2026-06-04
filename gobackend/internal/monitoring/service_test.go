package monitoring

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	monitoringv1 "github.com/zwarder/waf/gobackend/gen/monitoring/v1"
)

type fakeDocker struct {
	containers []containerSummary
	stats      map[string][]byte
}

func (f *fakeDocker) listProjectContainers(_ context.Context) ([]containerSummary, error) {
	return f.containers, nil
}
func (f *fakeDocker) containerStats(_ context.Context, id string) ([]byte, error) {
	return f.stats[id], nil
}

func TestGetMetricsMapsAllContainers(t *testing.T) {
	fd := &fakeDocker{
		containers: []containerSummary{{ID: "a", Name: "web", Status: "running", Image: "nginx:1"}},
		stats:      map[string][]byte{"a": []byte(`{"memory_stats":{"usage":1048576,"limit":2097152}}`)},
	}
	svc := NewService(fd)
	resp, err := svc.GetMetrics(context.Background(), &monitoringv1.GetMetricsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Containers, 1)
	require.Equal(t, "web", resp.Containers[0].Name)
	require.InDelta(t, 1.0, resp.Containers[0].Memory, 0.001)
	require.InDelta(t, 50.0, resp.Containers[0].MemoryPercent, 0.001)
}

func TestListContainers(t *testing.T) {
	fd := &fakeDocker{containers: []containerSummary{{ID: "a", Name: "web", Status: "running", Image: "nginx:1"}}}
	svc := NewService(fd)
	resp, err := svc.ListContainers(context.Background(), &monitoringv1.ListContainersRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Containers, 1)
	require.Equal(t, "nginx:1", resp.Containers[0].Image)
	require.Equal(t, "web", resp.Containers[0].Name)
}
