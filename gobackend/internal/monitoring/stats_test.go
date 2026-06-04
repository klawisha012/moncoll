package monitoring

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStatsToMetricsBasic(t *testing.T) {
	raw, err := os.ReadFile("testdata/stats_basic.json")
	require.NoError(t, err)
	m := statsToMetrics("web", raw)
	require.Equal(t, "web", m.Name)
	require.InDelta(t, 40.0, m.CPU, 0.001)
	require.InDelta(t, 50.0, m.Memory, 0.001)
	require.InDelta(t, 50.0, m.MemoryPercent, 0.001)
	require.InDelta(t, 1005.0, m.NetworkRx, 0.001)
	require.InDelta(t, 2007.0, m.NetworkTx, 0.001)
}

func TestStatsUnlimitedMemoryFallsBack(t *testing.T) {
	raw := []byte(`{"memory_stats":{"usage":1048576,"limit":9223372036854771712,
		"stats":{"total_rss":2097152,"total_cache":0}}}`)
	m := statsToMetrics("db", raw)
	require.InDelta(t, 1.0, m.Memory, 0.001)
	require.InDelta(t, 50.0, m.MemoryPercent, 0.001)
}

func TestStatsZeroSystemDeltaGivesZeroCPU(t *testing.T) {
	raw := []byte(`{"cpu_stats":{"cpu_usage":{"total_usage":5},"system_cpu_usage":10},
		"precpu_stats":{"cpu_usage":{"total_usage":5},"system_cpu_usage":10},
		"memory_stats":{"usage":0,"limit":100}}`)
	m := statsToMetrics("idle", raw)
	require.InDelta(t, 0.0, m.CPU, 0.001)
}

func TestStatsMalformedJSONIsSafe(t *testing.T) {
	m := statsToMetrics("broken", []byte(`not json`))
	require.Equal(t, "broken", m.Name)
	require.Equal(t, 0.0, m.CPU)
}
