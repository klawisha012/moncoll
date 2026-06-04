package monitoring

import (
	"encoding/json"
	"math"
)

// dockerUnlimitedMemory is the sentinel Docker reports when no memory limit is
// set (INT64_MAX rounded). Matches _DOCKER_UNLIMITED_MEMORY in router.py.
const dockerUnlimitedMemory = 9223372036854771712

// ContainerMetrics is the response row driving the mapping and tests.
type ContainerMetrics struct {
	Name          string
	CPU           float64
	Memory        float64
	MemoryPercent float64
	NetworkRx     float64
	NetworkTx     float64
}

type rawStats struct {
	CPUStats struct {
		CPUUsage struct {
			TotalUsage float64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemCPUUsage float64 `json:"system_cpu_usage"`
		OnlineCPUs     float64 `json:"online_cpus"`
	} `json:"cpu_stats"`
	PreCPUStats struct {
		CPUUsage struct {
			TotalUsage float64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemCPUUsage float64 `json:"system_cpu_usage"`
	} `json:"precpu_stats"`
	MemoryStats struct {
		Usage                   float64 `json:"usage"`
		Limit                   float64 `json:"limit"`
		HierarchicalMemoryLimit float64 `json:"hierarchical_memory_limit"`
		Stats                   struct {
			TotalRSS   float64 `json:"total_rss"`
			TotalCache float64 `json:"total_cache"`
		} `json:"stats"`
	} `json:"memory_stats"`
	Networks map[string]struct {
		RxBytes float64 `json:"rx_bytes"`
		TxBytes float64 `json:"tx_bytes"`
	} `json:"networks"`
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }

// statsToMetrics mirrors _calculate_container_stats. On any decode error it
// returns zeroed metrics with the name (matching the Python except-branch).
func statsToMetrics(name string, raw []byte) ContainerMetrics {
	zero := ContainerMetrics{Name: name}
	var s rawStats
	if err := json.Unmarshal(raw, &s); err != nil {
		return zero
	}

	// CPU
	cpuDelta := s.CPUStats.CPUUsage.TotalUsage - s.PreCPUStats.CPUUsage.TotalUsage
	systemDelta := s.CPUStats.SystemCPUUsage - s.PreCPUStats.SystemCPUUsage
	numCPUs := s.CPUStats.OnlineCPUs
	if numCPUs == 0 {
		// Python defaults online_cpus to 1 only when the key is ABSENT from the
		// payload, not when it is explicitly 0. In practice the outcomes are
		// identical here because the downstream guard (systemDelta > 0 &&
		// numCPUs > 0) prevents division by zero in either case, so we keep
		// the simpler form.
		numCPUs = 1
	}
	cpuPercent := 0.0
	if systemDelta > 0 && numCPUs > 0 {
		cpuPercent = (cpuDelta / systemDelta) * numCPUs * 100.0
	}

	// Memory
	usage := s.MemoryStats.Usage
	limit := s.MemoryStats.Limit
	if limit >= dockerUnlimitedMemory || limit <= 0 {
		limit = s.MemoryStats.HierarchicalMemoryLimit
	}
	if limit >= dockerUnlimitedMemory || limit <= 0 {
		limit = s.MemoryStats.Stats.TotalRSS + s.MemoryStats.Stats.TotalCache
		if limit <= 0 {
			limit = 1
		}
	}
	if usage < 0 {
		usage = 0
	}
	memoryMB := usage / (1024 * 1024)
	memoryPercent := (usage / limit) * 100.0

	// Network
	var rx, tx float64
	for _, n := range s.Networks {
		rx += n.RxBytes
		tx += n.TxBytes
	}

	return ContainerMetrics{
		Name:          name,
		CPU:           round2(cpuPercent),
		Memory:        round2(memoryMB),
		MemoryPercent: round2(memoryPercent),
		NetworkRx:     rx,
		NetworkTx:     tx,
	}
}
