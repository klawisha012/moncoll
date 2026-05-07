import { useEffect, useState } from "react";
import {
  Activity,
  Cpu,
  HardDrive,
  MemoryStick,
  Server,
} from "lucide-react";
import { api, ContainerMetrics } from "../api/client";

function formatBytes(bytes: number): string {
  if (bytes >= 1_000_000_000) return `${(bytes / 1_000_000_000).toFixed(1)} GB/s`;
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB/s`;
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} KB/s`;
  return `${bytes.toFixed(0)} B/s`;
}

export default function Monitoring() {
  const [metrics, setMetrics] = useState<ContainerMetrics[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    const fetchMetrics = async () => {
      try {
        const data = await api.getContainerMetrics();
        if (!cancelled) {
          setMetrics(data.containers || []);
          setError(null);
          setLoading(false);
        }
      } catch (err) {
        if (!cancelled) {
          console.error("Failed to fetch metrics:", err);
          setError(err instanceof Error ? err.message : "Failed to load metrics");
          setLoading(false);
        }
      }
    };

    fetchMetrics();
    const interval = setInterval(fetchMetrics, 5000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  if (loading) {
    return (
      <div className="loading">
        <div className="spinner" />
        Loading metrics…
      </div>
    );
  }

  if (error) {
    return (
      <div>
        <div className="page-header">
          <div>
            <h1>Monitoring</h1>
            <p>Container resource usage and real-time system metrics</p>
          </div>
        </div>
        <div
          className="card"
          style={{ gridColumn: "1 / -1", textAlign: "center", padding: "48px" }}
        >
          <Server
            size={48}
            style={{ color: "var(--danger)", marginBottom: "16px" }}
          />
          <p style={{ fontWeight: 600, marginBottom: "4px", color: "var(--danger)" }}>
            Failed to load metrics
          </p>
          <p className="text-muted">{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Monitoring</h1>
          <p>Container resource usage and real-time system metrics</p>
        </div>
      </div>

      <div className="metrics-grid">
        {metrics.length === 0 ? (
          <div
            className="card"
            style={{ gridColumn: "1 / -1", textAlign: "center", padding: "48px" }}
          >
            <Server
              size={48}
              style={{ color: "var(--text-muted)", marginBottom: "16px" }}
            />
            <p style={{ fontWeight: 600, marginBottom: "4px" }}>
              No container metrics available
            </p>
            <p className="text-muted">
              Metrics will appear once the services are running.
            </p>
          </div>
        ) : (
          metrics.map((container) => (
            <div key={container.name} className="card">
              <div className="card-header">
                <h3>{container.name}</h3>
                <Activity size={16} style={{ color: "var(--accent-3)" }} />
              </div>

              {/* CPU */}
              <div style={{ marginBottom: "14px" }}>
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    marginBottom: "6px",
                    fontSize: "12.5px",
                  }}
                >
                  <span
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                      color: "var(--text-secondary)",
                    }}
                  >
                    <Cpu size={14} /> CPU
                  </span>
                  <span style={{ fontWeight: 600 }}>
                    {(container.cpu ?? 0).toFixed(1)}%
                  </span>
                </div>
                <div className="progress-bar">
                  <div
                    className="progress-fill blue"
                    style={{
                      width: `${Math.min(container.cpu ?? 0, 100)}%`,
                    }}
                  />
                </div>
              </div>

              {/* Memory */}
              <div style={{ marginBottom: "14px" }}>
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    marginBottom: "6px",
                    fontSize: "12.5px",
                  }}
                >
                  <span
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                      color: "var(--text-secondary)",
                    }}
                  >
                    <MemoryStick size={14} /> Memory
                  </span>
                  <span style={{ fontWeight: 600 }}>
                    {(container.memory ?? 0).toFixed(0)} MB (
                    {(container.memory_percent ?? 0).toFixed(1)}%)
                  </span>
                </div>
                <div className="progress-bar">
                  <div
                    className="progress-fill green"
                    style={{
                      width: `${Math.min(container.memory_percent ?? 0, 100)}%`,
                    }}
                  />
                </div>
              </div>

              {/* Network */}
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  paddingTop: "12px",
                  borderTop: "1px solid var(--border-subtle)",
                  fontSize: "12px",
                  color: "var(--text-muted)",
                }}
              >
                <span
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "6px",
                  }}
                >
                  <HardDrive size={14} /> Network
                </span>
                <span>
                  ↓ {formatBytes(container.network_rx ?? 0)}{" "}
                  ↑ {formatBytes(container.network_tx ?? 0)}
                </span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
