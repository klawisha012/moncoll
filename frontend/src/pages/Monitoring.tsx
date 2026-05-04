import { useEffect, useState } from "react";
import { Activity, Cpu, HardDrive, MemoryStick } from "lucide-react";

interface ContainerMetrics {
  name: string;
  cpu: number;
  memory: number;
  memoryPercent: number;
  networkRx: number;
  networkTx: number;
}

export default function Monitoring() {
  const [metrics, setMetrics] = useState<ContainerMetrics[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchMetrics = async () => {
      try {
        const response = await fetch("/api/monitoring/metrics");
        const data = await response.json();
        setMetrics(data.containers || []);
        setLoading(false);
      } catch (error) {
        console.error("Failed to fetch metrics:", error);
        setLoading(false);
      }
    };

    fetchMetrics();
    const interval = setInterval(fetchMetrics, 5000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-lg">Loading metrics...</div>
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Monitoring</h1>
          <p>Container resource usage and metrics</p>
        </div>
      </div>

      <div className="metrics-grid">
        {metrics.map((container) => (
          <div key={container.name} className="card">
            <div className="card-header">
              <h3>{container.name}</h3>
              <Activity className="h-5 w-5 text-blue-500" />
            </div>

            <div style={{ marginBottom: "12px" }}>
              <div className="flex items-center justify-between text-sm" style={{ marginBottom: "4px" }}>
                <span className="flex items-center gap-1">
                  <Cpu className="h-4 w-4" /> CPU
                </span>
                <span>{(container.cpu ?? 0).toFixed(2)}%</span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div
                  className="bg-blue-500 h-2 rounded-full transition-all"
                  style={{ width: `${Math.min(container.cpu ?? 0, 100)}%` }}
                />
              </div>
            </div>

            <div style={{ marginBottom: "12px" }}>
              <div className="flex items-center justify-between text-sm" style={{ marginBottom: "4px" }}>
                <span className="flex items-center gap-1">
                  <MemoryStick className="h-4 w-4" /> Memory
                </span>
                 <span>{(container.memory ?? 0).toFixed(1)} MB ({(container.memoryPercent ?? 0).toFixed(1)}%)</span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div
                  className="bg-green-500 h-2 rounded-full transition-all"
                  style={{ width: `${Math.min(container.memoryPercent ?? 0, 100)}%` }}
                />
              </div>
            </div>

            <div className="flex items-center justify-between text-sm pt-2 border-t">
              <span className="flex items-center gap-1">
                <HardDrive className="h-4 w-4" /> Network
              </span>
              <span className="text-xs">
                ↓{((container.networkRx ?? 0) / 1024).toFixed(1)} KB/s ↑{((container.networkTx ?? 0) / 1024).toFixed(1)} KB/s
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}