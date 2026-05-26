import { createEffect, createSignal, onCleanup, For, Show } from "solid-js";
import {
  Activity,
  Cpu,
  HardDrive,
  MemoryStick,
  Server,
} from "lucide-solid";
import { api, ContainerMetrics } from "../api/client";
import { useSettings } from "../context/SettingsContext";

function formatBytes(bytes: number): string {
  if (bytes >= 1_000_000_000) return `${(bytes / 1_000_000_000).toFixed(1)} GB/s`;
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB/s`;
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} KB/s`;
  return `${bytes.toFixed(0)} B/s`;
}

export default function Monitoring() {
  const settings = useSettings();
  const [metrics, setMetrics] = createSignal<ContainerMetrics[]>([]);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);

  createEffect(() => {
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
    onCleanup(() => {
      cancelled = true;
      clearInterval(interval);
    });
  });

  return (
    <Show
      when={!loading()}
      fallback={
        <div class="loading">
          <div class="spinner" />
          {settings.t("monitoring.loading")}
        </div>
      }
    >
      <Show
        when={!error()}
        fallback={
          <div>
            <div class="page-header">
              <div>
                <h1>{settings.t("monitoring.title")}</h1>
                <p>{settings.t("monitoring.subtitle")}</p>
              </div>
            </div>
            <div
              class="card"
              style={{ "grid-column": "1 / -1", "text-align": "center", padding: "48px" }}
            >
              <Server
                size={48}
                style={{ color: "var(--danger)", "margin-bottom": "16px" }}
              />
              <p style={{ "font-weight": 600, "margin-bottom": "4px", color: "var(--danger)" }}>
                {settings.t("monitoring.error.title")}
              </p>
              <p class="text-muted">{error()}</p>
            </div>
          </div>
        }
      >
        <div>
          <div class="page-header">
            <div>
              <h1>{settings.t("monitoring.title")}</h1>
              <p>{settings.t("monitoring.subtitle")}</p>
            </div>
          </div>

          <div class="metrics-grid">
            <Show
              when={metrics().length > 0}
              fallback={
                <div
                  class="card"
                  style={{ "grid-column": "1 / -1", "text-align": "center", padding: "48px" }}
                >
                  <Server
                    size={48}
                    style={{ color: "var(--text-muted)", "margin-bottom": "16px" }}
                  />
                  <p style={{ "font-weight": 600, "margin-bottom": "4px" }}>
                    {settings.t("monitoring.empty.title")}
                  </p>
                  <p class="text-muted">
                    {settings.t("monitoring.empty.subtitle")}
                  </p>
                </div>
              }
            >
              <For each={metrics()}>
                {(container) => (
                  <div class="card">
                    <div class="card-header">
                      <h3>{container.name}</h3>
                      <Activity size={16} style={{ color: "var(--accent-3)" }} />
                    </div>

                    {/* CPU */}
                    <div style={{ "margin-bottom": "14px" }}>
                      <div
                        style={{
                          display: "flex",
                          "justify-content": "space-between",
                          "align-items": "center",
                          "margin-bottom": "6px",
                          "font-size": "12.5px",
                        }}
                      >
                        <span
                          style={{
                            display: "flex",
                            "align-items": "center",
                            gap: "6px",
                            color: "var(--text-secondary)",
                          }}
                        >
                          <Cpu size={14} /> {settings.t("monitoring.cpu")}
                        </span>
                        <span style={{ "font-weight": 600 }}>
                          {(container.cpu ?? 0).toFixed(1)}%
                        </span>
                      </div>
                      <div class="progress-bar">
                        <div
                          class="progress-fill blue"
                          style={{
                            width: `${Math.min(container.cpu ?? 0, 100)}%`,
                          }}
                        />
                      </div>
                    </div>

                    {/* Memory */}
                    <div style={{ "margin-bottom": "14px" }}>
                      <div
                        style={{
                          display: "flex",
                          "justify-content": "space-between",
                          "align-items": "center",
                          "margin-bottom": "6px",
                          "font-size": "12.5px",
                        }}
                      >
                        <span
                          style={{
                            display: "flex",
                            "align-items": "center",
                            gap: "6px",
                            color: "var(--text-secondary)",
                          }}
                        >
                          <MemoryStick size={14} /> {settings.t("monitoring.memory")}
                        </span>
                        <span style={{ "font-weight": 600 }}>
                          {(container.memory ?? 0).toFixed(0)} MB (
                          {(container.memory_percent ?? 0).toFixed(1)}%)
                        </span>
                      </div>
                      <div class="progress-bar">
                        <div
                          class="progress-fill green"
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
                        "justify-content": "space-between",
                        "align-items": "center",
                        "padding-top": "12px",
                        "border-top": "1px solid var(--border-subtle)",
                        "font-size": "12px",
                        color: "var(--text-muted)",
                      }}
                    >
                      <span
                        style={{
                          display: "flex",
                          "align-items": "center",
                          gap: "6px",
                        }}
                      >
                        <HardDrive size={14} /> {settings.t("monitoring.network")}
                      </span>
                      <span>
                        ↓ {formatBytes(container.network_rx ?? 0)}{" "}
                        ↑ {formatBytes(container.network_tx ?? 0)}
                      </span>
                    </div>
                  </div>
                )}
              </For>
            </Show>
          </div>
        </div>
      </Show>
    </Show>
  );
}
