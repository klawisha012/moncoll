import { Show, onMount, onCleanup, createEffect } from "solid-js";
import type { TrafficDataPoint } from "../../api/client";
import { EmptyState, formatNumber } from "./chart-utils";
import { useSettings } from "../../context/SettingsContext";
import * as echarts from "echarts";

interface Props {
  data: TrafficDataPoint[] | null;
  loading: boolean;
  /**
   * Optional ISO timestamps to highlight on the chart — used by the Tests
   * page to overlay a "spike" marker on the bars that landed during a test
   * run. The matching bar is highlighted with a glow ring; if no bar matches
   * (e.g. the marker landed between bucket boundaries) we draw a vertical
   * dashed pin at the closest bucket so the user can still see where the
   * test fired.
   */
  markerTimes?: string[];
}

function TrafficChartInner(props: {
  data: TrafficDataPoint[];
  loading: boolean;
  markerTimes?: string[];
}) {
  const settings = useSettings();
  let chartRef: HTMLDivElement | undefined;
  let chart: echarts.ECharts | undefined;

  const categories = () => props.data.map(d => 
    new Date(d.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  );

  const cleanData = () => props.data.map(d => d.clean);
  const maliciousData = () => props.data.map(d => d.malicious);

  const annotations = () => {
    const list = props.data;
    const markers = props.markerTimes;
    const items: { value: string }[] = [];
    if (markers && markers.length && list.length > 0) {
      const bucketMs = list.map((d) => new Date(d.timestamp).getTime());
      for (const ts of markers) {
        const t = new Date(ts).getTime();
        if (Number.isNaN(t)) continue;

        let idx = -1;
        for (let i = 0; i < bucketMs.length; i++) {
          if (bucketMs[i] <= t) idx = i;
          else break;
        }
        if (idx < 0) idx = 0;
        if (idx >= 0 && idx < list.length) {
          items.push({ value: new Date(list[idx].timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) });
        }
      }
    }
    return items;
  };

  onMount(() => {
    const handleResize = () => {
      chart?.resize();
    };
    window.addEventListener("resize", handleResize);

    onCleanup(() => {
      window.removeEventListener("resize", handleResize);
      if (chart) {
        chart.dispose();
      }
    });
  });

  createEffect(() => {
    if (!chartRef) return;
    if (!chart) {
      chart = echarts.init(chartRef);
    }

    const theme = settings.theme;
    const isDark = theme === "dark";

    const option: echarts.EChartsOption = {
      grid: {
        top: 40,
        left: 50,
        right: 20,
        bottom: 30,
        containLabel: false
      },
      tooltip: {
        trigger: "axis",
        backgroundColor: isDark ? "#1a1915" : "#fdfcf7",
        borderColor: "var(--border-subtle)",
        borderWidth: 1,
        textStyle: {
          color: "var(--text-primary)",
          fontFamily: "var(--font-body)",
          fontSize: 12
        },
        shadowColor: "rgba(0, 0, 0, 0.2)",
        shadowBlur: 10,
        padding: 10,
        formatter: (params: any) => {
          if (!params || params.length === 0) return "";
          const idx = params[0].dataIndex;
          const point = props.data[idx];
          if (!point) return "";

          const clean = point.clean ?? 0;
          const malicious = point.malicious ?? 0;
          const total = clean + malicious;
          const rate = total > 0 ? ((malicious / total) * 100).toFixed(1) : "0.0";
          const formattedDate = new Date(point.timestamp).toLocaleString([], {
            month: "short",
            day: "numeric",
            hour: "2-digit",
            minute: "2-digit",
          });

          return `
            <div style="font-family: var(--font-body); min-width: 160px;">
              <div style="font-weight: 600; margin-bottom: 6px; font-size: 12px; border-bottom: 1px solid var(--border-subtle); padding-bottom: 4px;">
                ${formattedDate}
              </div>
              <div style="font-size: 11px; display: flex; flex-direction: column; gap: 4px;">
                <div style="display: flex; justify-content: space-between; gap: 12px; align-items: center;">
                  <span style="display: flex; align-items: center; gap: 6px;">
                    <span style="width: 8px; height: 8px; border-radius: 50%; background: #10b981; display: inline-block;"></span>
                    Clean:
                  </span>
                  <span style="font-family: var(--font-mono); font-weight: 500;">${clean.toLocaleString()}</span>
                </div>
                <div style="display: flex; justify-content: space-between; gap: 12px; align-items: center;">
                  <span style="display: flex; align-items: center; gap: 6px;">
                    <span style="width: 8px; height: 8px; border-radius: 50%; background: #ef4444; display: inline-block;"></span>
                    Malicious:
                  </span>
                  <span style="font-family: var(--font-mono); font-weight: 500;">${malicious.toLocaleString()}</span>
                </div>
                <div style="display: flex; justify-content: space-between; gap: 12px; border-top: 1px dashed var(--border-subtle); margin-top: 4px; padding-top: 4px; align-items: center;">
                  <span>Total:</span>
                  <span style="font-family: var(--font-mono); font-weight: 600;">${total.toLocaleString()}</span>
                </div>
                <div style="display: flex; justify-content: space-between; gap: 12px; align-items: center;">
                  <span>Block rate:</span>
                  <span style="font-family: var(--font-mono); font-weight: 600; color: #ef4444;">${rate}%</span>
                </div>
              </div>
            </div>
          `;
        }
      },
      legend: {
        show: true,
        left: "left",
        top: 0,
        textStyle: {
          color: "var(--text-secondary)",
          fontFamily: "var(--font-mono)",
          fontSize: 11
        },
        itemWidth: 10,
        itemHeight: 10,
        icon: "rect"
      },
      xAxis: {
        type: "category",
        data: categories(),
        axisLine: {
          lineStyle: {
            color: "var(--border-subtle)",
            width: 1
          }
        },
        axisLabel: {
          color: "var(--text-secondary)",
          fontFamily: "var(--font-body)",
          fontSize: 10
        },
        boundaryGap: true
      },
      yAxis: {
        type: "value",
        axisLine: { show: false },
        splitLine: {
          lineStyle: {
            color: "var(--border-subtle)",
            type: "dashed"
          }
        },
        axisLabel: {
          color: "var(--text-secondary)",
          fontFamily: "var(--font-body)",
          fontSize: 10,
          formatter: (v: number) => formatNumber(Math.round(v))
        }
      },
      series: [
        {
          name: "Clean",
          type: "bar",
          stack: "traffic",
          color: "#10b981",
          barWidth: "60%",
          data: cleanData()
        },
        {
          name: "Malicious",
          type: "bar",
          stack: "traffic",
          color: "#ef4444",
          barWidth: "60%",
          itemStyle: {
            borderRadius: [2, 2, 0, 0]
          },
          markLine: annotations().length > 0 ? {
            symbol: "none",
            lineStyle: {
              color: "#f59e0b",
              type: "dashed",
              width: 1.5
            },
            label: {
              show: true,
              formatter: "TEST SPIKE",
              position: "end",
              color: "#f59e0b",
              fontFamily: "var(--font-mono)",
              fontSize: 9
            },
            data: annotations().map(ann => ({ xAxis: ann.value }))
          } : undefined,
          data: maliciousData()
        }
      ]
    };

    chart.setOption(option);
  });

  return (
    <div ref={chartRef} style={{ width: "100%", height: "320px" }} />
  );
}

export default function TrafficChart(props: Props) {
  return (
    <Show
      when={props.data && props.data.length > 0}
      fallback={<EmptyState loading={props.loading} message="No traffic data available" />}
    >
      <TrafficChartInner data={props.data!} loading={props.loading} markerTimes={props.markerTimes} />
    </Show>
  );
}
