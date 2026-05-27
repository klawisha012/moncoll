import { Show, onMount, onCleanup, createEffect } from "solid-js";
import type { TrafficDataPoint } from "../../api/client";
import { EmptyState, formatNumber } from "./chart-utils";
import ApexCharts from "apexcharts";
import { useSettings } from "../../context/SettingsContext";

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

export default function TrafficChart(props: Props) {
  const settings = useSettings();
  let chartRef: HTMLDivElement | undefined;
  let chart: ApexCharts | undefined;

  const safeData = () => props.data ?? [];

  onMount(() => {
    if (!chartRef) return;

    const options: any = {
      chart: {
        type: "bar",
        height: 320,
        stacked: true,
        fontFamily: "var(--font-body)",
        foreColor: "var(--text-secondary)",
        toolbar: { show: false },
        animations: { enabled: false },
      },
      series: [
        { name: "Clean", data: [] },
        { name: "Malicious", data: [] },
      ],
      colors: ["#10b981", "#ef4444"],
      grid: {
        borderColor: "var(--border-subtle)",
        strokeDashArray: 3,
        xaxis: { lines: { show: false } },
        yaxis: { lines: { show: true } },
      },
      plotOptions: {
        bar: {
          columnWidth: "70%",
          borderRadius: 2,
        },
      },
      xaxis: {
        type: "category",
        categories: [],
        axisBorder: { show: true, color: "var(--line)", strokeWidth: 2 },
        axisTicks: { show: true, color: "var(--line)" },
        labels: {
          style: {
            fontSize: "11px",
            fontFamily: "var(--font-body)",
          },
        },
      },
      yaxis: {
        labels: {
          formatter: (v: number) => formatNumber(Math.round(v)),
          style: {
            fontSize: "11px",
            fontFamily: "var(--font-body)",
          },
        },
      },
      tooltip: {
        theme: settings.theme === "dark" ? "dark" : "light",
        custom: function({ series, seriesIndex, dataPointIndex, w }: any) {
          const clean = series[0]?.[dataPointIndex] ?? 0;
          const malicious = series[1]?.[dataPointIndex] ?? 0;
          const total = clean + malicious;
          const rate = total > 0 ? ((malicious / total) * 100).toFixed(1) : "0.0";
          
          const point = props.data?.[dataPointIndex];
          if (!point) return '';
          
          const formattedDate = new Date(point.timestamp).toLocaleString([], {
            month: "short",
            day: "numeric",
            hour: "2-digit",
            minute: "2-digit",
          });
          
          const themeClass = settings.theme === "dark" ? "apexcharts-theme-dark" : "apexcharts-theme-light";
          
          return `
            <div class="apexcharts-active-tooltip ${themeClass}" style="padding: 10px; font-family: var(--font-body); border-radius: 4px; border: 1px solid var(--border-subtle); background: var(--card-bg); color: var(--text-primary); box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);">
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
      theme: {
        mode: settings.theme as "dark" | "light",
      },
      dataLabels: { enabled: false },
      legend: {
        position: "top",
        horizontalAlign: "left",
        fontFamily: "var(--font-mono)",
        fontSize: "12px",
        markers: {
          radius: 3,
        },
      },
    };

    chart = new ApexCharts(chartRef, options);
    chart.render();

    onCleanup(() => {
      chart?.destroy();
    });
  });

  createEffect(() => {
    const list = safeData();
    if (!chart || !list.length) return;

    const cleanData = list.map((d) => d.clean);
    const maliciousData = list.map((d) => d.malicious);
    const categories = list.map((d) =>
      new Date(d.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    );

    chart.updateSeries([
      { name: "Clean", data: cleanData },
      { name: "Malicious", data: maliciousData },
    ]);

    const annotations: any[] = [];
    const markers = props.markerTimes;
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

        if (idx >= 0 && idx < categories.length) {
          annotations.push({
            x: categories[idx],
            strokeDashArray: 4,
            borderColor: "#f59e0b",
            borderWidth: 2,
            label: {
              borderColor: "#f59e0b",
              style: {
                color: "#fff",
                background: "#f59e0b",
                fontFamily: "var(--font-body)",
                fontSize: "10px",
              },
              text: "TEST SPIKE",
              orientation: "vertical",
              position: "top",
              offsetY: 10,
            }
          });
        }
      }
    }

    chart.updateOptions({
      xaxis: {
        categories: categories,
      },
      annotations: {
        xaxis: annotations,
      }
    }, false, false);
  });

  createEffect(() => {
    const theme = settings.theme;
    chart?.updateOptions({
      theme: {
        mode: theme as "dark" | "light",
      },
      tooltip: {
        theme: theme as "dark" | "light",
      },
    }, false, false);
  });

  return (
    <Show
      when={props.data && props.data.length > 0}
      fallback={<EmptyState loading={props.loading} message="No traffic data available" />}
    >
      <div ref={chartRef} style={{ width: "100%", height: "320px" }} />
    </Show>
  );
}
