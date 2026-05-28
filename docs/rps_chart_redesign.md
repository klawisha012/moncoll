# Design Specification: WAF Dashboard Requests Rate Redesign (RPS / RPM / RPH)

This document specifies the technical design, architectural decisions, and integration plan for the requests rate dashboard panel.

---

## 1. Understanding Summary

* **What**: An interactive toggle buttons group (`RPS`, `RPM`, `RPH`) embedded in the header of the "Requests per Second" dashboard panel.
* **Why**: To provide granular, highly informative, and realistic measurements of traffic:
  * **RPS** displays the *peak (maximum) requests per second* recorded in a given bucket, preserving raw burst metrics.
  * **RPM / RPH** displays the *total count of requests* for the bucket (Minutes when viewing short windows, Hours when viewing long windows).
* **Who**: Security administrators and system operations engineers monitoring active attacks and traffic spikes.
* **Constraints**: 
  * Adaptive resolution (Option A): Minute-level buckets for windows `<= 2 hours` (RPS vs RPM), Hour-level buckets for windows `> 2 hours` (RPS vs RPH).
  * High-performance requirement: The solution must not transfer dense second-by-second data to the client, but aggregate it efficiently in ClickHouse.
* **Non-Goals**: Editing other timeline charts (like status codes or WAF events) or altering the underlying log format.

---

## 2. Assumptions & Non-Functional Requirements (NFRs)

* **Performance**: Under-50ms query execution on ClickHouse. Limit maximum response sizes to `168` points (hours mode) and `120` points (minutes mode) to prevent UI thread lock.
* **ClickHouse Schema**: `logs.nginx_access_log` stores `time_local` as a second-precision `DateTime` type.
* **State Persistence**: The active metric selection (`rps` or `volume`) will be retained in local SolidJS state and optionally persisted to `localStorage` so the preference remains active during page reloads.

---

## 3. Decision Log

### Decision 3.1: Server-Side clickhouse Aggregation (Option 1)
* **Description**: Aggregate raw logs to find peak RPS and totals on the backend/database level.
* **Alternatives Considered**: Frontend-side client processing (Option 2).
* **Rationale**: Raw logs over a 7-day window contain up to hundreds of thousands of entries. Transferring them to the browser would trigger huge memory spikes and network latency. ClickHouse is designed specifically to aggregate millions of rows instantly.

### Decision 3.2: Adaptive Metric Availability (Option A)
* **Description**: Disable / substitute time scales depending on the dashboard hours range.
* **Alternatives Considered**: Universal toggle with no bounds (Option B).
* **Rationale**: Rendering minute-level requests (RPM) for 7 days is unreadable on a small chart card. Hour-level requests (RPH) for a 5-minute window is empty. Automatically aligning the units avoids layout clutter and guarantees smooth ECharts rendering.

---

## 4. Technical Specifications

### A. Backend API & clickhouse
The `requests_per_second` route will accept a new parameter:
```python
@router.get("/requests-per-second")
async def requests_per_second(
    hours: float = _HOURS,
    connection_id: int | None = _CONNECTION_ID,
    metric: str = Query("rps", pattern="^(rps|volume)$"),
    user: User = _U
):
...
```

#### SQL Queries:

1. **Peak RPS (`metric == "rps"`)**
   * **`hours <= 2.0` (Minute buckets)**:
     ```sql
     SELECT toStartOfMinute(time_local) AS t, max(rps_sec) AS rps
     FROM (
         SELECT time_local, count() AS rps_sec
         FROM logs.nginx_access_log
         WHERE time_local >= now() - INTERVAL {minutes} MINUTE {nginx_filter}
         GROUP BY time_local
     )
     GROUP BY t ORDER BY t
     ```
   * **`hours > 2.0` (Hour buckets)**:
     ```sql
     SELECT toStartOfHour(time_local) AS t, max(rps_sec) AS rps
     FROM (
         SELECT time_local, count() AS rps_sec
         FROM logs.nginx_access_log
         WHERE time_local >= now() - INTERVAL {minutes} MINUTE {nginx_filter}
         GROUP BY time_local
     )
     GROUP BY t ORDER BY t
     ```

2. **Total Volume (`metric == "volume"`)**
   * **`hours <= 2.0` (RPM - Requests per minute)**:
     ```sql
     SELECT toStartOfMinute(time_local) AS t, toFloat64(count()) AS rps
     FROM logs.nginx_access_log
     WHERE time_local >= now() - INTERVAL {minutes} MINUTE {nginx_filter}
     GROUP BY t ORDER BY t
     ```
   * **`hours > 2.0` (RPH - Requests per hour)**:
     ```sql
     SELECT toStartOfHour(time_local) AS t, toFloat64(count()) AS rps
     FROM logs.nginx_access_log
     WHERE time_local >= now() - INTERVAL {minutes} MINUTE {nginx_filter}
     GROUP BY t ORDER BY t
     ```

---

### B. Frontend UI & State

1. **`PanelCard` Slots**: Add `headerActions` parameter to render toggle buttons at `card-header` container.
2. **Signals & Auto-Refresh**:
   ```typescript
   const [rpsMetric, setRpsMetric] = createSignal<"rps" | "volume">("rps");
   const rpsDeps = () => [props.hours, props.connectionId, rpsMetric()];
   const rps = useDashboardPanel<RpsPoint[]>(
     () => api.getRequestsPerSecond(props.hours, props.connectionId, rpsMetric()),
     rpsDeps,
     15000,
     () => props.visiblePanels.has("rps")
   );
   ```
3. **Dynamic Graph Props**:
   ```typescript
   unit={rpsMetric() === "rps" ? "rps" : "count"}
   valueLabel={rpsMetric() === "rps" ? settings.t("dashboard.tooltip.reqPerSec") : (props.hours <= 2 ? "RPM" : "RPH")}
   ```
