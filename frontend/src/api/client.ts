const API_BASE = "";

export interface ReloadResponse {
  success: boolean;
  message: string;
}

export interface ModSecuritySettings {
  rule_engine: string;
  request_body_access: boolean;
  response_body_access: boolean;
  request_body_limit: number;
  request_body_no_files_limit: number;
  request_body_limit_action: string;
  request_body_json_depth_limit: number;
  arguments_limit: number;
  response_body_mime_types: string[];
  response_body_limit: number;
  response_body_limit_action: string;
  audit_engine: string;
  audit_log_type: string;
  audit_log_format: string;
  audit_log_parts: string;
  audit_log_relevant_status: string;
  audit_log_path: string;
  pcre_match_limit: number;
  pcre_match_limit_recursion: number;
  status_engine: boolean;
  tmp_dir: string;
  data_dir: string;
}

export interface ModuleInfo {
  name: string;
  loaded: boolean;
}

export type HttpVersion = "h1" | "h2" | "h3";

export type CompressionAlgo = "auto" | "gzip" | "brotli" | "zstd" | "none";

export type OriginTlsMode = "strict" | "lenient";

export type ConnectionStatus =
  | "pending_verification"
  | "pending_dns"
  | "provisioning_cert"
  | "active"
  | "error";

export interface Connection {
  id: number;
  user_id: number | null;
  name: string;
  domain: string;
  origin_hosts: string[];
  origin_port: number;
  origin_tls_mode: OriginTlsMode;
  verify_token: string;
  verified_at: string | null;
  status: ConnectionStatus;
  status_detail: string | null;
  acme_retry_count: number;
  acme_next_retry_at: string | null;
  next_poll_at: string | null;
  dns_ttl_seconds: number;
  last_checked_at: string | null;
  http_versions: string; // CSV of HttpVersion
  compression_algo: CompressionAlgo;
  enabled: boolean;
  ssl_cert_path: string | null;
  ssl_key_path: string | null;
  created_at: string;
  updated_at: string;
}

export interface ConnectionCreate {
  name: string;
  domain: string;
  origin_port?: number;
  origin_tls_mode?: OriginTlsMode;
  http_versions?: string;
  compression_algo?: CompressionAlgo;
}

export interface ConnectionUpdate {
  name?: string;
  enabled?: boolean;
  origin_port?: number;
  origin_tls_mode?: OriginTlsMode;
  http_versions?: string;
  compression_algo?: CompressionAlgo;
}

export interface VerifyInstructions {
  txt_record_name: string;
  txt_record_value: string;
  edge_ipv4: string;
}

export interface ConnectionCreateResponse {
  connection: Connection;
  instructions: VerifyInstructions;
}

export interface AngieSettings {
  worker_processes: string;
  worker_rlimit_nofile: number;
  worker_connections: number;
  keepalive_timeout: number;
  sendfile: boolean;
  denied_countries: string[];
  modules: ModuleInfo[];
}

// ── CrowdSec types ─────────────────────────────────────────

export interface CrowdSecStatus {
  running: boolean;
  version: string;
  decisions_count: number;
  scenarios_count: number;
  alerts_count: number;
}

export interface DecisionItem {
  id?: number;
  source: string;
  scope: string;
  value: string;
  type: string;
  reason: string;
  duration: string;
  until: string;
  alert_id?: number;
  blocked_on: string[];
}

export interface DecisionCreate {
  ip: string;
  duration?: string;
  reason?: string;
  type?: string;
  connection_ids?: number[];
}

export interface DecisionResponse {
  success: boolean;
  message: string;
  ip?: string;
  action?: string;
}

export interface ScenarioInfo {
  name: string;
  description: string;
  loaded: boolean;
  type: string;
  labels: string[];
}

export interface ManualBlockLogEntry {
  timestamp: string;
  action: string;
  ip: string;
  duration: string;
  reason: string;
  source: string;
}

export interface AlertItem {
  id?: number;
  scenario: string;
  message: string;
  source_ip: string;
  source_scope: string;
  start_at: string;
  stop_at: string;
  capacity?: number;
  decisions_count: number;
}

export interface HubScenarioItem {
  name: string;
  description: string;
  author: string;
  labels: string[];
  installed: boolean;
}

export interface ContainerMetrics {
  name: string;
  cpu: number;
  memory: number;
  memory_percent: number;
  network_rx: number;
  network_tx: number;
}

export interface Metrics {
  total_requests: number;
  total_requests_change: number;
  blocked_threats: number;
  high_severity_count: number;
  system_health: number;
  avg_latency_ms: number;
  active_rules: number;
}

export interface TrafficDataPoint {
  timestamp: string;
  clean: number;
  malicious: number;
}

export interface ThreatOrigin {
  country: string;
  country_code: string;
  blocks_percent: number;
}

export interface SecurityEvent {
  timestamp: string;
  type: string;
  ip: string;
  country: string;
  path: string;
  severity: string;
}

export interface GeoipMapPoint {
  longitude: number;
  latitude: number;
  country_code: string;
  city_name: string;
  hits: number;
}

export interface UnresolvedIp {
  ip: string;
  hits: number;
}

// ── Extended analytics types ───────────────────────────────────────

export interface TimelinePoint {
  timestamp: string;
  hits: number;
}

export interface RuleHit {
  rule: string;
  hits: number;
}

export interface SeveritySlice {
  severity: string;
  hits: number;
}

export interface IpHit {
  ip: string;
  hits: number;
}

export interface AnomalyPoint {
  timestamp: string;
  score: number;
}

export interface TagHit {
  tag: string;
  hits: number;
}

export interface UriHit {
  uri: string;
  hits: number;
}

export interface RuleFileHit {
  file: string;
  hits: number;
}

export interface StatusCodePoint {
  timestamp: string;
  c2xx: number;
  c3xx: number;
  c4xx: number;
  c5xx: number;
}

export interface UserAgentHit {
  user_agent: string;
  hits: number;
}

export interface BytesPoint {
  timestamp: string;
  bytes: number;
}

export interface RpsPoint {
  timestamp: string;
  rps: number;
}

export interface CountryHit {
  country_code: string;
  hits: number;
}

// ── Tests tab types ─────────────────────────────────────────

export type TestFamily =
  | "xss"
  | "sqli"
  | "rce"
  | "rfi"
  | "lfi"
  | "scanner"
  | "java"
  | "php"
  | "session_fixation"
  | "multipart"
  | "method"
  | "protocol_attack"
  | "protocol_enforce"
  | "generic"
  | "blocking"
  | "crowdsec";

export interface TestCase {
  id: string;
  family: TestFamily;
  rule_id: string;
  description: string;
  method: "GET" | "POST";
  path: string;
  query: Record<string, string>;
  headers: Record<string, string>;
  body: string | null;
}

export interface TestsCatalog {
  tests: TestCase[];
  generated_at: string | null;
}

export type TestResultStatus =
  | "blocked"
  | "fired-but-not-blocked"
  | "passed"
  | "timeout";

export interface TestRunRequest {
  test_id: string;
  connection_id: number | null;
}

export interface TestRunResult {
  marker: string;
  status: TestResultStatus;
  http_code: number | null;
  blocked_by: string | null;
  latency_ms: number | null;
  target_url: string;
  error: string | null;
}

export interface TestTrafficEvent {
  timestamp: string;
  rule_id: string;
  client_ip: string;
  uri: string;
  method: string;
  severity: string;
  message: string;
  anomaly_score: number;
}

export interface TestTrafficResponse {
  events: TestTrafficEvent[];
  timestamps: string[];
}

export interface CrowdsecScenario {
  id: string;
  scenario: string;
  description: string;
  burst_size: number;
}

export interface CrowdsecCatalog {
  scenarios: CrowdsecScenario[];
}

export interface CrowdsecRunResult {
  scenario: string;
  source_ip: string;
  started_at: string;
  decisions_after: string[];
  bursts_sent: number;
  target_url: string;
}

function buildDashboardQuery(
  hours?: number,
  connectionId?: number | null
): string {
  const params = new URLSearchParams();
  if (hours !== undefined) params.set("hours", String(hours));
  if (connectionId != null) params.set("connection_id", String(connectionId));
  const qs = params.toString();
  return qs ? `?${qs}` : "";
}

async function fetchApi<T>(url: string, options?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    ...(options?.headers
      ? Object.fromEntries(
          new Headers(options.headers as HeadersInit).entries()
        )
      : {}),
  };
  // Only set Content-Type for requests with a body
  if (options?.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(`${API_BASE}${url}`, {
    headers,
    credentials: "include",
    ...options,
  });

  if (!response.ok) {
    const error = await response
      .json()
      .catch(() => ({ detail: response.statusText }));
    if (response.status === 401 && !url.startsWith("/api/auth/")) {
      window.dispatchEvent(new CustomEvent("auth:unauthorized"));
    }
    throw new Error(error.detail || "API request failed");
  }

  if (response.status === 204) {
    return {} as T;
  }

  return response.json();
}

// ── Auth types ─────────────────────────────────────────────

export type UserRole = "admin" | "viewer";

export interface UserPublic {
  id: number;
  username: string;
  role: UserRole;
  must_change_password: boolean;
  created_at: string;
  updated_at: string;
}

export interface LoginResponse {
  user: UserPublic;
  must_change_password: boolean;
}

export interface UserCreateRequest {
  username: string;
  password: string;
  role: UserRole;
}

export interface UserUpdateRequest {
  role?: UserRole;
  password?: string;
}

export interface CertificateStatus {
  certificate_exists: boolean;
  key_exists: boolean;
  certificate_path: string | null;
  key_path: string | null;
}

export interface CertificateResponse {
  success: boolean;
  message: string;
  certificate_path?: string;
  key_path?: string;
  client_name?: string;
}

export const api = {
  getModsecSettings: () =>
    fetchApi<ModSecuritySettings>("/api/modsecurity/settings"),
  updateModsecSettings: (settings: ModSecuritySettings) =>
    fetchApi<ModSecuritySettings>("/api/modsecurity/settings", {
      method: "PUT",
      body: JSON.stringify(settings),
    }),

  getAngieSettings: () => fetchApi<AngieSettings>("/api/angie/settings"),
  updateAngieSettings: (settings: AngieSettings) =>
    fetchApi<AngieSettings>("/api/angie/settings", {
      method: "PUT",
      body: JSON.stringify(settings),
    }),

  reloadModsec: () =>
    fetchApi<ReloadResponse>("/api/modsecurity/reload", { method: "POST" }),
  reloadAngie: () =>
    fetchApi<ReloadResponse>("/api/angie/reload", { method: "POST" }),

  getMetrics: (hours?: number, connectionId?: number | null) =>
    fetchApi<Metrics>(`/api/dashboard/metrics${buildDashboardQuery(hours, connectionId)}`),
  getContainerMetrics: () =>
    fetchApi<{ containers: ContainerMetrics[] }>("/api/monitoring/metrics"),
  getTraffic: (hours?: number, connectionId?: number | null) =>
    fetchApi<TrafficDataPoint[]>(
      `/api/dashboard/traffic${buildDashboardQuery(hours, connectionId)}`
    ),
  getThreatOrigins: (hours?: number, connectionId?: number | null) =>
    fetchApi<ThreatOrigin[]>(
      `/api/dashboard/threat-origins${buildDashboardQuery(hours, connectionId)}`
    ),
  getGeoipMap: (hours?: number, connectionId?: number | null) =>
    fetchApi<GeoipMapPoint[]>(
      `/api/dashboard/geoip-map${buildDashboardQuery(hours, connectionId)}`
    ),
  getGeoipUnresolved: (hours?: number, connectionId?: number | null) =>
    fetchApi<UnresolvedIp[]>(
      `/api/dashboard/geoip-unresolved${buildDashboardQuery(hours, connectionId)}`
    ),
  getEvents: (
    limit = 50,
    severity = "all",
    hours?: number,
    connectionId?: number | null
  ) => {
    const params = new URLSearchParams();
    params.set("limit", String(limit));
    params.set("severity", severity);
    if (hours !== undefined) params.set("hours", String(hours));
    if (connectionId != null) params.set("connection_id", String(connectionId));
    return fetchApi<SecurityEvent[]>(`/api/dashboard/events?${params.toString()}`);
  },

  // ── Extended analytics getters ──
  getWafEventsTimeline: (hours?: number, connectionId?: number | null) =>
    fetchApi<TimelinePoint[]>(
      `/api/dashboard/waf-events-timeline${buildDashboardQuery(hours, connectionId)}`
    ),
  getTopRules: (hours?: number, connectionId?: number | null) =>
    fetchApi<RuleHit[]>(
      `/api/dashboard/top-rules${buildDashboardQuery(hours, connectionId)}`
    ),
  getSeverityDistribution: (hours?: number, connectionId?: number | null) =>
    fetchApi<SeveritySlice[]>(
      `/api/dashboard/severity-distribution${buildDashboardQuery(hours, connectionId)}`
    ),
  getTopAttackingIps: (hours?: number, connectionId?: number | null) =>
    fetchApi<IpHit[]>(
      `/api/dashboard/top-attacking-ips${buildDashboardQuery(hours, connectionId)}`
    ),
  getAnomalyScore: (hours?: number, connectionId?: number | null) =>
    fetchApi<AnomalyPoint[]>(
      `/api/dashboard/anomaly-score${buildDashboardQuery(hours, connectionId)}`
    ),
  getTopTags: (hours?: number, connectionId?: number | null) =>
    fetchApi<TagHit[]>(
      `/api/dashboard/top-tags${buildDashboardQuery(hours, connectionId)}`
    ),
  getTopUris: (hours?: number, connectionId?: number | null) =>
    fetchApi<UriHit[]>(
      `/api/dashboard/top-uris${buildDashboardQuery(hours, connectionId)}`
    ),
  getTopRuleFiles: (hours?: number, connectionId?: number | null) =>
    fetchApi<RuleFileHit[]>(
      `/api/dashboard/top-rule-files${buildDashboardQuery(hours, connectionId)}`
    ),
  getStatusCodes: (hours?: number, connectionId?: number | null) =>
    fetchApi<StatusCodePoint[]>(
      `/api/dashboard/status-codes${buildDashboardQuery(hours, connectionId)}`
    ),
  getTopUserAgents: (hours?: number, connectionId?: number | null) =>
    fetchApi<UserAgentHit[]>(
      `/api/dashboard/top-user-agents${buildDashboardQuery(hours, connectionId)}`
    ),
  getTrafficVolume: (hours?: number, connectionId?: number | null) =>
    fetchApi<BytesPoint[]>(
      `/api/dashboard/traffic-volume${buildDashboardQuery(hours, connectionId)}`
    ),
  getRequestsPerSecond: (hours?: number, connectionId?: number | null) =>
    fetchApi<RpsPoint[]>(
      `/api/dashboard/requests-per-second${buildDashboardQuery(hours, connectionId)}`
    ),
  getRequestsByCountry: (hours?: number, connectionId?: number | null) =>
    fetchApi<CountryHit[]>(
      `/api/dashboard/requests-by-country${buildDashboardQuery(hours, connectionId)}`
    ),
  getTopClientIps: (hours?: number, connectionId?: number | null) =>
    fetchApi<IpHit[]>(
      `/api/dashboard/top-client-ips${buildDashboardQuery(hours, connectionId)}`
    ),

  // Tests tab — admin-only catalog + runner
  getTestsCatalog: () => fetchApi<TestsCatalog>("/api/tests/catalog"),
  runTest: (req: TestRunRequest) =>
    fetchApi<TestRunResult>("/api/tests/run", {
      method: "POST",
      body: JSON.stringify(req),
    }),
  getTestTrafficByMarker: (marker: string) =>
    fetchApi<TestTrafficResponse>(`/api/dashboard/test-traffic/${encodeURIComponent(marker)}`),
  getCrowdsecTestCatalog: () => fetchApi<CrowdsecCatalog>("/api/tests/crowdsec/catalog"),
  runCrowdsecScenario: (scenario_id: string) =>
    fetchApi<CrowdsecRunResult>("/api/tests/crowdsec/run", {
      method: "POST",
      body: JSON.stringify({ scenario_id }),
    }),

  // ── Connections API (domain-only model; spec §4) ─────────────
  // Per-deploy edge config — the wizard fetches this on mount so step 3
  // shows the correct A-record value on resume (not just on initial create).
  getEdgeInfo: () => fetchApi<{ edge_ipv4: string }>("/api/connections/edge-info"),
  getConnections: () => fetchApi<Connection[]>("/api/connections/"),
  getConnection: (id: number) => fetchApi<Connection>(`/api/connections/${id}`),
  createConnection: (conn: ConnectionCreate) =>
    fetchApi<ConnectionCreateResponse>("/api/connections/", {
      method: "POST",
      body: JSON.stringify(conn),
    }),
  // PATCH (not PUT) — only mutable fields land on the wire (name, enabled,
  // origin_tls_mode, http_versions, compression_algo). Domain is immutable.
  updateConnection: (id: number, conn: ConnectionUpdate) =>
    fetchApi<Connection>(`/api/connections/${id}`, {
      method: "PATCH",
      body: JSON.stringify(conn),
    }),
  deleteConnection: (id: number) =>
    fetchApi<void>(`/api/connections/${id}`, { method: "DELETE" }),
  // Kick the background poller to run NOW (zeros next_poll_at). Used by the
  // wizard's "Verify now" button and the list's "Retry" button on errored rows.
  probeConnection: (id: number) =>
    fetchApi<Connection>(`/api/connections/${id}/probe`, { method: "POST" }),
  reloadConnections: () =>
    fetchApi<ReloadResponse>("/api/connections/reload", { method: "POST" }),

  // SSL Certificates API
  getCertificateStatus: (connectionId: number) =>
    fetchApi<CertificateStatus>(`/api/ssl/status/${connectionId}`),
  requestCertificate: (connectionId: number, domains?: string[]) =>
    fetchApi<CertificateResponse>(`/api/ssl/request/${connectionId}`, {
      method: "POST",
      body: JSON.stringify({ domains, challenge_type: "http" }),
    }),
  regenerateCertificate: (connectionId: number) =>
    fetchApi<CertificateResponse>(`/api/ssl/regenerate/${connectionId}`, {
      method: "POST",
    }),

  // ── CrowdSec API ──────────────────────────────────────────

  getCrowdSecStatus: () =>
    fetchApi<CrowdSecStatus>("/api/crowdsec/status"),

  getCrowdSecDecisions: () =>
    fetchApi<DecisionItem[]>("/api/crowdsec/decisions"),

  addCrowdSecDecision: (req: DecisionCreate) =>
    fetchApi<DecisionResponse>("/api/crowdsec/decisions", {
      method: "POST",
      body: JSON.stringify(req),
    }),

  deleteCrowdSecDecision: (ip: string) =>
    fetchApi<DecisionResponse>(`/api/crowdsec/decisions/${encodeURIComponent(ip)}`, {
      method: "DELETE",
    }),

  deleteAllCrowdSecDecisions: () =>
    fetchApi<DecisionResponse>("/api/crowdsec/decisions", {
      method: "DELETE",
    }),

  getCrowdSecManualBlocks: (limit = 100, hours?: number) => {
    const params = new URLSearchParams({ limit: String(limit) });
    if (hours !== undefined) params.set("hours", String(hours));
    return fetchApi<ManualBlockLogEntry[]>(
      `/api/crowdsec/manual-blocks?${params.toString()}`
    );
  },

  getCrowdSecScenarios: () =>
    fetchApi<ScenarioInfo[]>("/api/crowdsec/scenarios"),

  getCrowdSecScenarioHub: () =>
    fetchApi<HubScenarioItem[]>("/api/crowdsec/scenarios/hub"),

  installCrowdSecScenario: (name: string) =>
    fetchApi<{success: boolean; message: string}>(
      `/api/crowdsec/scenarios/install/${encodeURIComponent(name)}`,
      { method: "POST" }
    ),

  removeCrowdSecScenario: (name: string) =>
    fetchApi<{success: boolean; message: string}>(
      `/api/crowdsec/scenarios/remove/${encodeURIComponent(name)}`,
      { method: "DELETE" }
    ),

  reloadCrowdSec: () =>
    fetchApi<ReloadResponse>("/api/crowdsec/reload", { method: "POST" }),

  getCrowdSecAlerts: (hours?: number) =>
    fetchApi<AlertItem[]>(
      `/api/crowdsec/alerts${hours !== undefined ? `?hours=${hours}` : ""}`
    ),

  getCrowdSecServiceStatus: () =>
    fetchApi<{enabled: boolean}>("/api/crowdsec/service-status"),

  toggleCrowdSecService: (enabled: boolean) =>
    fetchApi<{success: boolean; message: string; enabled: boolean}>(
      "/api/crowdsec/toggle",
      {
        method: "POST",
        body: JSON.stringify({ enabled }),
      }
    ),

  toggleCrowdSecScenario: (name: string) =>
    fetchApi<{success: boolean; message: string; name: string; enabled: boolean}>(
      `/api/crowdsec/scenarios/toggle/${encodeURIComponent(name)}`,
      { method: "POST" }
    ),

  // ── Auth ────────────────────────────────────────────────

  auth: {
    login: (username: string, password: string) =>
      fetchApi<LoginResponse>("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      }),

    logout: () =>
      fetchApi<void>("/api/auth/logout", { method: "POST" }),

    me: async (): Promise<UserPublic | null> => {
      try {
        return await fetchApi<UserPublic>("/api/auth/me");
      } catch {
        return null;
      }
    },

    changePassword: (currentPassword: string, newPassword: string) =>
      fetchApi<UserPublic>("/api/auth/change-password", {
        method: "POST",
        body: JSON.stringify({
          current_password: currentPassword,
          new_password: newPassword,
        }),
      }),

    listUsers: () => fetchApi<UserPublic[]>("/api/auth/users"),

    createUser: (user: UserCreateRequest) =>
      fetchApi<UserPublic>("/api/auth/users", {
        method: "POST",
        body: JSON.stringify(user),
      }),

    updateUser: (id: number, patch: UserUpdateRequest) =>
      fetchApi<UserPublic>(`/api/auth/users/${id}`, {
        method: "PUT",
        body: JSON.stringify(patch),
      }),

    deleteUser: (id: number) =>
      fetchApi<void>(`/api/auth/users/${id}`, { method: "DELETE" }),
  },
};
