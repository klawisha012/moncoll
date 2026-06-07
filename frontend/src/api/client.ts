const API_BASE = "";

export interface ReloadResponse {
  success: boolean;
  message: string;
}

export type ModSecState = "off" | "detection_only" | "blocking";

export interface SecurityConfig {
  modsec_state: ModSecState;
  geoip_denied_countries: string[];
  crowdsec_active: boolean;
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
  modsec_state: ModSecState;
  geoip_denied_countries: string[];
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
  ip?: string;
}

export interface TestRunResult {
  marker: string;
  status: TestResultStatus;
  http_code: number | null;
  blocked_by: string | null;
  latency_ms: number | null;
  target_url: string;
  error: string | null;
  request_raw: string | null;
  response_raw: string | null;
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
  category: string;
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
  decisions_before: DecisionItem[];
  decisions_after: DecisionItem[];
  bursts_sent: number;
  target_url: string;
}

function buildDashboardQuery(
  hours?: number,
  connectionId?: number | null,
  metric?: string
): string {
  const params = new URLSearchParams();
  if (hours !== undefined) params.set("hours", String(hours));
  if (connectionId != null) params.set("connection_id", String(connectionId));
  if (metric !== undefined) params.set("metric", metric);
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

// ── SaaS auth types ────────────────────────────────────────

export interface User {
  id: number;
  email: string;
  display_name: string;
  platform_role: "admin" | "client";
  tenant_id: number | null;
  tenant_role: "owner" | "member" | null;
  email_verified: boolean;
  totp_enabled: boolean;
}

export type SaasLoginResponse =
  | { user: User }
  | { totp_required: true }
  | { enrol_required: true };

export interface SignupResponse {
  message: string;
  // Present only when WAF_SMTP_HOST is unset (dev mode). Lets the UI show the
  // verify link directly so the user isn't blocked on email delivery.
  dev_verify_url?: string;
}

export interface ForgotPasswordResponse {
  message: string;
  dev_reset_url?: string;
}

export interface ProvidersResponse {
  google: boolean;
  github: boolean;
  // Always a usable Turnstile site key. Falls back to Cloudflare's "always pass"
  // test key (1x00000000000000000000AA) when WAF_TURNSTILE_SITE_KEY is unset,
  // so the captcha widget stays visible in dev/staging.
  captcha_site_key: string;
  captcha_dev_mode: boolean;
  smtp_dev_mode: boolean;
}

export interface TotpSetupResponse {
  secret_base32: string;
  qr_code_data_uri: string;
  recovery_codes: string[];
}

export interface TotpConfirmResponse {
  ok: boolean;
  user: User;
}

// ── Admin types ─────────────────────────────────────────────

export interface TenantRow {
  id: number;
  name: string;
  display_name: string | null;
  owner_email: string | null;
  user_count: number;
  connection_count: number;
  created_at: string;
  suspended_at: string | null;
  last_activity: string | null;
}

export interface TenantDetailUser {
  id: number;
  email: string;
  tenant_role: "owner" | "member";
  last_login_at: string | null;
  email_verified: boolean;
  totp_enabled: boolean;
}

export interface TenantDetailConnection {
  id: number;
  name: string;
  domain: string;
  status: string;
}

export interface TenantDetail {
  tenant: {
    id: number;
    name: string;
    display_name: string | null;
    created_at: string;
    suspended_at: string | null;
  };
  users: TenantDetailUser[];
  connections: TenantDetailConnection[];
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
  getRequestsPerSecond: (hours?: number, connectionId?: number | null, metric?: string) =>
    fetchApi<RpsPoint[]>(
      `/api/dashboard/requests-per-second${buildDashboardQuery(hours, connectionId, metric)}`
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
  runCrowdsecScenario: (scenario_id: string, connection_id: number | null, ip?: string) =>
    fetchApi<CrowdsecRunResult>("/api/tests/crowdsec/run", {
      method: "POST",
      body: JSON.stringify({ scenario_id, connection_id, ip }),
    }),

  // ── Connections API (domain-only model; spec §4) ─────────────
  // Per-deploy edge config — the wizard fetches this on mount so step 3
  // shows the correct A-record value on resume (not just on initial create).
  getEdgeInfo: () => fetchApi<{ edge_ipv4: string }>("/api/edge-info"),
  getConnections: () => fetchApi<Connection[]>("/api/connections"),
  getConnection: (id: number) => fetchApi<Connection>(`/api/connections/${id}`),
  createConnection: (conn: ConnectionCreate) =>
    fetchApi<ConnectionCreateResponse>("/api/connections", {
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

  // Per-connection WAF settings (ModSecurity state + GeoIP denied countries).
  // Persisting via PUT also regenerates the per-connection .conf and triggers
  // `angie -s reload` on the server — no separate reload call is needed.
  getConnectionSecurity: (id: number) =>
    fetchApi<SecurityConfig>(`/api/connections/${id}/security`),
  updateConnectionSecurity: (id: number, payload: SecurityConfig) =>
    fetchApi<SecurityConfig>(`/api/connections/${id}/security`, {
      method: "PUT",
      body: JSON.stringify(payload),
    }),

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

  getCrowdSecStatus: (connectionId?: number | null) => {
    const params = new URLSearchParams();
    if (connectionId != null) params.set("connection_id", String(connectionId));
    const qs = params.toString();
    return fetchApi<CrowdSecStatus>(`/api/crowdsec/status${qs ? `?${qs}` : ""}`);
  },

  getCrowdSecDecisions: (connectionId?: number | null) => {
    const params = new URLSearchParams();
    if (connectionId != null) params.set("connection_id", String(connectionId));
    const qs = params.toString();
    return fetchApi<DecisionItem[]>(`/api/crowdsec/decisions${qs ? `?${qs}` : ""}`);
  },

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
    login: async (
      email: string,
      password: string,
      captchaToken: string,
      totpCode?: string,
    ): Promise<SaasLoginResponse> => {
      try {
        return await fetchApi<SaasLoginResponse>("/api/auth/login", {
          method: "POST",
          body: JSON.stringify({
            email,
            password,
            captcha_token: captchaToken,
            ...(totpCode !== undefined ? { totp_code: totpCode } : {}),
          }),
        });
      } catch (err) {
        // Backend signals next-step continuation via HTTP-error responses
        // carrying a sentinel `detail` (e.g. 401 totp_required, 403
        // totp_enrol_required) plus a continuation cookie. fetchApi turns
        // those into thrown Errors; translate them back to the structured
        // shape Login.tsx expects so the user gets the TOTP / enrol screen
        // instead of a raw red error.
        const msg = err instanceof Error ? err.message : "";
        if (msg === "totp_required") return { totp_required: true };
        if (msg === "totp_enrol_required") return { enrol_required: true };
        throw err;
      }
    },

    signup: (
      email: string,
      password: string,
      tenantName: string,
      captchaToken: string,
      displayName?: string,
    ) =>
      fetchApi<SignupResponse>("/api/auth/signup", {
        method: "POST",
        body: JSON.stringify({
          email,
          password,
          tenant_name: tenantName,
          captcha_token: captchaToken,
          ...(displayName !== undefined ? { display_name: displayName } : {}),
        }),
      }),

    verifyEmail: (token: string) =>
      fetchApi<{ message: string }>("/api/auth/verify-email", {
        method: "POST",
        body: JSON.stringify({ token }),
      }),

    forgotPassword: (email: string, captchaToken: string) =>
      fetchApi<ForgotPasswordResponse>("/api/auth/password/forgot", {
        method: "POST",
        body: JSON.stringify({ email, captcha_token: captchaToken }),
      }),

    resetPassword: (token: string, newPassword: string) =>
      fetchApi<{ message: string }>("/api/auth/password/reset", {
        method: "POST",
        body: JSON.stringify({ token, new_password: newPassword }),
      }),

    getProviders: () => fetchApi<ProvidersResponse>("/api/auth/providers"),

    totpSetup: () =>
      fetchApi<TotpSetupResponse>("/api/auth/totp/setup", { method: "POST" }),

    totpConfirm: (code: string) =>
      fetchApi<TotpConfirmResponse>("/api/auth/totp/confirm", {
        method: "POST",
        body: JSON.stringify({ code }),
      }),

    logout: () =>
      fetchApi<void>("/api/auth/logout", { method: "POST" }),

    me: async (): Promise<User | null> => {
      try {
        return await fetchApi<User>("/api/auth/me");
      } catch {
        return null;
      }
    },

    changePassword: (currentPassword: string, newPassword: string) =>
      fetchApi<User>("/api/auth/change-password", {
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

  // ── Admin ───────────────────────────────────────────────
  admin: {
    listTenants: () => fetchApi<TenantRow[]>("/api/admin/tenants"),

    getTenant: (id: number) => fetchApi<TenantDetail>(`/api/admin/tenants/${id}`),

    suspendTenant: (id: number) =>
      fetchApi<{ suspended_at: string }>(`/api/admin/tenants/${id}/suspend`, { method: "POST" }),

    unsuspendTenant: (id: number) =>
      fetchApi<{ suspended_at: null }>(`/api/admin/tenants/${id}/unsuspend`, { method: "POST" }),

    deleteTenant: (id: number, confirm: string) =>
      fetchApi<void>(`/api/admin/tenants/${id}?confirm=${encodeURIComponent(confirm)}`, { method: "DELETE" }),
  },

  // ── Real-time (Centrifugo) ──
  // Short-lived HMAC JWT for centrifuge-js connect. centrifuge-js calls
  // this on initial connect and on token refresh (via getToken callback).
  getRealtimeToken: () =>
    fetchApi<{ token: string; ttl_seconds: number }>("/api/realtime/token", {
      method: "POST",
    }),
};
