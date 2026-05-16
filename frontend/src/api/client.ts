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

export type SourceType = "nginx_config" | "static_generate" | "container";

export interface Connection {
  id: number;
  name: string;
  domains: string[];
  source_type: SourceType;
  nginx_config_path: string | null;
  static_dir: string | null;
  backend_url: string;
  enabled: boolean;
  ssl_enabled: boolean;
  ssl_cert_path: string | null;
  ssl_key_path: string | null;
  preserve_host: boolean;
  custom_nginx_config: string | null;
  created_at: string;
  updated_at: string;
}

export interface ConnectionCreate {
  name: string;
  domains?: string[];
  source_type?: SourceType;
  nginx_config_path?: string | null;
  static_dir?: string | null;
  backend_url?: string;
  enabled?: boolean;
  ssl_enabled?: boolean;
  ssl_cert_path?: string | null;
  ssl_key_path?: string | null;
  preserve_host?: boolean;
  custom_nginx_config?: string | null;
}

export interface ConnectionUpdate {
  name?: string;
  domains?: string[];
  source_type?: SourceType;
  nginx_config_path?: string | null;
  static_dir?: string | null;
  backend_url?: string;
  enabled?: boolean;
  ssl_enabled?: boolean;
  ssl_cert_path?: string | null;
  ssl_key_path?: string | null;
  preserve_host?: boolean;
  custom_nginx_config?: string | null;
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

  getMetrics: () => fetchApi<Metrics>("/api/dashboard/metrics"),
  getContainerMetrics: () =>
    fetchApi<{ containers: ContainerMetrics[] }>("/api/monitoring/metrics"),
  getTraffic: () => fetchApi<TrafficDataPoint[]>("/api/dashboard/traffic"),
  getThreatOrigins: () =>
    fetchApi<ThreatOrigin[]>("/api/dashboard/threat-origins"),
  getGeoipMap: (hours?: number) =>
    fetchApi<GeoipMapPoint[]>(
      `/api/dashboard/geoip-map${hours ? `?hours=${hours}` : ""}`
    ),
  getEvents: (limit = 50, severity = "all") =>
    fetchApi<SecurityEvent[]>(
      `/api/dashboard/events?limit=${limit}&severity=${severity}`
    ),

  // Connections API
  getConnections: () => fetchApi<Connection[]>("/api/connections/"),
  getConnection: (id: number) => fetchApi<Connection>(`/api/connections/${id}`),
  createConnection: (conn: ConnectionCreate) =>
    fetchApi<Connection>("/api/connections/", {
      method: "POST",
      body: JSON.stringify(conn),
    }),
  updateConnection: (id: number, conn: ConnectionUpdate) =>
    fetchApi<Connection>(`/api/connections/${id}`, {
      method: "PUT",
      body: JSON.stringify(conn),
    }),
  deleteConnection: (id: number) =>
    fetchApi<void>(`/api/connections/${id}`, { method: "DELETE" }),
  reloadConnections: () =>
    fetchApi<ReloadResponse>("/api/connections/reload", { method: "POST" }),

  // Upload a static site file (e.g. index.html) — returns a backend path
  // that can be used as static_dir when creating/updating a connection.
  uploadStaticFile: async (file: File): Promise<{ path: string; filename: string }> => {
    const formData = new FormData();
    formData.append("file", file);
    const response = await fetch(`${API_BASE}/api/connections/upload-static`, {
      method: "POST",
      body: formData,
      credentials: "include",
    });
    if (!response.ok) {
      if (response.status === 401) {
        window.dispatchEvent(new CustomEvent("auth:unauthorized"));
      }
      const error = await response.json().catch(() => ({ detail: response.statusText }));
      throw new Error(error.detail || "Upload failed");
    }
    return response.json();
  },

  // Upload an nginx .conf file — returns the absolute backend path that can
  // be used as nginx_config_path when creating/updating a connection.
  uploadNginxConfig: async (file: File): Promise<{ path: string; filename: string }> => {
    const formData = new FormData();
    formData.append("file", file);
    const response = await fetch(`${API_BASE}/api/connections/upload-nginx-config`, {
      method: "POST",
      body: formData,
      credentials: "include",
    });
    if (!response.ok) {
      if (response.status === 401) {
        window.dispatchEvent(new CustomEvent("auth:unauthorized"));
      }
      const error = await response.json().catch(() => ({ detail: response.statusText }));
      throw new Error(error.detail || "Upload failed");
    }
    return response.json();
  },

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

  getCrowdSecManualBlocks: (limit = 100) =>
    fetchApi<ManualBlockLogEntry[]>(`/api/crowdsec/manual-blocks?limit=${limit}`),

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

  getCrowdSecAlerts: () =>
    fetchApi<AlertItem[]>("/api/crowdsec/alerts"),

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
