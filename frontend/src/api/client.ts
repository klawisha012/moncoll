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

export interface AngieSettings {
  worker_processes: string;
  worker_rlimit_nofile: number;
  worker_connections: number;
  keepalive_timeout: number;
  sendfile: boolean;
  denied_countries: string[];
  modules: ModuleInfo[];
}

export interface Metrics {
  total_requests: number;
  total_requests_change: number;
  blocked_threats: number;
  high_severity_count: number;
  system_health: number;
  avg_latency_ms: number;
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

async function fetchApi<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${url}`, {
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
    ...options,
  });

  if (!response.ok) {
    const error = await response
      .json()
      .catch(() => ({ detail: response.statusText }));
    throw new Error(error.detail || "API request failed");
  }

  if (response.status === 204) {
    return {} as T;
  }

  return response.json();
}

export const api = {
  getModsecSettings: () =>
    fetchApi<ModSecuritySettings>("/modsecurity/settings"),
  updateModsecSettings: (settings: ModSecuritySettings) =>
    fetchApi<ModSecuritySettings>("/modsecurity/settings", {
      method: "PUT",
      body: JSON.stringify(settings),
    }),

  getAngieSettings: () => fetchApi<AngieSettings>("/angie/settings"),
  updateAngieSettings: (settings: AngieSettings) =>
    fetchApi<AngieSettings>("/angie/settings", {
      method: "PUT",
      body: JSON.stringify(settings),
    }),

  reloadModsec: () =>
    fetchApi<ReloadResponse>("/modsecurity/reload", { method: "POST" }),
  reloadAngie: () =>
    fetchApi<ReloadResponse>("/angie/reload", { method: "POST" }),

  getMetrics: () => fetchApi<Metrics>("/dashboard/metrics"),
  getTraffic: () => fetchApi<TrafficDataPoint[]>("/dashboard/traffic"),
  getThreatOrigins: () =>
    fetchApi<ThreatOrigin[]>("/dashboard/threat-origins"),
  getEvents: (limit = 50, severity = "all") =>
    fetchApi<SecurityEvent[]>(
      `/dashboard/events?limit=${limit}&severity=${severity}`
    ),
};
