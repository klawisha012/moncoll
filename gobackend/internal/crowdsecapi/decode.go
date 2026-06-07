package crowdsecapi

// decode.go holds the cscli JSON decoding layer: the wire-shape structs that
// mirror cscli's output and the pure helpers that turn raw JSON into typed
// values. Keeping it separate from service.go isolates "parse cscli output"
// from "serve gRPC", so each file carries a single responsibility.

import (
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/wrapperspb"
)

// ── Helper types for JSON parsing ─────────────────────────────────────────────

// alertShape mirrors the cscli decisions list / alerts list JSON shape.
type alertShape struct {
	ID        json.RawMessage `json:"id"`
	Scenario  string          `json:"scenario"`
	Message   string          `json:"message"`
	Source    map[string]any  `json:"source"`
	Decisions []decisionShape `json:"decisions"`
	Meta      []metaItem      `json:"meta"`
	StopAt    string          `json:"stop_at"`
	StartAt   string          `json:"start_at"`
	Capacity  json.RawMessage `json:"capacity"`
}

type decisionShape struct {
	ID       json.RawMessage `json:"id"`
	Value    string          `json:"value"`
	Type     string          `json:"type"`
	Duration string          `json:"duration"`
	Origin   string          `json:"origin"`
	Scope    string          `json:"scope"`
}

type metaItem struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// scenarioItem is the JSON shape of one item from `cscli scenarios list`.
type scenarioItem struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Status      string          `json:"status"`
	Type        string          `json:"type"`
	Labels      json.RawMessage `json:"labels"`
}

// hubItem is the JSON shape of one item from `cscli hub list -a`.
type hubItem struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Status      string          `json:"status"`
	Labels      json.RawMessage `json:"labels"`
	LocalPath   string          `json:"local_path"`
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// rawToInt64Value converts a json.RawMessage that is either a number or null
// into a wrapperspb.Int64Value (nil when null or absent).
func rawToInt64Value(raw json.RawMessage) *wrapperspb.Int64Value {
	if raw == nil || string(raw) == "null" || string(raw) == "" {
		return nil
	}
	var v int64
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	return wrapperspb.Int64(v)
}

// sourceValue extracts the "value" field from a cscli source map.
func sourceValue(src map[string]any) string {
	if src == nil {
		return ""
	}
	v, _ := src["value"].(string)
	return v
}

// sourceScope extracts the "scope" field from a cscli source map.
func sourceScope(src map[string]any) string {
	if src == nil {
		return "Ip"
	}
	if v, ok := src["scope"].(string); ok && v != "" {
		return v
	}
	return "Ip"
}

// extractTargetHosts mirrors Python _extract_target_hosts_from_alerts.
func extractTargetHosts(alerts []alertShape) map[string]map[string]struct{} {
	result := make(map[string]map[string]struct{})
	for _, alert := range alerts {
		ip := sourceValue(alert.Source)
		if ip == "" {
			continue
		}
		for _, m := range alert.Meta {
			key := strings.ToLower(m.Key)
			val := strings.ToLower(strings.TrimSpace(m.Value))
			if val == "" {
				continue
			}
			switch key {
			case "target_host", "http_host", "target_fqdn", "host":
				if result[ip] == nil {
					result[ip] = make(map[string]struct{})
				}
				result[ip][val] = struct{}{}
			}
		}
	}
	return result
}

// resolveIPConnections is a thin wrapper around the crowdsec package function
// using the same shared logic.
//
// We re-use crowdsec.resolveIPConnections logic by reimplementing it here via
// the exported crowdsec package types if needed, but since crowdsec package
// exposes it indirectly through Syncer, we keep the resolution logic local to
// the service to keep the service testable without the full Syncer.
//
// Priority (mirrors Python _resolve_ip_connections exactly):
//  1. Manual mapping
//  2. target_host → domain → conn
//  3. Fallback: all connections
func resolveIPConnections(
	ipValue string,
	manualMapping map[string][]int64,
	targetHosts map[string]map[string]struct{},
	domainToConn map[string]int64,
	allConnIDs []int64,
) []int64 {
	if ids, ok := manualMapping[ipValue]; ok {
		return ids
	}
	hosts := targetHosts[ipValue]
	connIDSet := make(map[int64]struct{})
	for host := range hosts {
		if cid, ok := domainToConn[host]; ok {
			connIDSet[cid] = struct{}{}
		}
	}
	if len(connIDSet) > 0 {
		ids := make([]int64, 0, len(connIDSet))
		for id := range connIDSet {
			ids = append(ids, id)
		}
		return ids
	}
	return allConnIDs
}

// parseAlertsJSON decodes a json.RawMessage as []alertShape. Returns nil on
// error or when raw is empty/null.
func parseAlertsJSON(raw json.RawMessage) []alertShape {
	if raw == nil {
		return nil
	}
	var alerts []alertShape
	if err := json.Unmarshal(raw, &alerts); err != nil {
		slog.Warn("crowdsecapi: failed to parse alerts JSON", "err", err)
		return nil
	}
	return alerts
}

// parseAlertTimestamp mirrors Python _parse_alert_timestamp — best-effort,
// returns zero time on failure (meaning "don't filter out").
func parseAlertTimestamp(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	normalised := strings.ReplaceAll(value, "Z", "+00:00")
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999999Z07:00",
		"2006-01-02T15:04:05Z",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, normalised); err == nil {
			return t
		}
		if t, err := time.Parse(f, value); err == nil {
			return t
		}
	}
	return time.Time{}
}

// parseStringSlice decodes a json.RawMessage as a []string, returning nil on
// error or when raw is empty.
func parseStringSlice(raw json.RawMessage) []string {
	if raw == nil {
		return nil
	}
	var s []string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil
	}
	return s
}
