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
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/zwarder/waf/gobackend/internal/crowdsec"
)

// cleanUTF8 coerces a string into valid UTF-8 so it can be marshaled into a
// protobuf string field. cscli stdout/stderr is raw command output and may
// contain invalid byte sequences; gRPC rejects invalid UTF-8 in string fields
// with codes.Internal, which the gateway surfaces to the browser as HTTP 500.
func cleanUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "�")
}

// ── Helper types for JSON parsing ─────────────────────────────────────────────

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

// parseAlertsJSON decodes a json.RawMessage as []crowdsec.Alert. Returns nil on
// error or when raw is empty/null.
func parseAlertsJSON(raw json.RawMessage) []crowdsec.Alert {
	if raw == nil {
		return nil
	}
	var alerts []crowdsec.Alert
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
