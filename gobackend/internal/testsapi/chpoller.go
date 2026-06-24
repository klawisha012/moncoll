package testsapi

// CHClickHousePoller implements CHPoller using the existing ClickHouse client.
// It polls waf_audit_log for a row whose request_headers[X-Test-Marker] = marker,
// exactly mirroring Python _wait_for_marker / _query_marker in service.py.
//
// This is the live / production implementation.  Unit tests inject a fake that
// satisfies the CHPoller interface without a ClickHouse connection.

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const pollInterval = 500 * time.Millisecond

// CHClickHousePoller polls the WAF audit log for an X-Test-Marker row.
type CHClickHousePoller struct {
	dsn string // e.g. "clickhouse://..."
}

// NewCHClickHousePoller builds a poller that connects to ClickHouse at dsn.
// Pass an empty string to get the default from the environment variable
// WAF_CLICKHOUSE_DSN (mirrors how the dashboard package resolves it).
func NewCHClickHousePoller(dsn string) *CHClickHousePoller {
	return &CHClickHousePoller{dsn: dsn}
}

// PollMarker blocks until either the marker appears or timeout elapses.
// Returns (landed, ruleID, err). ruleID may be empty if the row landed but
// no rule matched.
func (p *CHClickHousePoller) PollMarker(ctx context.Context, marker string, timeout time.Duration) (bool, string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		landed, ruleID, err := p.queryMarker(ctx, marker)
		if err == nil && landed {
			return true, ruleID, nil
		}
		select {
		case <-ctx.Done():
			return false, "", ctx.Err()
		case <-time.After(pollInterval):
		}
	}
	return false, "", nil
}

func (p *CHClickHousePoller) queryMarker(ctx context.Context, marker string) (bool, string, error) {
	// Mirror Python _query_marker: look up the marker in request_headers Map
	// and return the first matching rule id.
	query := fmt.Sprintf(
		"SELECT any(m.ruleId) AS rid "+
			"FROM logs.waf_audit_log AS w "+
			"LEFT ARRAY JOIN messages AS m "+
			"WHERE request_headers['%s'] = '%s' "+
			"AND timestamp >= now() - INTERVAL 1 MINUTE "+
			"LIMIT 1",
		markerHeader, marker,
	)

	// Span over dial + query. Global tracer → non-recording when tracing is off.
	ctx, span := otel.Tracer("testsapi").Start(ctx, "clickhouse.query",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("db.system", "clickhouse"),
			attribute.String("db.statement", query),
		),
	)
	defer span.End()

	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{chAddr(p.dsn)},
	})
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "clickhouse open failed")
		return false, "", fmt.Errorf("testsapi: ch open: %w", err)
	}
	defer conn.Close()

	rows, err := conn.Query(ctx, query)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "clickhouse query failed")
		return false, "", fmt.Errorf("testsapi: ch query: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		return false, "", nil
	}
	var ruleID string
	if err := rows.Scan(&ruleID); err != nil {
		return false, "", nil
	}
	return true, ruleID, nil
}

// chAddr extracts a host:port from a clickhouse DSN or returns the default.
func chAddr(dsn string) string {
	if dsn != "" {
		return dsn
	}
	return "clickhouse:9000"
}
