package store

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Observer records the duration and error outcome of a database call. It is
// satisfied by *observability.Metrics (its ObserveDB method); declared here as
// a minimal interface so the store package stays decoupled from the metrics
// implementation and tests can pass a stub or nothing at all.
type Observer interface {
	ObserveDB(subsystem, operation string, start time.Time, err error)
}

// queryTracer is a pgx.QueryTracer that feeds every pooled query into an
// Observer. Query, QueryRow and Exec all route through this hook, so wiring it
// at the pool seam instruments all call sites uniformly instead of wrapping
// each one by hand. Queries are labelled subsystem="postgres" with the leading
// SQL verb as the operation, keeping label cardinality bounded.
type queryTracer struct{ obs Observer }

type tracerCtxKey struct{}

type tracerCtxVal struct {
	start time.Time
	op    string
}

func (t queryTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, tracerCtxKey{}, tracerCtxVal{start: time.Now(), op: sqlVerb(data.SQL)})
}

func (t queryTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	v, ok := ctx.Value(tracerCtxKey{}).(tracerCtxVal)
	if !ok {
		return
	}
	t.obs.ObserveDB("postgres", v.op, v.start, data.Err)
}

// sqlVerb extracts the leading SQL keyword (select/insert/update/delete/with/…)
// so the operation label stays low-cardinality regardless of the query text.
func sqlVerb(sql string) string {
	sql = strings.TrimSpace(sql)
	if sql == "" {
		return "unknown"
	}
	if i := strings.IndexFunc(sql, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}); i > 0 {
		sql = sql[:i]
	}
	return strings.ToLower(sql)
}
