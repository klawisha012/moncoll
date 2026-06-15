package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type recordingObserver struct {
	subsystem string
	operation string
	err       error
	calls     int
}

func (o *recordingObserver) ObserveDB(subsystem, operation string, _ time.Time, err error) {
	o.subsystem = subsystem
	o.operation = operation
	o.err = err
	o.calls++
}

func TestQueryTracerObservesPostgresCalls(t *testing.T) {
	obs := &recordingObserver{}
	tr := queryTracer{obs: obs}

	wantErr := errors.New("boom")
	ctx := tr.TraceQueryStart(context.Background(), nil, pgx.TraceQueryStartData{
		SQL: "SELECT id FROM users WHERE id = $1",
	})
	tr.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{Err: wantErr})

	if obs.calls != 1 {
		t.Fatalf("ObserveDB calls = %d, want 1", obs.calls)
	}
	if obs.subsystem != "postgres" {
		t.Errorf("subsystem = %q, want %q", obs.subsystem, "postgres")
	}
	if obs.operation != "select" {
		t.Errorf("operation = %q, want %q", obs.operation, "select")
	}
	if !errors.Is(obs.err, wantErr) {
		t.Errorf("err = %v, want %v", obs.err, wantErr)
	}
}

func TestTraceQueryEndWithoutStartIsNoop(t *testing.T) {
	obs := &recordingObserver{}
	tr := queryTracer{obs: obs}
	// No matching TraceQueryStart on this context → must not call ObserveDB
	// (and must not panic dereferencing the missing context value).
	tr.TraceQueryEnd(context.Background(), nil, pgx.TraceQueryEndData{})
	if obs.calls != 0 {
		t.Fatalf("ObserveDB calls = %d, want 0", obs.calls)
	}
}

func TestSQLVerb(t *testing.T) {
	cases := map[string]string{
		"SELECT * FROM t":          "select",
		"  insert into t values":   "insert",
		"\n\tUPDATE t SET x = 1":   "update",
		"DELETE FROM t":            "delete",
		"WITH cte AS (...) SELECT": "with",
		"":                         "unknown",
	}
	for in, want := range cases {
		if got := sqlVerb(in); got != want {
			t.Errorf("sqlVerb(%q) = %q, want %q", in, got, want)
		}
	}
}
