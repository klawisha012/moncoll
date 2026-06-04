package realtime

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── Aggregator unit tests ────────────────────────────────────────────────────

func TestAggregator_NoGeoip(t *testing.T) {
	agg := &aggregator{
		buckets:         make(map[bucketKey]int),
		bucketPrecision: 2,
	}
	// Event with no geoip field.
	agg.addEvent(map[string]any{"foo": "bar"})
	assert.Equal(t, 1, agg.droppedNoGeoip)
	assert.Empty(t, agg.buckets)
}

func TestAggregator_ZeroCoords(t *testing.T) {
	agg := &aggregator{
		buckets:         make(map[bucketKey]int),
		bucketPrecision: 2,
	}
	// lat/lon both zero → treated as missing.
	agg.addEvent(map[string]any{
		"geoip": map[string]any{
			"latitude":     float64(0),
			"longitude":    float64(0),
			"country_code": "US",
		},
	})
	assert.Equal(t, 1, agg.droppedNoGeoip)
	assert.Empty(t, agg.buckets)
}

func TestAggregator_AccumulatesAndDrains(t *testing.T) {
	agg := &aggregator{
		buckets:         make(map[bucketKey]int),
		bucketPrecision: 2,
	}

	// Three events: two into the same bucket (same rounded coords), one different.
	event1 := map[string]any{
		"geoip": map[string]any{
			"latitude":     float64(51.123),
			"longitude":    float64(13.456),
			"country_code": "DE",
			"city_name":    "Dresden",
		},
	}
	event2 := map[string]any{
		"geoip": map[string]any{
			"latitude":     float64(51.127), // rounds to 51.13 — different bucket
			"longitude":    float64(13.451), // rounds to 13.45 — different bucket
			"country_code": "DE",
			"city_name":    "Dresden",
		},
	}
	event3 := map[string]any{
		"geoip": map[string]any{
			"latitude":     float64(48.85),
			"longitude":    float64(2.35),
			"country_code": "FR",
			"city_name":    "Paris",
		},
	}

	agg.addEvent(event1)
	agg.addEvent(event2)
	agg.addEvent(event3)

	assert.Equal(t, 0, agg.droppedNoGeoip)

	points := agg.drain()
	require.Len(t, points, 3, "expected 3 distinct buckets")

	// After drain the buffer must be empty.
	assert.Empty(t, agg.buckets)
	assert.Nil(t, agg.drain(), "second drain should return nil")
}

func TestAggregator_SameBucketCounts(t *testing.T) {
	agg := &aggregator{
		buckets:         make(map[bucketKey]int),
		bucketPrecision: 1,
	}

	// Two events that round to the same 1-decimal bucket.
	ev := func(lat, lon float64) map[string]any {
		return map[string]any{
			"geoip": map[string]any{
				"latitude":     lat,
				"longitude":    lon,
				"country_code": "RU",
				"city_name":    "Moscow",
			},
		}
	}
	agg.addEvent(ev(55.71, 37.61)) // rounds to 55.7 / 37.6
	agg.addEvent(ev(55.74, 37.64)) // same bucket
	agg.addEvent(ev(55.74, 37.64)) // same bucket again

	points := agg.drain()
	require.Len(t, points, 1)
	assert.Equal(t, 3, points[0].Delta)
	assert.Equal(t, "RU", points[0].CC)
}

// ─── Flush-window batching integration test ───────────────────────────────────

// fakePublisher captures Publish calls for assertions.
type fakePublisher struct {
	calls []publishCall
}

type publishCall struct {
	channel string
	data    any
}

func (f *fakePublisher) Publish(_ context.Context, channel string, data any) (bool, error) {
	f.calls = append(f.calls, publishCall{channel: channel, data: data})
	return true, nil
}

func TestFlushLoop_BatchesWithinWindow(t *testing.T) {
	// Drive the consumer's runLoops directly (bypassing Redis).
	pub := &fakePublisher{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c := &Consumer{pub: pub, log: log}

	// Use a very short flush interval for the test.
	t.Setenv("AGGREGATOR_FLUSH_INTERVAL_S", "0.05") // 50 ms

	agg := &aggregator{
		buckets:         make(map[bucketKey]int),
		bucketPrecision: 2,
	}
	msgCh := make(chan map[string]any, 64)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	// Enqueue 5 events with the same bucket so they accumulate and are
	// flushed as a single point with delta=5.
	for i := 0; i < 5; i++ {
		msgCh <- map[string]any{
			"geoip": map[string]any{
				"latitude":     float64(51.10), // all round to the same bucket
				"longitude":    float64(13.10),
				"country_code": "DE",
				"city_name":    "Test",
			},
		}
	}

	go c.runLoops(ctx, agg, msgCh)
	<-ctx.Done()

	// At least one batch should have been published.
	require.NotEmpty(t, pub.calls, "expected at least one flush publish")

	// Verify shape of first publish: channel must be dashboard:map.
	first := pub.calls[0]
	assert.Equal(t, defaultChannelGeoipMap, first.channel)

	payload, ok := first.data.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "geoip_map_delta", payload["type"])
	_, hasTS := payload["ts"]
	assert.True(t, hasTS)
	points, ok := payload["points"].([]MapPoint)
	require.True(t, ok)
	require.NotEmpty(t, points)

	// Total delta across all points from first publish must equal 5.
	totalDelta := 0
	for _, p := range points {
		assert.Equal(t, "DE", p.CC)
		assert.GreaterOrEqual(t, p.Delta, 1)
		totalDelta += p.Delta
	}
	// All 5 events are in the same bucket, so first flush must have delta=5 in one point.
	assert.Equal(t, 5, totalDelta)
}
