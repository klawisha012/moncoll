package realtime

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
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
			"latitude":     float64(51.127),
			"longitude":    float64(13.451),
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

	assert.Empty(t, agg.buckets)
	assert.Nil(t, agg.drain(), "second drain should return nil")
}

func TestAggregator_SameBucketCounts(t *testing.T) {
	agg := &aggregator{
		buckets:         make(map[bucketKey]int),
		bucketPrecision: 1,
	}

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
	agg.addEvent(ev(55.71, 37.61))
	agg.addEvent(ev(55.74, 37.64))
	agg.addEvent(ev(55.74, 37.64))

	points := agg.drain()
	require.Len(t, points, 1)
	assert.Equal(t, 3, points[0].Delta)
	assert.Equal(t, "RU", points[0].CC)
}

// ─── Fakes ─────────────────────────────────────────────────────────────────────

// fakePublisher captures Publish calls for assertions.
type fakePublisher struct {
	mu    sync.Mutex
	calls []publishCall
}

type publishCall struct {
	channel string
	data    any
}

func (f *fakePublisher) Publish(_ context.Context, channel string, data any) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, publishCall{channel: channel, data: data})
	return true, nil
}

func (f *fakePublisher) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakePublisher) first() (publishCall, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return publishCall{}, false
	}
	return f.calls[0], true
}

// fakeRedis is an in-memory RedisList. Lists are stored head-first (index 0 =
// LEFT/head); Vector lpushes newest to the head, so the oldest entry is the tail.
type fakeRedis struct {
	mu   sync.Mutex
	data map[string][]string
}

func newFakeRedis() *fakeRedis { return &fakeRedis{data: make(map[string][]string)} }

// lpush simulates Vector's redis list sink (newest prepended to the head).
func (f *fakeRedis) lpush(key string, vals ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, v := range vals {
		f.data[key] = append([]string{v}, f.data[key]...)
	}
}

func (f *fakeRedis) llen(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.data[key])
}

func (f *fakeRedis) BLMove(ctx context.Context, source, destination, _, _ string, timeout time.Duration) *redis.StringCmd {
	f.mu.Lock()
	l := f.data[source]
	if len(l) == 0 {
		f.mu.Unlock()
		// Emulate the blocking wait so consumeLoop does not busy-spin, but stay
		// responsive to cancellation.
		t := timeout
		if t > 20*time.Millisecond {
			t = 20 * time.Millisecond
		}
		select {
		case <-ctx.Done():
		case <-time.After(t):
		}
		return redis.NewStringResult("", redis.Nil)
	}
	// Pop the tail (RIGHT = oldest) and prepend to the destination head (LEFT).
	val := l[len(l)-1]
	f.data[source] = l[:len(l)-1]
	f.data[destination] = append([]string{val}, f.data[destination]...)
	f.mu.Unlock()
	return redis.NewStringResult(val, nil)
}

func (f *fakeRedis) LRem(_ context.Context, key string, count int64, value interface{}) *redis.IntCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, _ := value.(string)
	var out []string
	var removed int64
	for _, v := range f.data[key] {
		if v == s && (count == 0 || removed < count) {
			removed++
			continue
		}
		out = append(out, v)
	}
	f.data[key] = out
	return redis.NewIntResult(removed, nil)
}

func (f *fakeRedis) LRange(_ context.Context, key string, _, _ int64) *redis.StringSliceCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	return redis.NewStringSliceResult(append([]string(nil), f.data[key]...), nil)
}

func (f *fakeRedis) LLen(_ context.Context, key string) *redis.IntCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	return redis.NewIntResult(int64(len(f.data[key])), nil)
}

func (f *fakeRedis) LTrim(_ context.Context, _ string, _, _ int64) *redis.StatusCmd {
	return redis.NewStatusResult("OK", nil)
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

func sampleEventJSON(t *testing.T) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"geoip": map[string]any{
			"latitude":     51.10,
			"longitude":    13.10,
			"country_code": "DE",
			"city_name":    "Test",
		},
	})
	require.NoError(t, err)
	return string(b)
}

// runUntil runs RunForever in a goroutine and blocks until it returns (ctx done)
// or the deadline elapses.
func runUntil(c *Consumer, d time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	done := make(chan struct{})
	go func() { c.RunForever(ctx); close(done) }()
	<-done
}

// ─── Reliable-queue consumer tests ─────────────────────────────────────────────

// TestConsumer_DeliversBacklogAndAcks covers durability + replay: an event
// enqueued while the consumer was "down" is delivered to Centrifugo after the
// consumer starts, and is acked (removed from both lists, never redelivered).
func TestConsumer_DeliversBacklogAndAcks(t *testing.T) {
	t.Setenv("AGGREGATOR_FLUSH_INTERVAL_S", "0.05")
	fake := newFakeRedis()
	fake.lpush(defaultRedisRawKey, sampleEventJSON(t)) // published while consumer was down
	pub := &fakePublisher{}

	c := &Consumer{rc: fake, pub: pub, log: testLogger()}
	runUntil(c, 250*time.Millisecond)

	require.NotZero(t, pub.count(), "backlog event should be flushed to Centrifugo after start")
	first, ok := pub.first()
	require.True(t, ok)
	assert.Equal(t, defaultChannelGeoipMap, first.channel)
	payload := first.data.(map[string]any)
	assert.Equal(t, "geoip_map_delta", payload["type"])

	assert.Equal(t, 0, fake.llen(defaultRedisRawKey), "ingest list should be drained")
	assert.Equal(t, 0, fake.llen(defaultProcessingKey), "processed entry should be acked (LREM'd)")
}

// TestConsumer_FailedProcessingRedeliveredOnRestart covers the PEL semantics: an
// entry whose processing fails is left in the processing list (unacked); on a
// restart it is re-drained and, when processing succeeds, acked.
func TestConsumer_FailedProcessingRedeliveredOnRestart(t *testing.T) {
	t.Setenv("AGGREGATOR_FLUSH_INTERVAL_S", "0.05")
	fake := newFakeRedis()
	fake.lpush(defaultRedisRawKey, sampleEventJSON(t))

	// Run 1: processing always fails → entry must remain in the processing list.
	failing := &Consumer{
		rc:         fake,
		pub:        &fakePublisher{},
		log:        testLogger(),
		processErr: func(map[string]any) error { return assert.AnError },
	}
	runUntil(failing, 200*time.Millisecond)

	assert.Equal(t, 0, fake.llen(defaultRedisRawKey), "entry moved out of the ingest list")
	require.Equal(t, 1, fake.llen(defaultProcessingKey), "failed entry must stay in the processing list for redelivery")

	// Run 2 (restart): processing succeeds → recoverProcessing redelivers it.
	pub2 := &fakePublisher{}
	healthy := &Consumer{rc: fake, pub: pub2, log: testLogger()}
	runUntil(healthy, 200*time.Millisecond)

	require.NotZero(t, pub2.count(), "redelivered entry should reach Centrifugo on restart")
	assert.Equal(t, 0, fake.llen(defaultProcessingKey), "redelivered entry should now be acked")
}

// TestConsumer_BadJSONIsDiscarded covers poison handling: malformed entries are
// acked (removed) rather than retried forever.
func TestConsumer_BadJSONIsDiscarded(t *testing.T) {
	t.Setenv("AGGREGATOR_FLUSH_INTERVAL_S", "0.05")
	fake := newFakeRedis()
	fake.lpush(defaultRedisRawKey, "{not valid json")
	pub := &fakePublisher{}

	c := &Consumer{rc: fake, pub: pub, log: testLogger()}
	runUntil(c, 200*time.Millisecond)

	assert.Equal(t, 0, fake.llen(defaultRedisRawKey))
	assert.Equal(t, 0, fake.llen(defaultProcessingKey), "poison entry must be acked, not stuck")
	assert.Zero(t, pub.count(), "malformed entry yields nothing to publish")
}
