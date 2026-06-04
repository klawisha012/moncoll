// Package realtime implements the Redis → aggregator → Centrifugo fan-out
// consumer, faithfully porting backend/src/realtime/consumer.py.
//
// Architecture:
//
//	Vector → Redis pub/sub "attacks:raw"
//	              ↓ SUBSCRIBE (subscribeLoop)
//	        in-memory aggregator (geoip bucket map)
//	              ↓ every 500 ms (flushLoop)
//	        Centrifugo channel "dashboard:map"
//
// Single-instance assumption: the Python backend is being removed, so there is
// exactly one consumer. If horizontal scaling is ever needed, move this to a
// dedicated single-replica worker container (Redis pub/sub copies to EVERY
// subscriber, which would double-publish with two replicas).
//
// Failure modes (all best-effort, never crash the server):
//   - Redis down       → backoff reconnect, server unaffected
//   - Bad JSON message → log + skip
//   - Centrifugo down  → Publish returns false, delta dropped
//   - Process restart  → in-flight 500 ms batches lost; events still in CH
package realtime

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"os"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// ─── Config ──────────────────────────────────────────────────────────────────

const (
	defaultRedisURL          = "redis://redis:6379/0"
	defaultRedisRawChannel   = "attacks:raw"
	defaultChannelGeoipMap   = "dashboard:map"
	defaultFlushIntervalMS   = 500
	defaultGeoipBucketPrec   = 2 // decimal places (~1 km)
)

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func flushInterval() time.Duration {
	s := os.Getenv("AGGREGATOR_FLUSH_INTERVAL_S")
	if s == "" {
		return defaultFlushIntervalMS * time.Millisecond
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f <= 0 {
		return defaultFlushIntervalMS * time.Millisecond
	}
	return time.Duration(f * float64(time.Second))
}

// ─── Interfaces (injected for testability) ────────────────────────────────────

// RedisSubscriber is the minimal interface the consumer needs from Redis.
// *redis.Client satisfies it.
type RedisSubscriber interface {
	Subscribe(ctx context.Context, channels ...string) *redis.PubSub
}

// Publishes abstracts the Centrifugo HTTP client.
type Publishes interface {
	Publish(ctx context.Context, channel string, data any) (bool, error)
}

// ─── Aggregator ───────────────────────────────────────────────────────────────

// bucketKey groups map points by rounded coordinates + country code + city.
// Mirrors _BucketKey in consumer.py.
type bucketKey struct {
	cc   string
	lat  float64
	lon  float64
	city string
}

// aggregator accumulates geoip event counts between flush ticks.
// Not safe for concurrent use — the consumer drives it from a single goroutine.
type aggregator struct {
	buckets         map[bucketKey]int
	droppedNoGeoip  int
	bucketPrecision int
}

func newAggregator() *aggregator {
	prec := defaultGeoipBucketPrec
	if s := os.Getenv("GEOIP_BUCKET_PRECISION"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			prec = n
		}
	}
	return &aggregator{
		buckets:         make(map[bucketKey]int),
		bucketPrecision: prec,
	}
}

// roundTo rounds f to prec decimal places.
func roundTo(f float64, prec int) float64 {
	p := math.Pow10(prec)
	return math.Round(f*p) / p
}

// addEvent ingests one raw event from Vector. Events without valid geoip
// coordinates are silently dropped (incrementing droppedNoGeoip).
// Mirrors _Aggregator.add_event in consumer.py.
func (a *aggregator) addEvent(raw map[string]any) {
	geoip, _ := raw["geoip"].(map[string]any)
	if geoip == nil {
		a.droppedNoGeoip++
		return
	}

	latRaw := geoip["latitude"]
	lonRaw := geoip["longitude"]
	ccRaw, _ := geoip["country_code"].(string)

	var lat, lon float64
	switch v := latRaw.(type) {
	case float64:
		lat = v
	case json.Number:
		lat, _ = v.Float64()
	}
	switch v := lonRaw.(type) {
	case float64:
		lon = v
	case json.Number:
		lon, _ = v.Float64()
	}

	if lat == 0 || lon == 0 || ccRaw == "" {
		a.droppedNoGeoip++
		return
	}

	city, _ := geoip["city_name"].(string)
	k := bucketKey{
		cc:   ccRaw,
		lat:  roundTo(lat, a.bucketPrecision),
		lon:  roundTo(lon, a.bucketPrecision),
		city: city,
	}
	a.buckets[k]++
}

// MapPoint is one element in the geoip_map_delta payload.
type MapPoint struct {
	CC    string  `json:"cc"`
	Lat   float64 `json:"lat"`
	Lon   float64 `json:"lon"`
	City  string  `json:"city"`
	Delta int     `json:"delta"`
}

// drain atomically returns and clears all accumulated points.
// Returns nil when the buffer is empty (no publish needed).
// Mirrors _Aggregator.drain in consumer.py.
func (a *aggregator) drain() []MapPoint {
	if len(a.buckets) == 0 {
		return nil
	}
	out := make([]MapPoint, 0, len(a.buckets))
	for k, v := range a.buckets {
		out = append(out, MapPoint{
			CC:    k.cc,
			Lat:   k.lat,
			Lon:   k.lon,
			City:  k.city,
			Delta: v,
		})
	}
	// Reset bucket map.
	a.buckets = make(map[bucketKey]int)
	return out
}

// ─── Consumer ─────────────────────────────────────────────────────────────────

// Consumer holds the injected dependencies for the Redis→Centrifugo pipeline.
type Consumer struct {
	rc   RedisSubscriber
	pub  Publishes
	log  *slog.Logger
}

// New constructs a Consumer with real Redis + Centrifugo clients.
// rc must be a connected *redis.Client (or nil-safe wrapper); pub is typically
// *centrifugo.Publisher.
func New(rc RedisSubscriber, pub Publishes, log *slog.Logger) *Consumer {
	return &Consumer{rc: rc, pub: pub, log: log}
}

// RunForever starts the subscribe loop and flush loop, blocking until ctx is
// cancelled. Best-effort: Redis/Centrifugo errors are logged and retried; the
// function never panics or returns an error.
// Mirrors consumer.run_forever in consumer.py.
func (c *Consumer) RunForever(ctx context.Context) {
	agg := newAggregator()
	// Channel used to pass messages from subscribeLoop to the aggregator.
	// Buffered so a slow flush tick doesn't block the redis receive loop.
	msgCh := make(chan map[string]any, 256)

	go c.subscribeLoop(ctx, msgCh)
	c.runLoops(ctx, agg, msgCh)
	c.log.InfoContext(ctx, "realtime: consumer stopped")
}

// runLoops drives the aggregator from msgCh and the flush ticker from a single
// goroutine, eliminating the need for a mutex on the aggregator.
func (c *Consumer) runLoops(ctx context.Context, agg *aggregator, msgCh <-chan map[string]any) {
	interval := flushInterval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	rawChannel := getenv("REDIS_RAW_CHANNEL", defaultRedisRawChannel)
	geoipMapChannel := getenv("CHANNEL_GEOIP_MAP", defaultChannelGeoipMap)
	_ = rawChannel // used in subscribe loop

	for {
		select {
		case <-ctx.Done():
			return
		case raw, ok := <-msgCh:
			if !ok {
				return
			}
			agg.addEvent(raw)
		case <-ticker.C:
			points := agg.drain()
			if len(points) == 0 {
				continue
			}
			payload := map[string]any{
				"type":   "geoip_map_delta",
				"ts":     time.Now().UnixMilli(),
				"points": points,
			}
			c.log.DebugContext(ctx, "realtime: flushing points",
				"count", len(points), "channel", geoipMapChannel)
			ok, _ := c.pub.Publish(ctx, geoipMapChannel, payload)
			if !ok {
				c.log.WarnContext(ctx, "realtime: drop points — publish failed",
					"count", len(points))
			}
		}
	}
}

// subscribeLoop holds a Redis pub/sub subscription, reconnecting with
// exponential backoff on error. Parsed events are sent to msgCh.
// Mirrors _subscribe_loop in consumer.py.
func (c *Consumer) subscribeLoop(ctx context.Context, msgCh chan<- map[string]any) {
	rawChannel := getenv("REDIS_RAW_CHANNEL", defaultRedisRawChannel)
	backoff := time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := c.runSubscription(ctx, rawChannel, msgCh); err != nil {
			c.log.WarnContext(ctx, "realtime: redis subscribe failed, retrying",
				"backoff", backoff, "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
				if backoff < 30*time.Second {
					backoff *= 2
				}
			}
		} else {
			// runSubscription returned nil — ctx was cancelled.
			return
		}
	}
}

// runSubscription subscribes to one Redis pub/sub channel and forwards
// messages to msgCh. Returns nil when ctx is cancelled, non-nil error on
// subscription failure.
func (c *Consumer) runSubscription(ctx context.Context, channel string, msgCh chan<- map[string]any) error {
	ps := c.rc.Subscribe(ctx, channel)
	defer ps.Close() //nolint:errcheck

	c.log.InfoContext(ctx, "realtime: subscribed to redis", "channel", channel)

	ch := ps.Channel()
	for {
		select {
		case <-ctx.Done():
			return nil
		case msg, ok := <-ch:
			if !ok {
				return fmt.Errorf("redis pubsub channel closed")
			}
			var raw map[string]any
			if err := json.Unmarshal([]byte(msg.Payload), &raw); err != nil {
				c.log.WarnContext(ctx, "realtime: bad json from redis", "err", err)
				continue
			}
			select {
			case msgCh <- raw:
			case <-ctx.Done():
				return nil
			default:
				// Buffer full — drop event to avoid blocking the redis receive loop.
				c.log.WarnContext(ctx, "realtime: msgCh full, dropping event")
			}
		}
	}
}

// ─── Redis client factory ─────────────────────────────────────────────────────

// NewRedisClient constructs a *redis.Client from REDIS_URL env.
// Returns nil and logs a warning if the URL cannot be parsed.
// The returned client is lazy-connected — subscribe errors will surface at
// first use and be handled by subscribeLoop's backoff.
func NewRedisClient() *redis.Client {
	url := getenv("REDIS_URL", defaultRedisURL)
	opt, err := redis.ParseURL(url)
	if err != nil {
		slog.Warn("realtime: cannot parse REDIS_URL", "err", err)
		return nil
	}
	opt.DialTimeout = 2 * time.Second
	opt.ReadTimeout = 0 // pub/sub blocks indefinitely
	return redis.NewClient(opt)
}
