// Package realtime implements the Redis → aggregator → Centrifugo fan-out
// consumer, faithfully porting backend/src/realtime/consumer.py.
//
// Architecture (durable reliable-queue ingest):
//
//	Vector → Redis LIST "attacks:raw"          (lpush; durable buffer)
//	              ↓ BLMOVE raw → "attacks:processing"  (reliable pop)
//	        in-memory aggregator (geoip bucket map)
//	              ↓ LREM processing  (ack: drop the handled entry)
//	              ↓ every 500 ms (flush)
//	        Centrifugo channel "dashboard:map"
//
// Why a list, not pub/sub: pub/sub is fire-and-forget — events published while
// the consumer is down are lost. A Redis list is durable, so the backlog
// survives a consumer restart and is drained on return. The reliable-queue
// pattern (BLMOVE into a processing list, LREM only after the event is
// aggregated) means a crash mid-processing leaves the entry in the processing
// list, which is re-drained on restart (at-least-once redelivery).
//
// Why a list, not a Redis stream: Vector's redis sink can only write list /
// channel / sortedset — it cannot XADD to a stream — so a stream cannot be fed
// end-to-end from the producer. The list reliable queue delivers the same
// durability + redelivery guarantee the single consumer needs. (A full stream
// with consumer groups would only be warranted with fan-out to many
// independent consumers.)
//
// Single-instance assumption: there is exactly one consumer. Two consumers
// would split the queue (each entry goes to exactly one BLMOVE caller), which
// is fine for load-sharing but would split the geoip aggregation — keep it
// single-replica.
//
// Failure modes (all best-effort, never crash the server):
//   - Redis down       → backoff reconnect, server unaffected
//   - Bad JSON entry   → log + ack (poison entries are not retried forever)
//   - Centrifugo down  → Publish returns false, delta dropped (ephemeral)
//   - Process restart  → in-flight 500 ms batch lost; queued + processing
//                        entries are NOT lost (durable list + re-drain)
package realtime

import (
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"os"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// ─── Config ──────────────────────────────────────────────────────────────────

const (
	defaultRedisURL        = "redis://redis:6379/0"
	defaultRedisRawKey     = "attacks:raw"
	defaultProcessingKey   = "attacks:processing"
	defaultChannelGeoipMap = "dashboard:map"
	defaultFlushIntervalMS = 500
	defaultGeoipBucketPrec = 2      // decimal places (~1 km)
	defaultQueueMaxLen     = 100000 // 0 = unbounded
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

// queueMaxLen is the soft cap on the ingest list. Beyond it the oldest entries
// are trimmed so a stalled consumer cannot exhaust Redis memory. 0 = unbounded.
func queueMaxLen() int64 {
	s := os.Getenv("REALTIME_QUEUE_MAXLEN")
	if s == "" {
		return defaultQueueMaxLen
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return defaultQueueMaxLen
	}
	return n
}

// ─── Interfaces (injected for testability) ────────────────────────────────────

// RedisList is the minimal interface the reliable-queue consumer needs.
// *redis.Client satisfies it.
type RedisList interface {
	BLMove(ctx context.Context, source, destination, srcpos, destpos string, timeout time.Duration) *redis.StringCmd
	LRem(ctx context.Context, key string, count int64, value interface{}) *redis.IntCmd
	LRange(ctx context.Context, key string, start, stop int64) *redis.StringSliceCmd
	LLen(ctx context.Context, key string) *redis.IntCmd
	LTrim(ctx context.Context, key string, start, stop int64) *redis.StatusCmd
}

// Publishes abstracts the Centrifugo HTTP client.
type Publishes interface {
	Publish(ctx context.Context, channel string, data any) (bool, error)
}

// QueueMetrics is the slice of observability.Metrics the consumer reports to.
// nil is allowed (metrics simply not recorded).
type QueueMetrics interface {
	SetQueueLength(queue string, n int64)
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
	rc      RedisList
	pub     Publishes
	log     *slog.Logger
	metrics QueueMetrics // nil-safe

	// processErr, when non-nil, is consulted before aggregating an entry. A
	// returned error simulates a processing failure: the entry is left in the
	// processing list (unacked) for redelivery. Test-only.
	processErr func(raw map[string]any) error
}

// New constructs a Consumer with real Redis + Centrifugo clients.
// rc must be a connected *redis.Client; pub is typically *centrifugo.Publisher.
// metrics may be nil.
func New(rc RedisList, pub Publishes, log *slog.Logger, metrics QueueMetrics) *Consumer {
	return &Consumer{rc: rc, pub: pub, log: log, metrics: metrics}
}

// RunForever drains any in-flight processing backlog, then runs the reliable-
// queue consume loop, blocking until ctx is cancelled. Best-effort: Redis /
// Centrifugo errors are logged and retried; the function never panics.
func (c *Consumer) RunForever(ctx context.Context) {
	agg := newAggregator()
	rawKey := getenv("REDIS_RAW_CHANNEL", defaultRedisRawKey)
	procKey := getenv("REDIS_PROCESSING_KEY", defaultProcessingKey)

	// Recover entries taken but not acked before a previous crash.
	c.recoverProcessing(ctx, agg, procKey)

	c.consumeLoop(ctx, agg, rawKey, procKey)
	c.log.InfoContext(ctx, "realtime: consumer stopped")
}

// recoverProcessing re-handles any entries still in the processing list from a
// prior crash (at-least-once redelivery), acking each on success.
func (c *Consumer) recoverProcessing(ctx context.Context, agg *aggregator, procKey string) {
	vals, err := c.rc.LRange(ctx, procKey, 0, -1).Result()
	if err != nil {
		if err != redis.Nil {
			c.log.WarnContext(ctx, "realtime: recover processing list failed", "err", err)
		}
		return
	}
	if len(vals) > 0 {
		c.log.InfoContext(ctx, "realtime: recovering in-flight entries", "count", len(vals), "key", procKey)
	}
	for _, v := range vals {
		c.handleValue(ctx, agg, procKey, v)
	}
}

// consumeLoop is the single-goroutine reliable-queue loop: BLMOVE one entry from
// the ingest list into the processing list, aggregate it, ack it, and flush the
// aggregated deltas to Centrifugo on the flush interval.
func (c *Consumer) consumeLoop(ctx context.Context, agg *aggregator, rawKey, procKey string) {
	geoipMapChannel := getenv("CHANNEL_GEOIP_MAP", defaultChannelGeoipMap)
	interval := flushInterval()
	maxLen := queueMaxLen()
	backoff := time.Second
	lastFlush := time.Now()

	for {
		if ctx.Err() != nil {
			return
		}

		// Block up to one flush interval waiting for the next entry. BLMOVE pops
		// the oldest (RIGHT, since Vector lpushes newest to the head) and pushes
		// it onto the processing list (LEFT) atomically.
		val, err := c.rc.BLMove(ctx, rawKey, procKey, "RIGHT", "LEFT", interval).Result()
		switch {
		case err == redis.Nil:
			// No entry within the interval — fall through to the flush check.
		case err != nil:
			if ctx.Err() != nil {
				return
			}
			c.log.WarnContext(ctx, "realtime: BLMOVE failed, retrying", "backoff", backoff, "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
				if backoff < 30*time.Second {
					backoff *= 2
				}
			}
			continue
		default:
			backoff = time.Second
			c.handleValue(ctx, agg, procKey, val)
		}

		// Flush aggregated deltas and refresh queue gauges on the interval.
		if time.Since(lastFlush) >= interval {
			c.flush(ctx, agg, geoipMapChannel)
			c.reportAndTrim(ctx, rawKey, procKey, maxLen)
			lastFlush = time.Now()
		}
	}
}

// handleValue parses one raw entry, aggregates it, and acks it (LREM from the
// processing list). Malformed entries are acked (not retried forever). When the
// processErr test hook returns an error the entry is left unacked for redelivery.
func (c *Consumer) handleValue(ctx context.Context, agg *aggregator, procKey, val string) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(val), &raw); err != nil {
		c.log.WarnContext(ctx, "realtime: bad json from redis, discarding", "err", err)
		c.ack(ctx, procKey, val)
		return
	}
	if c.processErr != nil {
		if err := c.processErr(raw); err != nil {
			c.log.WarnContext(ctx, "realtime: processing failed, leaving for redelivery", "err", err)
			return
		}
	}
	agg.addEvent(raw)
	c.ack(ctx, procKey, val)
}

// ack removes one instance of the handled entry from the processing list.
func (c *Consumer) ack(ctx context.Context, procKey, val string) {
	if err := c.rc.LRem(ctx, procKey, 1, val).Err(); err != nil {
		c.log.WarnContext(ctx, "realtime: ack (LREM) failed", "err", err)
	}
}

// flush publishes accumulated geoip deltas to Centrifugo (ephemeral; a failed
// publish drops that batch — the next batch supersedes it).
func (c *Consumer) flush(ctx context.Context, agg *aggregator, channel string) {
	points := agg.drain()
	if len(points) == 0 {
		return
	}
	payload := map[string]any{
		"type":   "geoip_map_delta",
		"ts":     time.Now().UnixMilli(),
		"points": points,
	}
	c.log.DebugContext(ctx, "realtime: flushing points", "count", len(points), "channel", channel)
	ok, _ := c.pub.Publish(ctx, channel, payload)
	if !ok {
		c.log.WarnContext(ctx, "realtime: drop points — publish failed", "count", len(points))
	}
}

// reportAndTrim updates queue-length gauges and caps the ingest list so a
// stalled consumer cannot grow it unbounded.
func (c *Consumer) reportAndTrim(ctx context.Context, rawKey, procKey string, maxLen int64) {
	rawLen, err := c.rc.LLen(ctx, rawKey).Result()
	if err != nil {
		return
	}
	if c.metrics != nil {
		c.metrics.SetQueueLength(rawKey, rawLen)
		if procLen, err := c.rc.LLen(ctx, procKey).Result(); err == nil {
			c.metrics.SetQueueLength(procKey, procLen)
		}
	}
	if maxLen > 0 && rawLen > maxLen {
		// Vector lpushes newest to the head, so keep the newest maxLen entries.
		if err := c.rc.LTrim(ctx, rawKey, 0, maxLen-1).Err(); err != nil {
			c.log.WarnContext(ctx, "realtime: LTRIM failed", "err", err)
		} else {
			c.log.WarnContext(ctx, "realtime: ingest list trimmed (backlog shed)",
				"key", rawKey, "had", rawLen, "kept", maxLen)
		}
	}
}

// ─── Redis client factory ─────────────────────────────────────────────────────

// NewRedisClient constructs a *redis.Client from REDIS_URL env.
// Returns nil and logs a warning if the URL cannot be parsed.
func NewRedisClient() *redis.Client {
	url := getenv("REDIS_URL", defaultRedisURL)
	opt, err := redis.ParseURL(url)
	if err != nil {
		slog.Warn("realtime: cannot parse REDIS_URL", "err", err)
		return nil
	}
	opt.DialTimeout = 2 * time.Second
	// BLMOVE blocks up to the flush interval per call; allow a little headroom
	// over the longest expected block so a normal timeout is not read as an error.
	opt.ReadTimeout = 10 * time.Second
	return redis.NewClient(opt)
}
