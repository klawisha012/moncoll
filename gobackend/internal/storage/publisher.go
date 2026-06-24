package storage

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"
)

// Publisher applies a change set atomically: callers Put/Delete objects, then
// call Publish to record them in a new manifest generation — the commit point
// edge sidecars watch (FR-004). Publish retries on ErrConflict so concurrent
// backend replicas converge (R6 / US2: CAS is the correctness floor).
type Publisher struct {
	store Store
	// OnPublish, if set, receives the new generation after each successful
	// publish — wired to the state_published_generation gauge (SC-007). Optional
	// so storage stays free of a metrics dependency.
	OnPublish func(generation int64)
	// Lock, if set, serialises the read-modify-publish section cluster-wide
	// (Postgres advisory lock, T025). Optional: nil in single-node local mode
	// (one writer); set in s3 mode so backend replicas rarely race on the CAS.
	// It only reduces contention — the CAS in PublishManifest is the floor (R6).
	Lock Locker
}

// Locker serialises a critical section across processes (advisory lock).
type Locker interface {
	WithLock(ctx context.Context, fn func() error) error
}

func NewPublisher(s Store) *Publisher { return &Publisher{store: s} }

// ChangeSet describes one atomic update to the source of truth.
type ChangeSet struct {
	Changed         []ObjectInfo // objects written this change set
	Removed         []string     // exact object keys deleted this change set
	RemovedPrefixes []string     // remove all manifest entries under these prefixes
	SuspendAdd      []int64      // tenants to mark suspended (FR-011)
	SuspendRemove   []int64      // tenants to unsuspend
}

const publishMaxAttempts = 8

// Publish bumps the generation, recording cs, and stores the new manifest with
// optimistic concurrency. On ErrConflict it rebuilds on the winner's manifest
// and retries. When a Locker is set, the whole read-modify-publish runs under a
// cluster-wide advisory lock so replicas rarely reach the CAS conflict path.
func (p *Publisher) Publish(ctx context.Context, cs ChangeSet) error {
	if p.Lock != nil {
		return p.Lock.WithLock(ctx, func() error { return p.publish(ctx, cs) })
	}
	return p.publish(ctx, cs)
}

func (p *Publisher) publish(ctx context.Context, cs ChangeSet) error {
	for attempt := 0; attempt < publishMaxAttempts; attempt++ {
		m, etag, err := p.store.ReadManifest(ctx)
		if err != nil {
			return err
		}
		m.Generation++
		m.PublishedAt = time.Now()
		if m.Entries == nil {
			m.Entries = map[string]Entry{}
		}
		for _, oi := range cs.Changed {
			m.Entries[oi.Key] = Entry{ETag: oi.ETag, Size: oi.Size, Mode: oi.Mode, Sensitive: oi.Sensitive}
		}
		for _, k := range cs.Removed {
			delete(m.Entries, k)
		}
		for _, prefix := range cs.RemovedPrefixes {
			for k := range m.Entries {
				if strings.HasPrefix(k, prefix) {
					delete(m.Entries, k)
				}
			}
		}
		m.SuspendedTenants = applySuspend(m.SuspendedTenants, cs.SuspendAdd, cs.SuspendRemove)

		if _, err := p.store.PublishManifest(ctx, m, etag); err != nil {
			if errors.Is(err, ErrConflict) {
				continue // another replica published first; rebuild and retry
			}
			return err
		}
		if p.OnPublish != nil {
			p.OnPublish(m.Generation)
		}
		return nil
	}
	return ErrConflict
}

func applySuspend(cur, add, remove []int64) []int64 {
	set := make(map[int64]struct{}, len(cur))
	for _, id := range cur {
		set[id] = struct{}{}
	}
	for _, id := range add {
		set[id] = struct{}{}
	}
	for _, id := range remove {
		delete(set, id)
	}
	out := make([]int64, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
