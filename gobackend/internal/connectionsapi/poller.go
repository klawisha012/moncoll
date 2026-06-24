// Package connectionsapi (continued) — background DNS/ACME poller.
//
// This file ports backend/src/connections/poller.py to Go.
//
// State transitions (spec §3):
//
//	pending_verification → pending_dns       (TXT _waf-verify.<domain> seen)
//	pending_dns          → provisioning_cert (A(domain) ⊇ {EDGE_IPV4})
//	provisioning_cert    → active            (ACME succeeded)
//	provisioning_cert    → pending_dns       (ACME failed, retries left)
//	provisioning_cert    → error             (acme_retry_count >= MAX_RETRIES, strict TLS)
//	provisioning_cert    → active            (ACME exhausted, self-signed fallback, lenient TLS)
//	error                → pending_dns       (treated same as pending_dns on next tick)
//
// Best-effort: every error is logged; the poller never crashes the server.
package connectionsapi

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/zwarder/waf/gobackend/internal/angiecfg"
	"github.com/zwarder/waf/gobackend/internal/conndns"
	"github.com/zwarder/waf/gobackend/internal/edge"
	"github.com/zwarder/waf/gobackend/internal/store"
)

// Notifier is the subset of notify.Notifier used by the poller.
// Defining it locally keeps the package free of a hard dependency on the
// notify package and allows tests to inject a fake.
type Notifier interface {
	NotifyTenantMembers(ctx context.Context, tenantID, excludeUserID int64, typ, title, body string, data map[string]any) error
}

// Poller runs the background DNS/ACME state machine for connections.
type Poller struct {
	store    Store
	dns      conndns.Verifier
	edge     edge.Resolver
	cfg      CfgWriter
	certs    CertManager
	reloader AngieReloader
	notifier Notifier // optional; nil = no notifications
	log      *slog.Logger

	tickInterval time.Duration
	connTimeout  time.Duration
}

// NewPoller constructs a Poller. notifier may be nil (no notifications emitted).
func NewPoller(
	store Store,
	dns conndns.Verifier,
	edgeResolver edge.Resolver,
	cfg CfgWriter,
	certs CertManager,
	reloader AngieReloader,
	log *slog.Logger,
	notifier Notifier,
) *Poller {
	tick := 60 * time.Second
	if s := os.Getenv("WAF_POLLER_TICK_SECONDS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			tick = time.Duration(n) * time.Second
		}
	}
	// Per-connection processing deadline so one stuck DNS/ACME/DB op cannot
	// wedge the whole poller. Generous by default (covers normal ACME issuance);
	// override with WAF_POLLER_CONN_TIMEOUT_SECONDS.
	connTimeout := 120 * time.Second
	if s := os.Getenv("WAF_POLLER_CONN_TIMEOUT_SECONDS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			connTimeout = time.Duration(n) * time.Second
		}
	}
	return &Poller{
		store:        store,
		dns:          dns,
		edge:         edgeResolver,
		cfg:          cfg,
		certs:        certs,
		reloader:     reloader,
		notifier:     notifier,
		log:          log,
		tickInterval: tick,
		connTimeout:  connTimeout,
	}
}

// Run blocks until ctx is cancelled, waking every tickInterval to process
// due connections. Best-effort: panics from individual ticks are recovered.
func (p *Poller) Run(ctx context.Context) {
	p.log.Info("connections poller starting",
		"tick", p.tickInterval,
		"edge_mode", "resolver",
	)
	for {
		select {
		case <-ctx.Done():
			p.log.Info("connections poller stopped")
			return
		default:
		}

		func() {
			defer func() {
				if r := recover(); r != nil {
					p.log.Error("poller tick panicked", "panic", r)
				}
			}()
			if count, err := p.tickOnce(ctx); err != nil {
				p.log.Error("poller tick failed", "err", err)
			} else if count > 0 {
				p.log.Debug("poller tick", "processed", count)
			}
		}()

		select {
		case <-ctx.Done():
			p.log.Info("connections poller stopped")
			return
		case <-time.After(p.tickInterval):
		}
	}
}

// tickOnce fetches due rows and processes them sequentially.
// (Python uses asyncio.gather with a semaphore; Go uses goroutines but
// for simplicity we process sequentially — the poller is single-threaded
// and ACME calls are the bottleneck anyway.)
func (p *Poller) tickOnce(ctx context.Context) (int, error) {
	rows, err := p.store.ListConnectionsForPoll(ctx)
	if err != nil {
		return 0, fmt.Errorf("ListConnectionsForPoll: %w", err)
	}
	for i := range rows {
		p.processOne(ctx, &rows[i])
	}
	return len(rows), nil
}

// processOne runs one tick for a single connection. Errors are logged; the
// poller continues regardless.
func (p *Poller) processOne(ctx context.Context, row *store.Connection) {
	if !row.Enabled {
		return
	}
	// Bound this connection's I/O (DNS, ACME, DB) so a single stuck op cannot
	// hang the poller. Derived from the loop context, so a shutdown still wins.
	ctx, cancel := context.WithTimeout(ctx, p.connTimeout)
	defer cancel()

	prevStatus := row.Status
	now := time.Now().UTC()

	ps := store.PollerState{
		Status:         row.Status,
		StatusDetail:   row.StatusDetail,
		VerifiedAt:     row.VerifiedAt,
		AcmeRetryCount: row.AcmeRetryCount,
		DNSTTLSeconds:  row.DNSTTLSeconds,
		SSLCertPath:    row.SSLCertPath,
		SSLKeyPath:     row.SSLKeyPath,
	}

	var tickErr error
	switch row.Status {
	case "pending_verification":
		tickErr = p.tickVerification(ctx, row, &ps)
	case "pending_dns", "error":
		tickErr = p.tickPendingDNS(ctx, row, &ps)
	case "provisioning_cert":
		tickErr = p.tickProvisioning(ctx, row, &ps)
	}

	if tickErr != nil {
		p.log.Warn("poller tick error", "conn", row.ID, "status", row.Status, "err", tickErr)
		d := fmt.Sprintf("Poller error: %v", tickErr)
		ps.StatusDetail = &d
	}

	// Bump next_poll_at: max(tickInterval, dns_ttl)
	delay := p.tickInterval
	if ttl := time.Duration(row.DNSTTLSeconds) * time.Second; ttl > delay {
		delay = ttl
	}
	nextPoll := now.Add(delay)
	ps.NextPollAt = &nextPoll
	ps.LastCheckedAt = &now

	updated, err := p.store.UpdatePollerState(ctx, row.ID, ps)
	if err != nil {
		p.log.Error("poller: UpdatePollerState failed", "conn", row.ID, "err", err)
		return
	}

	if updated.Status != prevStatus {
		p.log.Info("poller: status changed",
			"conn", row.ID, "from", prevStatus, "to", updated.Status)
		cfg := connCfg(updated)
		if wErr := p.cfg.Write(ctx, cfg); wErr != nil {
			p.log.Warn("poller: failed to write Angie config", "conn", row.ID, "err", wErr)
		} else {
			p.reloader.Reload(ctx)
		}

		if p.notifier != nil {
			switch updated.Status {
			case "active":
				if err := p.notifier.NotifyTenantMembers(ctx, updated.TenantID, 0,
					"connection.active", "Connection active",
					"Connection "+updated.Name+" is now active and protected.",
					map[string]any{"connection_id": updated.ID, "name": updated.Name},
				); err != nil && p.log != nil {
					p.log.Warn("poller: notify active failed", "conn", row.ID, "err", err)
				}
			case "error":
				if err := p.notifier.NotifyTenantMembers(ctx, updated.TenantID, 0,
					"connection.error", "Connection error",
					"Connection "+updated.Name+" failed: certificate could not be issued.",
					map[string]any{"connection_id": updated.ID, "name": updated.Name},
				); err != nil && p.log != nil {
					p.log.Warn("poller: notify error failed", "conn", row.ID, "err", err)
				}
			}
		}
	}
}

// tickVerification mirrors _tick_verification in poller.py.
func (p *Poller) tickVerification(ctx context.Context, row *store.Connection, ps *store.PollerState) error {
	found, _ := p.dns.VerifyTXT(ctx, row.Domain, row.VerifyToken)
	if found {
		ps.Status = "pending_dns"
		now := time.Now().UTC()
		ps.VerifiedAt = &now
		d := "Domain ownership verified."
		ps.StatusDetail = &d
		p.log.Info("poller: TXT verified", "conn", row.ID)

		if len(row.OriginHosts) == 0 {
			if ips, err := p.dns.LookupOriginHosts(ctx, row.Domain); err == nil && len(ips) > 0 {
				_, updateErr := p.store.UpdateConnection(ctx, row.TenantID, row.ID, store.ConnectionUpdate{
					OriginHosts: ips,
				})
				if updateErr == nil {
					row.OriginHosts = ips
				} else {
					p.log.Warn("poller: failed to save resolved origin hosts", "conn", row.ID, "err", updateErr)
				}
			}
		}
	} else {
		d := "Waiting for TXT _waf-verify record to propagate."
		ps.StatusDetail = &d
	}
	return nil
}

// tickPendingDNS mirrors _tick_pending_dns in poller.py.
func (p *Poller) tickPendingDNS(ctx context.Context, row *store.Connection, ps *store.PollerState) error {
	targets := p.edge.Resolve(ctx)
	if len(targets.IPs) == 0 {
		p.log.Warn("poller: edge not configured; cannot detect DNS flip", "conn", row.ID)
		d := "Edge not configured; cannot detect DNS flip."
		ps.StatusDetail = &d
		return nil
	}
	result := p.dns.VerifyEdge(ctx, row.Domain, targets.IPs)
	if result.Err != nil {
		d := fmt.Sprintf("DNS lookup: %v", result.Err)
		ps.StatusDetail = &d
		return nil
	}
	ps.DNSTTLSeconds = row.DNSTTLSeconds // unchanged if not resolved
	if result.FlippedToEdge {
		ps.Status = "provisioning_cert"
		d := "DNS now points to WAF edge; issuing certificate."
		ps.StatusDetail = &d
		p.log.Info("poller: DNS flipped to edge", "conn", row.ID)
	} else {
		d := fmt.Sprintf("A-record points to %s; expecting %s.", strings.Join(result.ResolvedIPs, ","), result.EdgeIP)
		ps.StatusDetail = &d
	}
	return nil
}

// tickProvisioning mirrors _tick_provisioning in poller.py (with exponential
// backoff and self-signed fallback).
func (p *Poller) tickProvisioning(ctx context.Context, row *store.Connection, ps *store.PollerState) error {
	// Throttle: backoff window
	if row.AcmeNextRetryAt != nil && row.AcmeNextRetryAt.After(time.Now().UTC()) {
		return nil
	}

	tenantID := row.TenantID
	result := p.certs.TriggerACME(row.ID, []string{row.Domain}, &tenantID)

	if result.Success {
		certPath := result.CertificatePath
		keyPath := result.KeyPath
		ps.SSLCertPath = &certPath
		ps.SSLKeyPath = &keyPath
		ps.Status = "active"
		d := "Certificate issued."
		ps.StatusDetail = &d
		ps.AcmeRetryCount = 0
		ps.AcmeNextRetryAt = nil
		p.log.Info("poller: ACME succeeded", "conn", row.ID)
		// Immediately write config with cert paths so TLS block is rendered
		if wErr := p.writeCertConfig(ctx, row, ps); wErr != nil {
			p.log.Warn("poller: config write after ACME", "conn", row.ID, "err", wErr)
		}
		return nil
	}

	// ACME failed
	ps.AcmeRetryCount = row.AcmeRetryCount + 1
	d := fmt.Sprintf("ACME failed: %s", result.Message)
	ps.StatusDetail = &d

	if ps.AcmeRetryCount >= acmeMaxRetries {
		// Exhausted retries
		if row.OriginTLSMode == "strict" {
			ps.Status = "error"
			ps.AcmeNextRetryAt = nil
			detail := fmt.Sprintf("ACME failed: %s (Strict TLS mode prevents self-signed fallback)", result.Message)
			ps.StatusDetail = &detail
			p.log.Warn("poller: ACME exhausted (strict TLS)", "conn", row.ID)
		} else {
			// Lenient: fall back to self-signed
			p.log.Warn("poller: ACME exhausted, falling back to self-signed", "conn", row.ID)
			fbResult, _ := p.certs.GenerateSelfSigned(row.ID, []string{row.Domain}, &tenantID)
			if fbResult.Success {
				certPath := fbResult.CertificatePath
				keyPath := fbResult.KeyPath
				ps.SSLCertPath = &certPath
				ps.SSLKeyPath = &keyPath
				ps.Status = "active"
				ps.StatusDetail = ptrString("Self-signed cert (ACME unreachable from this network).")
				ps.AcmeNextRetryAt = nil
				if wErr := p.writeCertConfig(ctx, row, ps); wErr != nil {
					p.log.Warn("poller: config write after self-signed", "conn", row.ID, "err", wErr)
				}
			} else {
				ps.Status = "error"
				ps.AcmeNextRetryAt = nil
				detail := fmt.Sprintf("ACME and self-signed both failed: %s", fbResult.Message)
				ps.StatusDetail = &detail
			}
		}
	} else {
		// Retries remain: go back to pending_dns + schedule next retry
		ps.Status = "pending_dns"
		next := acmeScheduleNextRetry(ps.AcmeRetryCount)
		ps.AcmeNextRetryAt = &next
	}
	return nil
}

// writeCertConfig is called immediately after ACME succeeds to write the config
// with SSL cert paths before UpdatePollerState fires (so the status-change
// detection branch in processOne sees the new Angie config).
func (p *Poller) writeCertConfig(ctx context.Context, row *store.Connection, ps *store.PollerState) error {
	// Build a synthetic Connection with the new cert paths for the config writer.
	tmp := *row
	tmp.SSLCertPath = ps.SSLCertPath
	tmp.SSLKeyPath = ps.SSLKeyPath
	tmp.Status = ps.Status
	tmp.StatusDetail = ps.StatusDetail
	cfg := angiecfg.ConnConfig{
		ID:                         tmp.ID,
		TenantID:                   tmp.TenantID,
		Name:                       tmp.Name,
		Domain:                     tmp.Domain,
		OriginHosts:                tmp.OriginHosts,
		OriginPort:                 tmp.OriginPort,
		OriginTLSMode:              tmp.OriginTLSMode,
		Status:                     tmp.Status,
		StatusDetail:               tmp.StatusDetail,
		HTTPVersions:               tmp.HTTPVersions,
		Compression:                tmp.CompressionAlgo,
		ModsecState:                tmp.ModsecState,
		GeoipDenied:                tmp.GeoipDeniedCountries,
		CrowdsecActive:             tmp.CrowdsecActive,
		SSLCertPath:                tmp.SSLCertPath,
		SSLKeyPath:                 tmp.SSLKeyPath,
		ExcludeControlPlaneMetrics: selfTenantID != 0 && tmp.TenantID == selfTenantID,
	}
	return p.cfg.Write(ctx, cfg)
}
