/**
 * Connections page — domain-only model (spec §7).
 *
 * Two surfaces:
 *
 *   1. List page — table of (domain, status, origin, actions). Status badges
 *      use Constructivist tokens; rows in pending_* state expose "Resume setup".
 *
 *   2. Three-step wizard modal (variant A — Inset Modal, approved via
 *      /design-shotgun on 2026-05-22):
 *
 *        Step 1: Name + Domain + Origin TLS mode
 *        Step 2: TXT _waf-verify token + auto-poll every 10s + "Verify now"
 *        Step 3: Edge IP instructions + Done
 *
 *      Closing the modal mid-flight does NOT delete the row — it stays in
 *      its current pending_* state and the list shows a "Resume setup"
 *      button next to its badge (spec §7.7 / decision D3A).
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { Plus, Trash2, RefreshCw, X, Copy, Shield, Check } from "lucide-react";

import {
  api,
  Connection,
  ConnectionCreate,
  ConnectionStatus,
  OriginTlsMode,
  VerifyInstructions,
} from "../api/client";
import { useSettings } from "../context/SettingsContext";

// ── Status badge palette (matches spec §7.1) ─────────────────────────────────
const BADGE_TONE: Record<ConnectionStatus, { bg: string; fg: string; icon: string }> = {
  pending_verification: { bg: "var(--cream-3)", fg: "var(--ink-soft)", icon: "▢" },
  pending_dns: { bg: "rgba(178, 122, 0, 0.16)", fg: "var(--amber)", icon: "▷" },
  provisioning_cert: { bg: "rgba(12, 12, 12, 0.08)", fg: "var(--ink)", icon: "◐" },
  active: { bg: "rgba(44, 122, 61, 0.16)", fg: "var(--ok)", icon: "■" },
  error: { bg: "var(--red-soft)", fg: "var(--red-deep)", icon: "▲" },
};

type Toast = { kind: "success" | "error" | "info"; msg: string };

// Auto-poll interval while step 2 (TXT verify) is open. Spec §7.8 (decision D2A).
const TXT_POLL_MS = 10_000;

// Background refresh interval for the list page — picks up poller status changes.
const LIST_REFRESH_MS = 15_000;

// ─────────────────────────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────────────────────────

export default function Connections() {
  const { t } = useSettings();
  const [rows, setRows] = useState<Connection[]>([]);
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState<Toast | null>(null);
  const [wizardConnId, setWizardConnId] = useState<number | "new" | null>(null);

  const showToast = useCallback((kind: Toast["kind"], msg: string) => {
    setToast({ kind, msg });
    setTimeout(() => setToast(null), 4000);
  }, []);

  const reload = useCallback(async () => {
    try {
      const data = await api.getConnections();
      setRows(data);
    } catch {
      showToast("error", t("connections.toast.loadFailed"));
    } finally {
      setLoading(false);
    }
  }, [showToast, t]);

  useEffect(() => {
    void reload();
  }, [reload]);

  // Refresh while page is open so badge transitions land without F5.
  useEffect(() => {
    const id = window.setInterval(() => void reload(), LIST_REFRESH_MS);
    return () => window.clearInterval(id);
  }, [reload]);

  const onDelete = useCallback(
    async (conn: Connection) => {
      if (!window.confirm(t("connections.confirmDelete"))) return;
      try {
        await api.deleteConnection(conn.id);
        showToast("success", t("connections.toast.deleted"));
        await reload();
      } catch {
        showToast("error", t("connections.toast.deleteFailed"));
      }
    },
    [reload, showToast, t]
  );

  const onProbe = useCallback(
    async (conn: Connection) => {
      try {
        await api.probeConnection(conn.id);
        showToast("info", t("connections.toast.probeOk"));
        await reload();
      } catch {
        showToast("error", t("connections.toast.toggleFailed"));
      }
    },
    [reload, showToast, t]
  );

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1 className="page-title">{t("connections.title")}</h1>
          <p className="page-subtitle">{t("connections.subtitle")}</p>
        </div>
        <button
          type="button"
          className="btn-primary"
          onClick={() => setWizardConnId("new")}
        >
          <Plus size={16} /> {t("connections.add")}
        </button>
      </header>

      {loading ? (
        <div className="card">{t("connections.loading")}</div>
      ) : rows.length === 0 ? (
        <EmptyState onAdd={() => setWizardConnId("new")} />
      ) : (
        <ConnectionsTable
          rows={rows}
          onDelete={onDelete}
          onProbe={onProbe}
          onResume={(id) => setWizardConnId(id)}
        />
      )}

      {wizardConnId !== null && (
        <Wizard
          conn={wizardConnId === "new" ? null : rows.find((r) => r.id === wizardConnId) ?? null}
          onClose={() => {
            setWizardConnId(null);
            void reload();
          }}
          onSavedResume={() => {
            setWizardConnId(null);
            showToast("info", t("connections.toast.savedResume"));
            void reload();
          }}
          showToast={showToast}
        />
      )}

      {toast && (
        <div
          role="status"
          aria-live="polite"
          className={`toast toast-${toast.kind}`}
          style={{
            position: "fixed",
            bottom: 24,
            right: 24,
            padding: "12px 18px",
            background: "var(--ink)",
            color: "var(--cream)",
            border: "2px solid var(--ink)",
            boxShadow: "var(--shadow-offset-sm)",
            fontFamily: "var(--font-cond)",
            textTransform: "uppercase",
            letterSpacing: "0.06em",
            fontSize: 13,
            zIndex: 1000,
          }}
        >
          {toast.msg}
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Subcomponents
// ─────────────────────────────────────────────────────────────────────────────

function EmptyState({ onAdd }: { onAdd: () => void }) {
  const { t } = useSettings();
  return (
    <div
      className="card"
      style={{
        textAlign: "center",
        padding: "48px 24px",
        border: "2px solid var(--ink)",
        boxShadow: "var(--shadow-offset)",
        background: "var(--cream-2)",
      }}
    >
      <Shield size={48} style={{ marginBottom: 12, color: "var(--ink)" }} />
      <h2 style={{ fontFamily: "var(--font-display)", marginBottom: 8 }}>
        {t("connections.empty.title")}
      </h2>
      <p style={{ color: "var(--ink-soft)", marginBottom: 20, maxWidth: 420, margin: "0 auto 20px" }}>
        {t("connections.empty.desc")}
      </p>
      <button type="button" className="btn-primary" onClick={onAdd}>
        <Plus size={16} /> {t("connections.add")}
      </button>
    </div>
  );
}

function ConnectionsTable({
  rows,
  onDelete,
  onProbe,
  onResume,
}: {
  rows: Connection[];
  onDelete: (c: Connection) => void;
  onProbe: (c: Connection) => void;
  onResume: (id: number) => void;
}) {
  const { t } = useSettings();
  return (
    <div className="card" style={{ border: "2px solid var(--ink)", overflow: "hidden" }}>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr style={{ background: "var(--ink)", color: "var(--cream)" }}>
            <Th>{t("connections.col.domain")}</Th>
            <Th>{t("connections.col.status")}</Th>
            <Th>{t("connections.col.origin")}</Th>
            <Th style={{ textAlign: "right" }}>{t("connections.col.actions")}</Th>
          </tr>
        </thead>
        <tbody>
          {rows.map((c) => (
            <tr key={c.id} style={{ borderTop: "1.5px solid var(--ink)" }}>
              <Td>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 14 }}>{c.domain}</div>
                <div style={{ fontSize: 12, color: "var(--ink-soft)" }}>{c.name}</div>
              </Td>
              <Td>
                <StatusBadge status={c.status} detail={c.status_detail} />
              </Td>
              <Td>
                <code style={{ fontSize: 12, color: "var(--ink-soft)" }}>
                  {c.origin_hosts.length ? c.origin_hosts.join(", ") : "—"}
                </code>
              </Td>
              <Td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                {(c.status === "pending_verification" || c.status === "pending_dns") && (
                  <button
                    type="button"
                    className="btn-outline btn-sm"
                    onClick={() => onResume(c.id)}
                    style={{ marginRight: 8 }}
                  >
                    {t("connections.action.resume")}
                  </button>
                )}
                {c.status === "error" && (
                  <button
                    type="button"
                    className="btn-outline btn-sm"
                    onClick={() => onProbe(c)}
                    style={{ marginRight: 8 }}
                  >
                    <RefreshCw size={14} /> {t("connections.action.retry")}
                  </button>
                )}
                <button
                  type="button"
                  className="btn-icon"
                  aria-label={t("connections.delete")}
                  onClick={() => onDelete(c)}
                >
                  <Trash2 size={16} />
                </button>
              </Td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Th({ children, style }: React.PropsWithChildren<{ style?: React.CSSProperties }>) {
  return (
    <th
      style={{
        padding: "10px 14px",
        textAlign: "left",
        fontFamily: "var(--font-cond)",
        textTransform: "uppercase",
        letterSpacing: "0.06em",
        fontSize: 12,
        ...style,
      }}
    >
      {children}
    </th>
  );
}

function Td({ children, style }: React.PropsWithChildren<{ style?: React.CSSProperties }>) {
  return <td style={{ padding: "12px 14px", verticalAlign: "middle", ...style }}>{children}</td>;
}

function StatusBadge({ status, detail }: { status: ConnectionStatus; detail: string | null }) {
  const { t } = useSettings();
  const tone = BADGE_TONE[status];
  return (
    <span
      title={detail ?? ""}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        padding: "3px 10px",
        background: tone.bg,
        color: tone.fg,
        border: `1.5px solid ${tone.fg}`,
        fontFamily: "var(--font-cond)",
        fontSize: 11,
        textTransform: "uppercase",
        letterSpacing: "0.04em",
      }}
    >
      <span style={{ fontSize: 13, lineHeight: 1 }}>{tone.icon}</span>
      {t(`connections.status.${status}`)}
    </span>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Wizard
// ─────────────────────────────────────────────────────────────────────────────

type WizardStep = 1 | 2 | 3;

function Wizard({
  conn,
  onClose,
  onSavedResume,
  showToast,
}: {
  conn: Connection | null;
  onClose: () => void;
  onSavedResume: () => void;
  showToast: (kind: Toast["kind"], msg: string) => void;
}) {
  const { t } = useSettings();

  // Step is derived from the row's status when resuming; "new" rows start at 1.
  const initialStep: WizardStep = useMemo(() => {
    if (!conn) return 1;
    if (conn.status === "pending_verification") return 2;
    return 3;
  }, [conn]);
  const [step, setStep] = useState<WizardStep>(initialStep);

  const [name, setName] = useState(conn?.name ?? "");
  const [domain, setDomain] = useState(conn?.domain ?? "");
  const [tlsMode, setTlsMode] = useState<OriginTlsMode>(conn?.origin_tls_mode ?? "strict");
  const [submitting, setSubmitting] = useState(false);
  const [createdConn, setCreatedConn] = useState<Connection | null>(conn);
  const [instructions, setInstructions] = useState<VerifyInstructions | null>(
    conn
      ? {
          txt_record_name: `_waf-verify.${conn.domain}`,
          txt_record_value: conn.verify_token,
          edge_ipv4: "", // resolved from the server's env on backend; surfaced via probe below
        }
      : null
  );
  const [verifying, setVerifying] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // Close on Esc — saved (not discarded), per decision D3A.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        if (step > 1 && createdConn) onSavedResume();
        else onClose();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [step, createdConn, onClose, onSavedResume]);

  // ── Step 1 → Step 2: create the row ──
  const submitStep1 = useCallback(async () => {
    setFormError(null);
    if (!name.trim() || !domain.trim()) {
      setFormError("Name and domain are required.");
      return;
    }
    setSubmitting(true);
    try {
      const body: ConnectionCreate = {
        name: name.trim(),
        domain: domain.trim(),
        origin_tls_mode: tlsMode,
      };
      const res = await api.createConnection(body);
      setCreatedConn(res.connection);
      setInstructions(res.instructions);
      setStep(2);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setFormError(msg);
    } finally {
      setSubmitting(false);
    }
  }, [name, domain, tlsMode]);

  // ── Step 2 → Step 3: TXT verified ──
  const checkVerified = useCallback(async (): Promise<boolean> => {
    if (!createdConn) return false;
    setVerifying(true);
    try {
      const fresh = await api.probeConnection(createdConn.id);
      setCreatedConn(fresh);
      // The poller advances pending_verification → pending_dns the moment TXT
      // is seen. So any status past pending_verification means we're verified.
      return fresh.status !== "pending_verification";
    } catch {
      return false;
    } finally {
      setVerifying(false);
    }
  }, [createdConn]);

  // Auto-poll TXT every 10s while step 2 is open (decision D2A).
  useEffect(() => {
    if (step !== 2 || !createdConn) return;
    let cancelled = false;
    const tick = async () => {
      if (cancelled) return;
      const ok = await checkVerified();
      if (ok && !cancelled) setStep(3);
    };
    void tick();
    const id = window.setInterval(tick, TXT_POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [step, createdConn, checkVerified]);

  const onCopy = useCallback(
    async (value: string) => {
      try {
        await navigator.clipboard.writeText(value);
        showToast("info", t("connections.toast.copyOk"));
      } catch {
        // clipboard may be denied in insecure contexts — silently fail
      }
    },
    [showToast, t]
  );

  const backdropClick = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      if (e.target === e.currentTarget) {
        if (step > 1 && createdConn) onSavedResume();
        else onClose();
      }
    },
    [step, createdConn, onClose, onSavedResume]
  );

  return (
    <div
      onClick={backdropClick}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(12, 12, 12, 0.55)",
        display: "flex",
        alignItems: "flex-start",
        justifyContent: "center",
        paddingTop: 64,
        zIndex: 900,
      }}
      role="dialog"
      aria-modal="true"
      aria-labelledby="wizard-heading"
    >
      <div
        style={{
          width: 480,
          maxWidth: "95vw",
          background: "var(--cream)",
          border: "2px solid var(--ink)",
          boxShadow: "var(--shadow-offset-lg)",
          padding: 24,
          position: "relative",
        }}
      >
        <button
          type="button"
          className="btn-icon"
          onClick={() => {
            if (step > 1 && createdConn) onSavedResume();
            else onClose();
          }}
          aria-label="Close"
          style={{ position: "absolute", top: 8, right: 8 }}
        >
          <X size={18} />
        </button>

        <StepIndicator current={step} />

        <h2
          id="wizard-heading"
          style={{
            fontFamily: "var(--font-display)",
            fontWeight: 700,
            fontSize: 22,
            marginBottom: 4,
          }}
        >
          {t("wizard.title")}
        </h2>
        <div
          style={{
            fontFamily: "var(--font-cond)",
            textTransform: "uppercase",
            letterSpacing: "0.06em",
            fontSize: 11,
            color: "var(--ink-soft)",
            marginBottom: 20,
          }}
        >
          {t("wizard.stepOf").replace("{n}", String(step))}
        </div>

        {step === 1 && (
          <Step1
            name={name}
            domain={domain}
            tlsMode={tlsMode}
            submitting={submitting}
            error={formError}
            onName={setName}
            onDomain={setDomain}
            onTlsMode={setTlsMode}
            onCancel={onClose}
            onNext={submitStep1}
          />
        )}

        {step === 2 && instructions && (
          <Step2
            instructions={instructions}
            verifying={verifying}
            statusDetail={createdConn?.status_detail ?? null}
            onCopy={onCopy}
            onVerifyNow={async () => {
              const ok = await checkVerified();
              if (ok) setStep(3);
            }}
            onCancel={() => onSavedResume()}
          />
        )}

        {step === 3 && createdConn && instructions && (
          <Step3
            domain={createdConn.domain}
            originHosts={createdConn.origin_hosts}
            edgeIpv4={instructions.edge_ipv4}
            onCopy={onCopy}
            onDone={onClose}
          />
        )}
      </div>
    </div>
  );
}

function StepIndicator({ current }: { current: WizardStep }) {
  return (
    <div style={{ display: "flex", gap: 8, marginBottom: 18 }}>
      {[1, 2, 3].map((n) => (
        <span
          key={n}
          aria-current={n === current ? "step" : undefined}
          style={{
            width: 14,
            height: 14,
            border: "2px solid var(--ink)",
            background: n === current ? "var(--ink)" : "transparent",
            transition: "background var(--duration-fast) var(--ease-out)",
          }}
        />
      ))}
    </div>
  );
}

function Step1({
  name,
  domain,
  tlsMode,
  submitting,
  error,
  onName,
  onDomain,
  onTlsMode,
  onCancel,
  onNext,
}: {
  name: string;
  domain: string;
  tlsMode: OriginTlsMode;
  submitting: boolean;
  error: string | null;
  onName: (s: string) => void;
  onDomain: (s: string) => void;
  onTlsMode: (m: OriginTlsMode) => void;
  onCancel: () => void;
  onNext: () => void;
}) {
  const { t } = useSettings();
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (!submitting) onNext();
      }}
    >
      <Label>{t("wizard.step1.name")}</Label>
      <input
        type="text"
        value={name}
        onChange={(e) => onName(e.target.value)}
        placeholder={t("wizard.step1.namePlaceholder")}
        autoFocus
        style={fieldStyle}
      />

      <Label>{t("wizard.step1.domain")}</Label>
      <input
        type="text"
        value={domain}
        onChange={(e) => onDomain(e.target.value)}
        placeholder={t("wizard.step1.domainPlaceholder")}
        autoCapitalize="none"
        autoCorrect="off"
        spellCheck={false}
        style={{ ...fieldStyle, fontFamily: "var(--font-mono)" }}
      />

      <Label>{t("wizard.step1.tls")}</Label>
      <div style={{ display: "flex", gap: 16, marginBottom: 6 }}>
        {(["strict", "lenient"] as const).map((m) => (
          <label
            key={m}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 6,
              fontSize: 13,
              cursor: "pointer",
            }}
          >
            <span
              style={{
                width: 14,
                height: 14,
                border: "2px solid var(--ink)",
                background: tlsMode === m ? "var(--ink)" : "transparent",
              }}
            />
            <input
              type="radio"
              checked={tlsMode === m}
              onChange={() => onTlsMode(m)}
              style={{ position: "absolute", opacity: 0, pointerEvents: "none" }}
            />
            {t(`wizard.step1.tls.${m}`)}
          </label>
        ))}
      </div>
      <div style={{ fontSize: 12, color: "var(--ink-soft)", marginBottom: 16 }}>
        {t("wizard.step1.tls.hint")}
      </div>

      {error && (
        <div
          role="alert"
          style={{
            background: "var(--red-soft)",
            border: "2px solid var(--red-deep)",
            padding: 10,
            marginBottom: 16,
            color: "var(--red-deep)",
            fontSize: 13,
          }}
        >
          {error}
        </div>
      )}

      <div style={{ display: "flex", justifyContent: "flex-end", gap: 12 }}>
        <button type="button" className="btn-outline" onClick={onCancel}>
          {t("wizard.cancel")}
        </button>
        <button type="submit" className="btn-primary" disabled={submitting} aria-busy={submitting}>
          {submitting ? "…" : t("wizard.next")}
        </button>
      </div>
    </form>
  );
}

function Step2({
  instructions,
  verifying,
  statusDetail,
  onCopy,
  onVerifyNow,
  onCancel,
}: {
  instructions: VerifyInstructions;
  verifying: boolean;
  statusDetail: string | null;
  onCopy: (value: string) => void;
  onVerifyNow: () => void;
  onCancel: () => void;
}) {
  const { t } = useSettings();
  // Distinguish a "fresh first probe" from a "we checked and didn't find it
  // yet" state — the latter deserves a more pointed message than the
  // generic auto-poll hint.
  const txtNotFound =
    !verifying &&
    !!statusDetail &&
    (statusDetail.toLowerCase().includes("not found") || statusDetail.toLowerCase().includes("propagation"));

  return (
    <>
      <h3 style={{ fontSize: 16, marginBottom: 6 }}>{t("wizard.step2.title")}</h3>
      <p style={{ fontSize: 13, marginBottom: 16 }}>{t("wizard.step2.body")}</p>

      <KeyValueBlock label="Name" value={instructions.txt_record_name} onCopy={onCopy} />
      <KeyValueBlock label="TXT value" value={instructions.txt_record_value} onCopy={onCopy} />

      <div
        role="status"
        aria-live="polite"
        style={{
          fontSize: 12,
          color: txtNotFound ? "var(--red-deep)" : "var(--ink-soft)",
          margin: "10px 0 18px",
          minHeight: 18,
          display: "flex",
          alignItems: "center",
          gap: 6,
        }}
      >
        {verifying && (
          <span
            aria-hidden
            style={{
              display: "inline-block",
              animation: "spin 0.9s linear infinite",
              fontSize: 14,
              lineHeight: 1,
            }}
          >
            ◐
          </span>
        )}
        {verifying
          ? "Checking DNS for the TXT record…"
          : txtNotFound
          ? statusDetail
          : t("wizard.step2.polling")}
      </div>

      {/* Local keyframes (Constructivist system has no spinner utility yet). */}
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>

      <div style={{ display: "flex", justifyContent: "flex-end", gap: 12 }}>
        <button type="button" className="btn-outline" onClick={onCancel}>
          {t("wizard.cancel")}
        </button>
        <button
          type="button"
          className="btn-primary"
          onClick={onVerifyNow}
          disabled={verifying}
          aria-busy={verifying}
          style={{ minWidth: 150 }}
        >
          {verifying ? (
            <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
              <span
                aria-hidden
                style={{ animation: "spin 0.9s linear infinite", display: "inline-block" }}
              >
                ◐
              </span>
              {"Checking…"}
            </span>
          ) : (
            <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
              <Check size={14} /> {t("wizard.step2.verifyNow")}
            </span>
          )}
        </button>
      </div>
    </>
  );
}

function Step3({
  domain,
  originHosts,
  edgeIpv4,
  onCopy,
  onDone,
}: {
  domain: string;
  originHosts: string[];
  edgeIpv4: string;
  onCopy: (value: string) => void;
  onDone: () => void;
}) {
  const { t } = useSettings();
  return (
    <>
      <h3 style={{ fontSize: 16, marginBottom: 6 }}>{t("wizard.step3.title")}</h3>
      <p style={{ fontSize: 13, marginBottom: 12 }}>
        {t("wizard.step3.bodyVerified").replace("{origin}", originHosts.join(", ") || "—")}
      </p>
      <p style={{ fontSize: 13, marginBottom: 12 }}>
        {t("wizard.step3.bodyPoint").replace("{domain}", domain)}
      </p>

      {edgeIpv4 ? (
        <KeyValueBlock label="A record" value={edgeIpv4} onCopy={onCopy} />
      ) : (
        <div
          role="alert"
          style={{
            background: "var(--red-soft)",
            border: "2px solid var(--red-deep)",
            padding: 10,
            marginBottom: 16,
            color: "var(--red-deep)",
            fontSize: 13,
          }}
        >
          {t("wizard.step3.edgeMissing")}
        </div>
      )}

      <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 20 }}>
        <button type="button" className="btn-primary" onClick={onDone}>
          {t("wizard.step3.done")}
        </button>
      </div>
    </>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Reused atoms
// ─────────────────────────────────────────────────────────────────────────────

function Label({ children }: React.PropsWithChildren) {
  return (
    <label
      style={{
        display: "block",
        fontFamily: "var(--font-cond)",
        textTransform: "uppercase",
        letterSpacing: "0.06em",
        fontSize: 11,
        color: "var(--ink-soft)",
        marginTop: 12,
        marginBottom: 6,
      }}
    >
      {children}
    </label>
  );
}

const fieldStyle: React.CSSProperties = {
  width: "100%",
  height: 44,
  padding: "0 10px",
  background: "var(--input-bg)",
  border: "2px solid var(--ink)",
  color: "var(--ink)",
  fontSize: 14,
};

function KeyValueBlock({
  label,
  value,
  onCopy,
}: {
  label: string;
  value: string;
  onCopy: (value: string) => void;
}) {
  // Click-to-copy block; spec §7.4 (mobile tap-to-copy).
  return (
    <div style={{ marginBottom: 10 }}>
      <div
        style={{
          fontFamily: "var(--font-cond)",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          fontSize: 10,
          color: "var(--ink-soft)",
          marginBottom: 4,
        }}
      >
        {label}
      </div>
      <button
        type="button"
        onClick={() => onCopy(value)}
        title="Click to copy"
        style={{
          width: "100%",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "10px 12px",
          background: "var(--cream-3)",
          border: "2px solid var(--ink)",
          fontFamily: "var(--font-mono)",
          fontSize: 13,
          color: "var(--ink)",
          textAlign: "left",
          cursor: "pointer",
        }}
      >
        <span style={{ overflow: "auto", wordBreak: "break-all" }}>{value}</span>
        <Copy size={14} style={{ flexShrink: 0, marginLeft: 8 }} />
      </button>
    </div>
  );
}
