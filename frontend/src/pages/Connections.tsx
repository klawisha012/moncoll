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

import { createSignal, createEffect, createMemo, onMount, onCleanup, For, Show, type JSX } from "solid-js";
import { Plus, Trash2, RefreshCw, X, Copy, Shield, Check } from "lucide-solid";

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
  const settings = useSettings();
  const [rows, setRows] = createSignal<Connection[]>([]);
  const [loading, setLoading] = createSignal(true);
  const [toast, setToast] = createSignal<Toast | null>(null);
  const [wizardConnId, setWizardConnId] = createSignal<number | "new" | null>(null);

  const showToast = (kind: Toast["kind"], msg: string) => {
    setToast({ kind, msg });
    setTimeout(() => setToast(null), 4000);
  };

  const reload = async () => {
    try {
      const data = await api.getConnections();
      setRows(data);
    } catch {
      showToast("error", settings.t("connections.toast.loadFailed"));
    } finally {
      setLoading(false);
    }
  };

  onMount(() => {
    void reload();
    const intervalId = setInterval(() => void reload(), LIST_REFRESH_MS);
    onCleanup(() => clearInterval(intervalId));
  });

  const onDelete = async (conn: Connection) => {
    if (!window.confirm(settings.t("connections.confirmDelete"))) return;
    try {
      await api.deleteConnection(conn.id);
      showToast("success", settings.t("connections.toast.deleted"));
      await reload();
    } catch {
      showToast("error", settings.t("connections.toast.deleteFailed"));
    }
  };

  const onProbe = async (conn: Connection) => {
    try {
      await api.probeConnection(conn.id);
      showToast("info", settings.t("connections.toast.probeOk"));
      await reload();
    } catch {
      showToast("error", settings.t("connections.toast.toggleFailed"));
    }
  };

  return (
    <div class="page">
      <header class="page-header">
        <div>
          <h1 class="page-title">{settings.t("connections.title")}</h1>
          <p class="page-subtitle">{settings.t("connections.subtitle")}</p>
        </div>
        <button
          type="button"
          class="btn-primary"
          onClick={() => setWizardConnId("new")}
        >
          <Plus size={16} /> {settings.t("connections.add")}
        </button>
      </header>

      <Show
        when={!loading()}
        fallback={<div class="card">{settings.t("connections.loading")}</div>}
      >
        <Show
          when={rows().length > 0}
          fallback={<EmptyState onAdd={() => setWizardConnId("new")} />}
        >
          <ConnectionsTable
            rows={rows()}
            onDelete={onDelete}
            onProbe={onProbe}
            onResume={(id) => setWizardConnId(id)}
          />
        </Show>
      </Show>

      <Show when={wizardConnId() !== null}>
        <Wizard
          conn={wizardConnId() === "new" ? null : rows().find((r) => r.id === wizardConnId()) ?? null}
          onClose={() => {
            setWizardConnId(null);
            void reload();
          }}
          onSavedResume={() => {
            setWizardConnId(null);
            showToast("info", settings.t("connections.toast.savedResume"));
            void reload();
          }}
          showToast={showToast}
        />
      </Show>

      <Show when={toast()}>
        <div
          role="status"
          aria-live="polite"
          class={`toast toast-${toast()!.kind}`}
          style={{
            position: "fixed",
            bottom: "24px",
            right: "24px",
            padding: "12px 18px",
            background: "var(--ink)",
            color: "var(--cream)",
            border: "2px solid var(--ink)",
            "box-shadow": "var(--shadow-offset-sm)",
            "font-family": "var(--font-cond)",
            "text-transform": "uppercase",
            "letter-spacing": "0.06em",
            "font-size": "13px",
            "z-index": 1000,
          }}
        >
          {toast()!.msg}
        </div>
      </Show>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Subcomponents
// ─────────────────────────────────────────────────────────────────────────────

function EmptyState(props: { onAdd: () => void }) {
  const settings = useSettings();
  return (
    <div
      class="card"
      style={{
        "text-align": "center",
        padding: "48px 24px",
        border: "2px solid var(--ink)",
        "box-shadow": "var(--shadow-offset)",
        background: "var(--cream-2)",
      }}
    >
      <Shield size={48} style={{ "margin-bottom": "12px", color: "var(--ink)" }} />
      <h2 style={{ "font-family": "var(--font-display)", "margin-bottom": "8px" }}>
        {settings.t("connections.empty.title")}
      </h2>
      <p style={{ color: "var(--ink-soft)", "margin-bottom": "20px", "max-width": "420px", margin: "0 auto 20px" }}>
        {settings.t("connections.empty.desc")}
      </p>
      <button type="button" class="btn-primary" onClick={props.onAdd}>
        <Plus size={16} /> {settings.t("connections.add")}
      </button>
    </div>
  );
}

function ConnectionsTable(props: {
  rows: Connection[];
  onDelete: (c: Connection) => void;
  onProbe: (c: Connection) => void;
  onResume: (id: number) => void;
}) {
  const settings = useSettings();
  return (
    <div class="card" style={{ border: "2px solid var(--ink)", overflow: "hidden" }}>
      <table style={{ width: "100%", "border-collapse": "collapse" }}>
        <thead>
          <tr style={{ background: "var(--ink)", color: "var(--cream)" }}>
            <Th>{settings.t("connections.col.domain")}</Th>
            <Th>{settings.t("connections.col.status")}</Th>
            <Th>{settings.t("connections.col.origin")}</Th>
            <Th style={{ "text-align": "right" }}>{settings.t("connections.col.actions")}</Th>
          </tr>
        </thead>
        <tbody>
          <For each={props.rows}>
            {(c) => (
              <tr style={{ "border-top": "1.5px solid var(--ink)" }}>
                <Td>
                  <div style={{ "font-family": "var(--font-mono)", "font-size": "14px" }}>{c.domain}</div>
                  <div style={{ "font-size": "12px", color: "var(--ink-soft)" }}>{c.name}</div>
                </Td>
                <Td>
                  <StatusBadge status={c.status} detail={c.status_detail} />
                </Td>
                <Td>
                  <code style={{ "font-size": "12px", color: "var(--ink-soft)" }}>
                    {c.origin_hosts.length ? c.origin_hosts.join(", ") : "—"}
                  </code>
                </Td>
                <Td style={{ "text-align": "right", "white-space": "nowrap" }}>
                  <Show when={c.status === "pending_dns"}>
                    <button
                      type="button"
                      class="btn-outline btn-sm"
                      onClick={() => props.onProbe(c)}
                      style={{ "margin-right": "8px" }}
                      title="Re-check DNS now"
                    >
                      <RefreshCw size={14} /> Re-check
                    </button>
                  </Show>
                  <Show when={c.status === "pending_verification" || c.status === "pending_dns"}>
                    <button
                      type="button"
                      class="btn-outline btn-sm"
                      onClick={() => props.onResume(c.id)}
                      style={{ "margin-right": "8px" }}
                    >
                      {settings.t("connections.action.resume")}
                    </button>
                  </Show>
                  <Show when={c.status === "error"}>
                    <button
                      type="button"
                      class="btn-outline btn-sm"
                      onClick={() => props.onProbe(c)}
                      style={{ "margin-right": "8px" }}
                    >
                      <RefreshCw size={14} /> {settings.t("connections.action.retry")}
                    </button>
                  </Show>
                  <button
                    type="button"
                    class="btn-icon"
                    aria-label={settings.t("connections.delete")}
                    onClick={() => props.onDelete(c)}
                  >
                    <Trash2 size={16} />
                  </button>
                </Td>
              </tr>
            )}
          </For>
        </tbody>
      </table>
    </div>
  );
}

function Th(props: { children: JSX.Element; style?: JSX.CSSProperties }) {
  return (
    <th
      style={{
        padding: "10px 14px",
        "text-align": "left",
        "font-family": "var(--font-cond)",
        "text-transform": "uppercase",
        "letter-spacing": "0.06em",
        "font-size": "12px",
        ...props.style,
      }}
    >
      {props.children}
    </th>
  );
}

function Td(props: { children: JSX.Element; style?: JSX.CSSProperties }) {
  return <td style={{ padding: "12px 14px", "vertical-align": "middle", ...props.style }}>{props.children}</td>;
}

function StatusBadge(props: { status: ConnectionStatus; detail: string | null }) {
  const settings = useSettings();
  // Active + self-signed cert is functionally protected (encryption + WAF
  // rules) but the cert isn't from a trusted CA. We surface this as an
  // amber-toned "Self-signed" badge rather than green so the operator
  // doesn't mistake it for a real LE cert. Detection is via status_detail
  // — set by acme.fallback_self_signed in the poller.
  const isSelfSigned = () =>
    props.status === "active" && (props.detail ?? "").toLowerCase().includes("self-signed");
  const tone = () => isSelfSigned()
    ? { bg: "rgba(178, 122, 0, 0.16)", fg: "var(--amber)", icon: "■" }
    : BADGE_TONE[props.status];
  const label = () => isSelfSigned()
    ? "Protected (self-signed)"
    : settings.t(`connections.status.${props.status}`);

  return (
    <span
      title={props.detail ?? ""}
      style={{
        display: "inline-flex",
        "align-items": "center",
        gap: "6px",
        padding: "3px 10px",
        background: tone().bg,
        color: tone().fg,
        border: `1.5px solid ${tone().fg}`,
        "font-family": "var(--font-cond)",
        "font-size": "11px",
        "text-transform": "uppercase",
        "letter-spacing": "0.04em",
      }}
    >
      <span style={{ "font-size": "13px", "line-height": 1 }}>{tone().icon}</span>
      {label()}
    </span>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Wizard
// ─────────────────────────────────────────────────────────────────────────────

type WizardStep = 1 | 2 | 3;

function Wizard(props: {
  conn: Connection | null;
  onClose: () => void;
  onSavedResume: () => void;
  showToast: (kind: Toast["kind"], msg: string) => void;
}) {
  const settings = useSettings();

  // Step is derived from the row's status when resuming; "new" rows start at 1.
  const initialStep = () => {
    const c = props.conn;
    if (!c) return 1;
    if (c.status === "pending_verification") return 2;
    return 3;
  };
  const [step, setStep] = createSignal<WizardStep>(initialStep());

  const [name, setName] = createSignal(props.conn?.name ?? "");
  const [domain, setDomain] = createSignal(props.conn?.domain ?? "");
  const [originPort, setOriginPort] = createSignal<number>(props.conn?.origin_port ?? 443);
  const [tlsMode, setTlsMode] = createSignal<OriginTlsMode>(props.conn?.origin_tls_mode ?? "strict");
  const [submitting, setSubmitting] = createSignal(false);
  const [createdConn, setCreatedConn] = createSignal<Connection | null>(props.conn);
  const [instructions, setInstructions] = createSignal<VerifyInstructions | null>(
    props.conn
      ? {
          txt_record_name: `_waf-verify.${props.conn.domain}`,
          txt_record_value: props.conn.verify_token,
          edge_ipv4: "", // backfilled below via api.getEdgeInfo
        }
      : null
  );

  // Backfill edge_ipv4 from the platform's /edge-info endpoint when we
  // entered the wizard on Resume (the create-response carries the IP, but
  // we don't keep that response across page reloads).
  onMount(() => {
    if (!props.conn) return;
    let cancelled = false;
    onCleanup(() => {
      cancelled = true;
    });
    api
      .getEdgeInfo()
      .then((info) => {
        if (cancelled) return;
        setInstructions((cur) =>
          cur ? { ...cur, edge_ipv4: info.edge_ipv4 } : cur
        );
      })
      .catch(() => {/* leaves edge_ipv4 empty; step 3 shows the operator-missing message */});
  });

  const [verifying, setVerifying] = createSignal(false);
  const [formError, setFormError] = createSignal<string | null>(null);

  // Close on Esc — saved (not discarded), per decision D3A.
  onMount(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        if (step() > 1 && createdConn()) props.onSavedResume();
        else props.onClose();
      }
    }
    window.addEventListener("keydown", onKey);
    onCleanup(() => window.removeEventListener("keydown", onKey));
  });

  // ── Step 1 → Step 2: create the row ──
  const submitStep1 = async () => {
    setFormError(null);
    const currName = name();
    const currDomain = domain();
    if (!currName.trim() || !currDomain.trim()) {
      setFormError("Name and domain are required.");
      return;
    }
    setSubmitting(true);
    try {
      const body: ConnectionCreate = {
        name: currName.trim(),
        domain: currDomain.trim(),
        origin_port: originPort(),
        origin_tls_mode: tlsMode(),
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
  };

  // ── Step 2 → Step 3: TXT verified ──
  const checkVerified = async (): Promise<boolean> => {
    const c = createdConn();
    if (!c) return false;
    setVerifying(true);
    try {
      const fresh = await api.probeConnection(c.id);
      setCreatedConn(fresh);
      // The poller advances pending_verification → pending_dns the moment TXT
      // is seen. So any status past pending_verification means we're verified.
      return fresh.status !== "pending_verification";
    } catch {
      return false;
    } finally {
      setVerifying(false);
    }
  };

  // Auto-poll TXT every 10s while step 2 is open (decision D2A).
  createEffect(() => {
    if (step() !== 2 || !createdConn()) return;
    let cancelled = false;
    const tick = async () => {
      if (cancelled) return;
      const ok = await checkVerified();
      if (ok && !cancelled) setStep(3);
    };
    void tick();
    const intervalId = setInterval(tick, TXT_POLL_MS);
    onCleanup(() => {
      cancelled = true;
      clearInterval(intervalId);
    });
  });

  // Step 3: same pattern for DNS-flip detection. Probe re-resolves the
  // domain and flips status to provisioning_cert when A == WAF edge.
  createEffect(() => {
    if (step() !== 3 || !createdConn()) return;
    let cancelled = false;
    const tick = async () => {
      if (cancelled) return;
      try {
        const fresh = await api.probeConnection(createdConn()!.id);
        if (cancelled) return;
        setCreatedConn(fresh);
        // Once we're past pending_dns, the WAF owns the flow — close the
        // wizard so the user sees the row transition through provisioning
        // → active on the list page.
        if (fresh.status !== "pending_dns" && fresh.status !== "pending_verification") {
          props.onSavedResume();
        }
      } catch {
        // ignore — next tick retries
      }
    };
    const intervalId = setInterval(tick, TXT_POLL_MS);
    onCleanup(() => {
      cancelled = true;
      clearInterval(intervalId);
    });
  });

  const onCopy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      props.showToast("info", settings.t("connections.toast.copyOk"));
    } catch {
      // clipboard may be denied in insecure contexts — silently fail
    }
  };

  const backdropClick = (e: MouseEvent) => {
    if (e.target === e.currentTarget) {
      if (step() > 1 && createdConn()) props.onSavedResume();
      else props.onClose();
    }
  };

  return (
    <div
      onClick={backdropClick}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(12, 12, 12, 0.55)",
        display: "flex",
        "align-items": "flex-start",
        "justify-content": "center",
        "padding-top": "64px",
        "z-index": 900,
      }}
      role="dialog"
      aria-modal="true"
      aria-labelledby="wizard-heading"
    >
      <div
        style={{
          width: "480px",
          "max-width": "95vw",
          background: "var(--cream)",
          border: "2px solid var(--ink)",
          "box-shadow": "var(--shadow-offset-lg)",
          padding: "24px",
          position: "relative",
        }}
      >
        <button
          type="button"
          class="btn-icon"
          onClick={() => {
            if (step() > 1 && createdConn()) props.onSavedResume();
            else props.onClose();
          }}
          aria-label="Close"
          style={{ position: "absolute", top: "8px", right: "8px" }}
        >
          <X size={18} />
        </button>

        <StepIndicator current={step()} />

        <h2
          id="wizard-heading"
          style={{
            "font-family": "var(--font-display)",
            "font-weight": 700,
            "font-size": "22px",
            "margin-bottom": "4px",
          }}
        >
          {settings.t("wizard.title")}
        </h2>
        <div
          style={{
            "font-family": "var(--font-cond)",
            "text-transform": "uppercase",
            "letter-spacing": "0.06em",
            "font-size": "11px",
            color: "var(--ink-soft)",
            "margin-bottom": "20px",
          }}
        >
          {settings.t("wizard.stepOf").replace("{n}", String(step()))}
        </div>

        <Show when={step() === 1}>
          <Step1
            name={name()}
            domain={domain()}
            originPort={originPort()}
            tlsMode={tlsMode()}
            submitting={submitting()}
            error={formError()}
            onName={setName}
            onDomain={setDomain}
            onOriginPort={setOriginPort}
            onTlsMode={setTlsMode}
            onCancel={props.onClose}
            onNext={submitStep1}
          />
        </Show>

        <Show when={step() === 2 && instructions()}>
          <Step2
            instructions={instructions()!}
            verifying={verifying()}
            statusDetail={createdConn()?.status_detail ?? null}
            onCopy={onCopy}
            onVerifyNow={async () => {
              const ok = await checkVerified();
              if (ok) setStep(3);
            }}
            onCancel={() => props.onSavedResume()}
          />
        </Show>

        <Show when={step() === 3 && createdConn() && instructions()}>
          <Step3
            domain={createdConn()!.domain}
            originHosts={createdConn()!.origin_hosts}
            edgeIpv4={instructions()!.edge_ipv4}
            onCopy={onCopy}
            onDone={props.onClose}
          />
        </Show>
      </div>
    </div>
  );
}

function StepIndicator(props: { current: WizardStep }) {
  return (
    <div style={{ display: "flex", gap: "8px", "margin-bottom": "18px" }}>
      <For each={[1, 2, 3] as const}>
        {(n) => (
          <span
            aria-current={n === props.current ? "step" : undefined}
            style={{
              width: "14px",
              height: "14px",
              border: "2px solid var(--ink)",
              background: n === props.current ? "var(--ink)" : "transparent",
              transition: "background var(--duration-fast) var(--ease-out)",
            }}
          />
        )}
      </For>
    </div>
  );
}

function Step1(props: {
  name: string;
  domain: string;
  originPort: number;
  tlsMode: OriginTlsMode;
  submitting: boolean;
  error: string | null;
  onName: (s: string) => void;
  onDomain: (s: string) => void;
  onOriginPort: (n: number) => void;
  onTlsMode: (m: OriginTlsMode) => void;
  onCancel: () => void;
  onNext: () => void;
}) {
  const settings = useSettings();
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (!props.submitting) props.onNext();
      }}
    >
      <Label>{settings.t("wizard.step1.name")}</Label>
      <input
        type="text"
        value={props.name}
        onInput={(e) => props.onName(e.currentTarget.value)}
        placeholder={settings.t("wizard.step1.namePlaceholder")}
        autofocus
        style={fieldStyle}
      />

      <Label>{settings.t("wizard.step1.domain")}</Label>
      <input
        type="text"
        value={props.domain}
        onInput={(e) => props.onDomain(e.currentTarget.value)}
        placeholder={settings.t("wizard.step1.domainPlaceholder")}
        autocapitalize="none"
        autocorrect="off"
        spellcheck={false}
        style={{ ...fieldStyle, "font-family": "var(--font-mono)" }}
      />

      <Label>Origin port</Label>
      <input
        type="number"
        min={1}
        max={65535}
        value={props.originPort}
        onInput={(e) => props.onOriginPort(Number(e.currentTarget.value) || 443)}
        style={{ ...fieldStyle, "font-family": "var(--font-mono)", width: "140px" }}
      />
      <div style={{ "font-size": "12px", color: "var(--ink-soft)", "margin-top": "4px", "margin-bottom": "8px" }}>
        Default 443. Override when the origin serves HTTPS on a different port.
      </div>

      <Label>{settings.t("wizard.step1.tls")}</Label>
      <div style={{ display: "flex", gap: "16px", "margin-bottom": "6px" }}>
        <For each={["strict", "lenient"] as const}>
          {(m) => (
            <label
              style={{
                display: "inline-flex",
                "align-items": "center",
                gap: "6px",
                "font-size": "13px",
                cursor: "pointer",
              }}
            >
              <span
                style={{
                  width: "14px",
                  height: "14px",
                  border: "2px solid var(--ink)",
                  background: props.tlsMode === m ? "var(--ink)" : "transparent",
                }}
              />
              <input
                type="radio"
                checked={props.tlsMode === m}
                onChange={() => props.onTlsMode(m)}
                style={{ position: "absolute", opacity: 0, "pointer-events": "none" }}
              />
              {settings.t(`wizard.step1.tls.${m}`)}
            </label>
          )}
        </For>
      </div>
      <div style={{ "font-size": "12px", color: "var(--ink-soft)", "margin-bottom": "16px" }}>
        {settings.t("wizard.step1.tls.hint")}
      </div>

      <Show when={props.error}>
        <div
          role="alert"
          style={{
            background: "var(--red-soft)",
            border: "2px solid var(--red-deep)",
            padding: "10px",
            "margin-bottom": "16px",
            color: "var(--red-deep)",
            "font-size": "13px",
          }}
        >
          {props.error}
        </div>
      </Show>

      <div style={{ display: "flex", "justify-content": "flex-end", gap: "12px" }}>
        <button type="button" class="btn-outline" onClick={props.onCancel}>
          {settings.t("wizard.cancel")}
        </button>
        <button type="submit" class="btn-primary" disabled={props.submitting} aria-busy={props.submitting}>
          {props.submitting ? "…" : settings.t("wizard.next")}
        </button>
      </div>
    </form>
  );
}

function Step2(props: {
  instructions: VerifyInstructions;
  verifying: boolean;
  statusDetail: string | null;
  onCopy: (value: string) => void;
  onVerifyNow: () => void;
  onCancel: () => void;
}) {
  const settings = useSettings();
  // Distinguish a "fresh first probe" from a "we checked and didn't find it
  // yet" state — the latter deserves a more pointed message than the
  // generic auto-poll hint.
  const txtNotFound = () =>
    !props.verifying &&
    !!props.statusDetail &&
    (props.statusDetail.toLowerCase().includes("not found") || props.statusDetail.toLowerCase().includes("propagation"));

  return (
    <>
      <h3 style={{ "font-size": "16px", "margin-bottom": "6px" }}>{settings.t("wizard.step2.title")}</h3>
      <p style={{ "font-size": "13px", "margin-bottom": "16px" }}>{settings.t("wizard.step2.body")}</p>

      <KeyValueBlock label="Name" value={props.instructions.txt_record_name} onCopy={props.onCopy} />
      <KeyValueBlock label="TXT value" value={props.instructions.txt_record_value} onCopy={props.onCopy} />

      <div
        role="status"
        aria-live="polite"
        style={{
          "font-size": "12px",
          color: txtNotFound() ? "var(--red-deep)" : "var(--ink-soft)",
          margin: "10px 0 18px",
          "min-height": "18px",
          display: "flex",
          "align-items": "center",
          gap: "6px",
        }}
      >
        <Show when={props.verifying}>
          <span
            aria-hidden
            style={{
              display: "inline-block",
              animation: "spin 0.9s linear infinite",
              "font-size": "14px",
              "line-height": 1,
            }}
          >
            ◐
          </span>
        </Show>
        {props.verifying
          ? "Checking DNS for the TXT record…"
          : txtNotFound()
          ? props.statusDetail
          : settings.t("wizard.step2.polling")}
      </div>

      {/* Local keyframes (Constructivist system has no spinner utility yet). */}
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>

      <div style={{ display: "flex", "justify-content": "flex-end", gap: "12px" }}>
        <button type="button" class="btn-outline" onClick={props.onCancel}>
          {settings.t("wizard.cancel")}
        </button>
        <button
          type="button"
          class="btn-primary"
          onClick={props.onVerifyNow}
          disabled={props.verifying}
          aria-busy={props.verifying}
          style={{ "min-width": "150px" }}
        >
          <Show
            when={!props.verifying}
            fallback={
              <span style={{ display: "inline-flex", "align-items": "center", gap: "6px" }}>
                <span
                  aria-hidden
                  style={{ animation: "spin 0.9s linear infinite", display: "inline-block" }}
                >
                  ◐
                </span>
                {"Checking…"}
              </span>
            }
          >
            <span style={{ display: "inline-flex", "align-items": "center", gap: "6px" }}>
              <Check size={14} /> {settings.t("wizard.step2.verifyNow")}
            </span>
          </Show>
        </button>
      </div>
    </>
  );
}

function Step3(props: {
  domain: string;
  originHosts: string[];
  edgeIpv4: string;
  onCopy: (value: string) => void;
  onDone: () => void;
}) {
  const settings = useSettings();
  return (
    <>
      <h3 style={{ "font-size": "16px", "margin-bottom": "6px" }}>{settings.t("wizard.step3.title")}</h3>
      <p style={{ "font-size": "13px", "margin-bottom": "12px" }}>
        {settings.t("wizard.step3.bodyVerified").replace("{origin}", props.originHosts.join(", ") || "—")}
      </p>
      <p style={{ "font-size": "13px", "margin-bottom": "12px" }}>
        {settings.t("wizard.step3.bodyPoint").replace("{domain}", props.domain)}
      </p>

      <Show
        when={props.edgeIpv4}
        fallback={
          <div
            role="alert"
            style={{
              background: "var(--red-soft)",
              border: "2px solid var(--red-deep)",
              padding: "10px",
              "margin-bottom": "16px",
              color: "var(--red-deep)",
              "font-size": "13px",
            }}
          >
            {settings.t("wizard.step3.edgeMissing")}
          </div>
        }
      >
        <KeyValueBlock label="A record" value={props.edgeIpv4} onCopy={props.onCopy} />
      </Show>

      <div style={{ display: "flex", "justify-content": "flex-end", "margin-top": "20px" }}>
        <button type="button" class="btn-primary" onClick={props.onDone}>
          {settings.t("wizard.step3.done")}
        </button>
      </div>
    </>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Reused atoms
// ─────────────────────────────────────────────────────────────────────────────

function Label(props: { children: JSX.Element }) {
  return (
    <label
      style={{
        display: "block",
        "font-family": "var(--font-cond)",
        "text-transform": "uppercase",
        "letter-spacing": "0.06em",
        "font-size": "11px",
        color: "var(--ink-soft)",
        "margin-top": "12px",
        "margin-bottom": "6px",
      }}
    >
      {props.children}
    </label>
  );
}

const fieldStyle = {
  width: "100%",
  height: "44px",
  padding: "0 10px",
  background: "var(--input-bg)",
  border: "2px solid var(--ink)",
  color: "var(--ink)",
  "font-size": "14px",
};

function KeyValueBlock(props: {
  label: string;
  value: string;
  onCopy: (value: string) => void;
}) {
  // Click-to-copy block; spec §7.4 (mobile tap-to-copy).
  return (
    <div style={{ "margin-bottom": "10px" }}>
      <div
        style={{
          "font-family": "var(--font-cond)",
          "text-transform": "uppercase",
          "letter-spacing": "0.06em",
          "font-size": "10px",
          color: "var(--ink-soft)",
          "margin-bottom": "4px",
        }}
      >
        {props.label}
      </div>
      <button
        type="button"
        onClick={() => props.onCopy(props.value)}
        title="Click to copy"
        style={{
          width: "100%",
          display: "flex",
          "align-items": "center",
          "justify-content": "space-between",
          padding: "10px 12px",
          background: "var(--cream-3)",
          border: "2px solid var(--ink)",
          "font-family": "var(--font-mono)",
          "font-size": "13px",
          color: "var(--ink)",
          "text-align": "left",
          cursor: "pointer",
        }}
      >
        <span style={{ overflow: "auto", "word-break": "break-all" }}>{props.value}</span>
        <Copy size={14} style={{ "flex-shrink": 0, "margin-left": "8px" }} />
      </button>
    </div>
  );
}
