import { createSignal, type JSX } from "solid-js";
import { Show } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { Eye, EyeOff, Lock } from "lucide-solid";
import { useAuth } from "../context/AuthContext";
import { useSettings } from "../context/SettingsContext";

export default function ChangePassword() {
  const navigate = useNavigate();
  const auth = useAuth();
  const settings = useSettings();

  const [current, setCurrent] = createSignal("");
  const [next, setNext] = createSignal("");
  const [confirm, setConfirm] = createSignal("");
  const [showCurrent, setShowCurrent] = createSignal(false);
  const [showNext, setShowNext] = createSignal(false);
  const [showConfirm, setShowConfirm] = createSignal(false);
  const [submitting, setSubmitting] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  // must_change_password removed in SaaS schema; forced-change flow handled by backend redirect
  const forced = false;

  const submit = async (e: Event) => {

    e.preventDefault();
    setError(null);
    if (next().length < 8) {
      setError(() => settings.t("auth.changePassword.tooShort"));
      return;
    }
    if (next() !== confirm()) {
      setError(() => settings.t("auth.changePassword.mismatch"));
      return;
    }
    setSubmitting(true);
    try {
      // On first login the current password is always the default "admin"
      await auth.changePassword(forced ? "admin" : current(), next());
      navigate("/dashboard", { replace: true });
    } catch (err) {
      setError(() => err instanceof Error ? err.message : settings.t("general.error"));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      style={{
        "min-height": "100vh",
        "width": "100%",
        "display": "flex",
        "align-items": "center",
        "justify-content": "center",
        "background": "var(--bg-base)",
        "padding": "20px",
      }}
    >
      <form
        onSubmit={submit}
        style={{
          "width": "100%",
          "max-width": "420px",
          "background": "var(--bg-elevated)",
          "border": "1px solid var(--border-subtle)",
          "border-radius": "14px",
          "padding": "28px",
        }}
      >
        <h1 style={{ "font-size": "22px", "margin": 0, "color": "var(--text-primary)" }}>
          {settings.t("auth.changePassword.title")}
        </h1>
        <p
          style={{
            "font-size": "13px",
            "color": "var(--text-muted)",
            "margin-top": "6px",
            "margin-bottom": "22px",
          }}
        >
          <Show when={forced} fallback={settings.t("auth.changePassword.subtitle")}>
            {settings.t("auth.changePassword.forced")}
          </Show>
        </p>

        <Show when={!forced}>
          <Field label={settings.t("auth.changePassword.current")} value={current()} onChange={setCurrent} show={showCurrent()} onToggleShow={() => setShowCurrent((v) => !v)} />
        </Show>
        <Field label={settings.t("auth.changePassword.new")} value={next()} onChange={setNext} show={showNext()} onToggleShow={() => setShowNext((v) => !v)} />
        <Field label={settings.t("auth.changePassword.confirm")} value={confirm()} onChange={setConfirm} show={showConfirm()} onToggleShow={() => setShowConfirm((v) => !v)} />

        <Show when={error()}>
          <div
            style={{
              "padding": "10px 12px",
              "background": "rgba(239,68,68,0.08)",
              "border": "1px solid rgba(239,68,68,0.25)",
              "border-radius": "8px",
              "color": "#ef4444",
              "font-size": "13px",
              "margin-bottom": "14px",
            }}
          >
            {error()}
          </div>
        </Show>

        <div style={{ "display": "flex", "gap": "10px" }}>
          <button
            type="submit"
            disabled={submitting() || (!forced && !current()) || !next() || !confirm()}
            style={{
              "flex": "1",
              "padding": "11px 14px",
              "border-radius": "8px",
              "border": "1px solid var(--accent-primary)",
              "background": "var(--accent-primary)",
              "color": "#fff",
              "font-size": "14px",
              "font-weight": "600",
              "cursor": submitting() ? "not-allowed" : "pointer",
              "opacity": submitting() ? "0.6" : "1",
            }}
          >
            {submitting() ? settings.t("general.saving") : settings.t("general.save")}
          </button>
        </div>
      </form>
    </div>
  );
}

function Field(props: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  show: boolean;
  onToggleShow: () => void;
}) {
  const settings = useSettings();
  return (
    <div style={{ "margin-bottom": "14px" }}>
      <label
        style={{
          "display": "block",
          "font-size": "12px",
          "color": "var(--text-muted)",
          "margin-bottom": "6px",
          "text-transform": "uppercase",
          "letter-spacing": "0.4px",
        }}
      >
        {props.label}
      </label>
      <div style={{ "position": "relative" }}>
        <Lock
          size={15}
          style={{
            "position": "absolute",
            "left": "12px",
            "top": "50%",
            "transform": "translateY(-50%)",
            "color": "var(--text-muted)",
          }}
        />
        <input
          type={props.show ? "text" : "password"}
          value={props.value}
          onInput={(e) => props.onChange(e.currentTarget.value)}
          required
          style={{ ...inputStyle, "padding-right": "40px" }}
        />
        <button
          type="button"
          onClick={props.onToggleShow}
          tabIndex={-1}
          aria-label={props.show ? settings.t("auth.hidePassword") : settings.t("auth.showPassword")}
          style={{
            "position": "absolute",
            "right": "8px",
            "top": "50%",
            "transform": "translateY(-50%)",
            "background": "none",
            "border": "none",
            "color": "var(--text-muted)",
            "cursor": "pointer",
            "padding": "4px",
            "display": "flex",
            "align-items": "center",
          }}
        >
          <Show when={props.show} fallback={<Eye size={16} />}>
            <EyeOff size={16} />
          </Show>
        </button>
      </div>
    </div>
  );
}

const inputStyle: JSX.CSSProperties = {
  "width": "100%",
  "padding": "10px 12px 10px 36px",
  "border-radius": "8px",
  "border": "1px solid var(--border-subtle)",
  "background": "var(--bg-base)",
  "color": "var(--text-primary)",
  "font-size": "14px",
  "outline": "none",
};
