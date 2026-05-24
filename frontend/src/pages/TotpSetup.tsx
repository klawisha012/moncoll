import { useEffect, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useSettings } from "../context/SettingsContext";
import { useAuth } from "../context/AuthContext";
import { api } from "../api/client";

export default function TotpSetup() {
  const { t } = useSettings();
  const { user, refresh } = useAuth();
  const navigate = useNavigate();

  const [qrDataUri, setQrDataUri] = useState("");
  const [secret, setSecret] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [code, setCode] = useState("");
  const [loadError, setLoadError] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [confirmed, setConfirmed] = useState(false);

  useEffect(() => {
    api.auth.totpSetup()
      .then((data) => {
        setQrDataUri(data.qr_code_data_uri);
        setSecret(data.secret_base32);
        // Recovery codes are issued ONCE at setup; we surface them after
        // the user successfully confirms a code.
        setRecoveryCodes(data.recovery_codes ?? []);
      })
      .catch((err: Error) => setLoadError(err.message));
  }, []);

  const confirm = async (e: FormEvent) => {
    e.preventDefault();
    setSubmitError(null);
    setSubmitting(true);
    try {
      await api.auth.totpConfirm(code);
      setConfirmed(true);
      await refresh();
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : t("general.error"));
    } finally {
      setSubmitting(false);
    }
  };

  const proceed = () => {
    const role = user?.platform_role;
    navigate(role === "admin" ? "/monitoring" : "/home", { replace: true });
  };

  const downloadCodes = () => {
    const lines = [
      "WAF — recovery codes",
      `Account: ${user?.email ?? ""}`,
      `Issued:  ${new Date().toISOString()}`,
      "",
      "Each code can be used ONCE. Store this file somewhere safe.",
      "",
      ...recoveryCodes,
      "",
    ];
    const blob = new Blob([lines.join("\n")], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `waf-recovery-codes-${new Date().toISOString().slice(0, 10)}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="cv-root">
      <style>{styles}</style>

      <section className="cv-manifest">
        <div className="cv-eyebrow">
          <span className="cv-n">06</span>
          <span className="cv-eyebrow-text">{t("auth.totp.eyebrow")}</span>
        </div>
        <h1 className="cv-h1">
          <span className="cv-stack">{t("auth.totp.heroLine1")}</span>
          <span className="cv-stack"><span className="cv-ws">{t("auth.totp.heroLine2")}</span></span>
          <span className="cv-stack"><span className="cv-tilt">{t("auth.totp.heroLine3")}</span></span>
        </h1>
        <p className="cv-deck">{t("auth.totp.quote")}</p>
        <div className="cv-disc" aria-hidden />
      </section>

      <section className="cv-form-side">
        <div className="cv-form">
          <div className="cv-form-head">
            <span className="cv-kicker">{t("auth.totp.kicker")}</span>
          </div>

          {loadError && <div className="cv-error">{loadError}</div>}

          {!loadError && !confirmed && (
            <>
              {qrDataUri && (
                <div className="cv-qr-block">
                  <p className="cv-label">{t("auth.totp.scanQr")}</p>
                  <img src={qrDataUri} alt="TOTP QR code" className="cv-qr-img" />
                  <p className="cv-label" style={{ marginTop: 12 }}>{t("auth.totp.orEnterSecret")}</p>
                  <code className="cv-secret">{secret}</code>
                </div>
              )}

              <form onSubmit={confirm} className="cv-inner-form">
                <div className="cv-field">
                  <label htmlFor="cv-totp-code">{t("auth.totp.enterCode")}</label>
                  <div className="cv-inp">
                    <span className="cv-tag">⊕</span>
                    <input
                      id="cv-totp-code"
                      type="text" inputMode="numeric" pattern="\d{6}" maxLength={6}
                      value={code}
                      onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                      autoComplete="one-time-code" placeholder="000000"
                      autoFocus
                    />
                  </div>
                </div>

                {submitError && <div className="cv-error">{submitError}</div>}

                <button type="submit" className="cv-submit" disabled={submitting || code.length !== 6}>
                  <span>{submitting ? t("auth.totp.confirming") : t("auth.totp.confirm")}</span>
                  <span className="cv-ar">→</span>
                </button>
              </form>
            </>
          )}

          {confirmed && (
            <>
              <div className="cv-success-box">
                <p className="cv-label" style={{ marginBottom: 8 }}>{t("auth.totp.recoveryCodes")}</p>
                <p className="cv-hint">{t("auth.totp.recoveryCodesDesc")}</p>
                <div className="cv-recovery-grid">
                  {recoveryCodes.map((rc) => (
                    <code key={rc} className="cv-rc">{rc}</code>
                  ))}
                </div>
                <button
                  type="button"
                  className="cv-download"
                  onClick={downloadCodes}
                  disabled={recoveryCodes.length === 0}
                >
                  ↓ {t("auth.totp.downloadCodes")}
                </button>
              </div>

              <button type="button" className="cv-submit" onClick={proceed}>
                <span>{t("general.continue")}</span>
                <span className="cv-ar">→</span>
              </button>
            </>
          )}
        </div>
      </section>
    </div>
  );
}

const styles = `
.cv-root {
  --rule: var(--ink);
  height: 100vh; width: 100%;
  background: var(--cream); color: var(--ink);
  font-family: 'Inter Tight', system-ui, -apple-system, sans-serif;
  font-size: 15px; line-height: 1.45;
  display: grid; grid-template-columns: 1.25fr 1fr; overflow: auto;
  background-image: radial-gradient(rgba(0,0,0,0.05) 1px, transparent 1px);
  background-size: 4px 4px;
}
[data-theme="dark"] .cv-root { background-image: radial-gradient(rgba(241, 234, 216, 0.04) 1px, transparent 1px); }
.cv-manifest {
  padding: 72px 64px; border-right: 3px solid var(--rule);
  position: relative; overflow: hidden;
  display: flex; flex-direction: column; justify-content: center;
}
.cv-disc {
  position: absolute; right: -110px; bottom: -110px;
  width: 340px; height: 340px;
  background: var(--red); border: 3px solid var(--rule); border-radius: 50%; pointer-events: none;
}
.cv-eyebrow { display: flex; align-items: center; gap: 16px; margin-bottom: 22px; position: relative; z-index: 1; }
.cv-n {
  font-family: 'Unbounded', sans-serif; font-weight: 900; font-size: 22px; line-height: 1;
  background: var(--red); color: var(--cream); padding: 4px 10px 6px;
  transform: rotate(-2deg); display: inline-block;
}
.cv-eyebrow-text {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 13px; letter-spacing: 0.28em; text-transform: uppercase; color: var(--ink);
}
.cv-h1 {
  font-family: 'Unbounded', sans-serif; font-weight: 900;
  font-size: clamp(64px, 8vw, 124px); line-height: 0.86;
  letter-spacing: -0.05em; text-transform: uppercase;
  margin: 0 0 32px; position: relative; z-index: 1; color: var(--ink);
}
.cv-stack { display: block; }
.cv-ws { color: var(--red); }
.cv-tilt { display: inline-block; transform: rotate(-3deg); }
.cv-deck {
  font-family: 'Inter Tight', sans-serif; font-weight: 500;
  font-size: 17px; line-height: 1.5; max-width: 36ch;
  border-left: 4px solid var(--red); padding-left: 16px;
  margin: 0; position: relative; z-index: 1; color: var(--ink);
}
.cv-form-side { background: var(--cream); padding: 48px 64px; display: flex; flex-direction: column; justify-content: center; overflow-y: auto; }
.cv-form { display: flex; flex-direction: column; gap: 22px; max-width: 460px; }
.cv-inner-form { display: flex; flex-direction: column; gap: 22px; }
.cv-form-head {
  display: flex; align-items: baseline; justify-content: space-between;
  gap: 16px; border-bottom: 3px solid var(--rule); padding-bottom: 14px; margin-bottom: 6px;
}
.cv-kicker {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 12px; letter-spacing: 0.28em; text-transform: uppercase; color: var(--red);
}
.cv-label {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 11px; letter-spacing: 0.24em; text-transform: uppercase; color: var(--ink); margin: 0;
}
.cv-hint { font-family: 'Inter Tight', sans-serif; font-size: 13px; color: var(--ink-soft, #666); margin: 4px 0 0; }
.cv-qr-block { display: flex; flex-direction: column; gap: 8px; }
.cv-qr-img { width: 200px; height: 200px; border: 3px solid var(--rule); }
.cv-secret {
  font-family: 'JetBrains Mono', monospace; font-size: 13px; letter-spacing: 0.08em;
  background: var(--ink); color: var(--cream); padding: 10px 14px; word-break: break-all;
}
.cv-field { display: flex; flex-direction: column; }
.cv-field label {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 11px; letter-spacing: 0.24em; text-transform: uppercase; margin-bottom: 8px; color: var(--ink);
}
.cv-inp { border: 3px solid var(--rule); background: var(--cream); display: flex; align-items: stretch; }
.cv-inp:focus-within { outline: 3px solid var(--red); outline-offset: 3px; }
.cv-tag {
  background: var(--ink); color: var(--cream); padding: 0 14px;
  display: flex; align-items: center;
  font-family: 'JetBrains Mono', monospace; font-weight: 700; font-size: 16px;
}
.cv-inp input {
  flex: 1; border: 0; background: transparent; outline: 0; padding: 14px 16px;
  font-family: 'Inter Tight', sans-serif; font-weight: 500; font-size: 16px; color: var(--ink); min-width: 0;
}
.cv-success-box {
  border: 3px solid var(--rule); padding: 16px;
  display: flex; flex-direction: column; gap: 8px;
}
.cv-recovery-grid {
  display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 8px;
}
.cv-rc {
  font-family: 'JetBrains Mono', monospace; font-size: 12px;
  background: var(--ink); color: var(--cream); padding: 6px 10px; text-align: center;
}
.cv-download {
  margin-top: 12px;
  background: var(--cream); color: var(--ink);
  border: 2px solid var(--rule); padding: 10px 14px; cursor: pointer;
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 12px; letter-spacing: 0.18em; text-transform: uppercase;
  display: inline-flex; align-items: center; gap: 8px;
  align-self: flex-start;
  transition: transform 90ms, box-shadow 90ms;
}
.cv-download:hover:not(:disabled) { background: var(--ink); color: var(--cream); }
.cv-download:disabled { opacity: 0.4; cursor: not-allowed; }
.cv-error {
  border: 3px solid var(--red); background: rgba(214, 54, 42, 0.08); padding: 12px 16px;
  font-family: 'JetBrains Mono', monospace; font-size: 13px; color: var(--red);
}
.cv-submit {
  background: var(--red); color: var(--cream); border: 3px solid var(--rule);
  padding: 18px 24px; cursor: pointer;
  font-family: 'Unbounded', sans-serif; font-weight: 900;
  font-size: 22px; letter-spacing: 0.02em; text-transform: uppercase;
  display: flex; justify-content: space-between; align-items: center;
  box-shadow: 6px 6px 0 var(--rule); transition: transform 90ms, box-shadow 90ms; margin-top: 8px;
}
.cv-submit:hover:not(:disabled) { transform: translate(-3px, -3px); box-shadow: 9px 9px 0 var(--rule); }
.cv-submit:disabled { opacity: 0.45; cursor: not-allowed; box-shadow: 3px 3px 0 var(--rule); transform: none; }
.cv-ar { font-family: 'JetBrains Mono', monospace; font-size: 22px; }
@media (max-width: 960px) {
  .cv-root { grid-template-columns: 1fr; height: auto; min-height: 100vh; }
  .cv-manifest { border-right: 0; border-bottom: 3px solid var(--rule); padding: 48px 32px; }
  .cv-form-side { padding: 48px 32px; }
  .cv-h1 { font-size: clamp(48px, 14vw, 84px); }
}
`;
