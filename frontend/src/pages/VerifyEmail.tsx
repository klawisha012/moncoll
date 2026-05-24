import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useSettings } from "../context/SettingsContext";
import { api } from "../api/client";

export default function VerifyEmail() {
  const { t } = useSettings();
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";

  const [status, setStatus] = useState<"loading" | "success" | "error">("loading");
  const [message, setMessage] = useState("");

  useEffect(() => {
    if (!token) {
      setStatus("error");
      setMessage("Missing token");
      return;
    }
    api.auth.verifyEmail(token)
      .then(() => setStatus("success"))
      .catch((err: Error) => {
        setStatus("error");
        setMessage(err.message);
      });
  }, [token]);

  const isSuccess = status === "success";
  const title = status === "loading"
    ? t("auth.verifyEmail.verifying")
    : isSuccess
      ? t("auth.verifyEmail.success")
      : t("auth.verifyEmail.error");

  return (
    <div className="cv-root">
      <style>{styles}</style>
      <section className="cv-manifest">
        <div className="cv-eyebrow">
          <span className="cv-n">{isSuccess ? "✓" : status === "loading" ? "…" : "✕"}</span>
          <span className="cv-eyebrow-text">— Email</span>
        </div>
        <h1 className="cv-h1 cv-h1-sm">
          <span className="cv-stack">{title}</span>
        </h1>
        {isSuccess && <p className="cv-deck">{t("auth.verifyEmail.successDesc")}</p>}
        {status === "error" && <p className="cv-deck" style={{ borderLeftColor: "var(--red)" }}>{message}</p>}
        <div className="cv-disc" aria-hidden />
      </section>

      <section className="cv-form-side">
        <div className="cv-form">
          <div className="cv-form-head">
            <span className="cv-kicker">№ 07 / email verification</span>
          </div>
          {status === "loading" && (
            <p className="cv-body">{t("auth.verifyEmail.verifying")}</p>
          )}
          {isSuccess && (
            <>
              <p className="cv-body">{t("auth.verifyEmail.successDesc")}</p>
              <Link to="/login" className="cv-submit" style={{ textDecoration: "none", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span>{t("auth.verifyEmail.toLogin")}</span>
                <span className="cv-ar">→</span>
              </Link>
            </>
          )}
          {status === "error" && (
            <>
              <p className="cv-body cv-body-err">{message || t("auth.verifyEmail.error")}</p>
              <Link to="/login" className="cv-submit cv-submit-alt" style={{ textDecoration: "none", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span>{t("auth.verifyEmail.toLogin")}</span>
                <span className="cv-ar">→</span>
              </Link>
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
  display: grid; grid-template-columns: 1.25fr 1fr;
  overflow: auto;
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
.cv-h1-sm { font-size: clamp(36px, 5vw, 72px); }
.cv-stack { display: block; }
.cv-deck {
  font-family: 'Inter Tight', sans-serif; font-weight: 500;
  font-size: 17px; line-height: 1.5; max-width: 36ch;
  border-left: 4px solid var(--red); padding-left: 16px;
  margin: 0; position: relative; z-index: 1; color: var(--ink);
}
.cv-form-side { background: var(--cream); padding: 72px 64px; display: flex; flex-direction: column; justify-content: center; }
.cv-form { display: flex; flex-direction: column; gap: 22px; max-width: 460px; }
.cv-form-head {
  display: flex; align-items: baseline; justify-content: space-between;
  gap: 16px; border-bottom: 3px solid var(--rule); padding-bottom: 14px; margin-bottom: 6px;
}
.cv-kicker {
  font-family: 'Oswald', sans-serif; font-weight: 700;
  font-size: 12px; letter-spacing: 0.28em; text-transform: uppercase; color: var(--red);
}
.cv-body { font-family: 'Inter Tight', sans-serif; font-size: 15px; color: var(--ink); line-height: 1.6; margin: 0; }
.cv-body-err { color: var(--red); }
.cv-submit {
  background: var(--red); color: var(--cream); border: 3px solid var(--rule);
  padding: 18px 24px; cursor: pointer;
  font-family: 'Unbounded', sans-serif; font-weight: 900;
  font-size: 22px; letter-spacing: 0.02em; text-transform: uppercase;
  display: flex; justify-content: space-between; align-items: center;
  box-shadow: 6px 6px 0 var(--rule); transition: transform 90ms, box-shadow 90ms; margin-top: 8px;
}
.cv-submit:hover { transform: translate(-3px, -3px); box-shadow: 9px 9px 0 var(--rule); }
.cv-submit-alt { background: var(--ink); }
.cv-ar { font-family: 'JetBrains Mono', monospace; font-size: 22px; }
@media (max-width: 960px) {
  .cv-root { grid-template-columns: 1fr; height: auto; min-height: 100vh; }
  .cv-manifest { border-right: 0; border-bottom: 3px solid var(--rule); padding: 48px 32px; }
  .cv-form-side { padding: 48px 32px; }
  .cv-h1 { font-size: clamp(32px, 12vw, 64px); }
}
`;
