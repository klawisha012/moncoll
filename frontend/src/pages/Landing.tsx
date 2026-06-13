import { createSignal, onMount, For, Show } from "solid-js";
import { A } from "@solidjs/router";
import { Globe, ShieldCheck, Ban, Activity, ArrowRight, Sun, Moon } from "lucide-solid";
import type { Component } from "solid-js";
import Logo from "../components/Logo";
import { useAuth } from "../context/AuthContext";
import { useSettings } from "../context/SettingsContext";

export default function Landing() {
  const auth = useAuth();
  const settings = useSettings();

  // Respect reduced-motion: don't autoplay the promo; show the static panel.
  const [playVideo, setPlayVideo] = createSignal(true);
  const [videoOk, setVideoOk] = createSignal(true);
  onMount(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    setPlayVideo(!mq.matches);
  });

  // Header CTA: guests sign in; authenticated users jump into the app.
  const ctaHref = () =>
    auth.user ? (auth.user.platform_role === "admin" ? "/monitoring" : "/home") : "/login";
  const ctaLabel = () =>
    auth.user ? settings.t("landing.nav.toApp") : settings.t("landing.nav.login");

  const features = (): { icon: Component<{ size?: number }>; title: string; desc: string }[] => [
    { icon: Globe, title: settings.t("landing.features.geoip.title"), desc: settings.t("landing.features.geoip.desc") },
    { icon: ShieldCheck, title: settings.t("landing.features.modsec.title"), desc: settings.t("landing.features.modsec.desc") },
    { icon: Ban, title: settings.t("landing.features.crowdsec.title"), desc: settings.t("landing.features.crowdsec.desc") },
    { icon: Activity, title: settings.t("landing.features.realtime.title"), desc: settings.t("landing.features.realtime.desc") },
  ];

  return (
    <div class="lp-root">
      <style>{styles}</style>

      <header class="lp-header">
        <a class="lp-brand" href="/">
          <Logo size={38} title={settings.t("brand.logoAlt")} />
          <span class="lp-brand-name">{settings.t("brand.name")}</span>
        </a>
        <nav class="lp-nav">
          <button
            type="button"
            class="lp-icon-btn"
            onClick={() => settings.toggleTheme()}
            aria-label={settings.t("landing.theme.toggle")}
          >
            <Show when={settings.theme === "dark"} fallback={<Moon size={18} />}>
              <Sun size={18} />
            </Show>
          </button>
          <A href="/signup" class="lp-link">{settings.t("landing.nav.signup")}</A>
          <A href={ctaHref()} class="lp-login-btn">
            <span>{ctaLabel()}</span>
            <ArrowRight size={18} />
          </A>
        </nav>
      </header>

      <section class="lp-hero">
        <div class="lp-hero-copy">
          <div class="lp-eyebrow">
            <span class="lp-eyebrow-n">01</span>
            <span class="lp-eyebrow-text">{settings.t("landing.hero.eyebrow")}</span>
          </div>
          <h1 class="lp-h1">
            <span class="lp-stack">{settings.t("landing.hero.title1")}</span>
            <span class="lp-stack lp-h1-red">{settings.t("landing.hero.title2")}</span>
            <span class="lp-stack lp-tilt">{settings.t("landing.hero.title3")}</span>
          </h1>
          <p class="lp-deck">{settings.t("landing.hero.deck")}</p>
          <div class="lp-cta-row">
            <A href={ctaHref()} class="lp-cta-primary">
              <span>{ctaLabel()}</span>
              <span class="lp-ar">→</span>
            </A>
            <A href="/signup" class="lp-cta-secondary">{settings.t("landing.nav.signup")}</A>
          </div>
        </div>

        <div class="lp-media">
          <div class="lp-media-fallback" aria-hidden="true">
            <Logo size={120} />
            <span class="lp-media-tag">moncoll · WAF</span>
          </div>
          <Show when={playVideo() && videoOk()}>
            <video
              class="lp-video"
              src="/landing/moncoll-promo.mp4"
              autoplay
              muted
              loop
              playsinline
              preload="metadata"
              onError={() => setVideoOk(false)}
            />
          </Show>
        </div>
      </section>

      <section class="lp-features">
        <h2 class="lp-section-title">{settings.t("landing.features.title")}</h2>
        <div class="lp-feature-grid">
          <For each={features()}>
            {(f) => {
              const Icon = f.icon;
              return (
                <article class="lp-feature-card">
                  <div class="lp-feature-icon"><Icon size={22} /></div>
                  <h3 class="lp-feature-title">{f.title}</h3>
                  <p class="lp-feature-desc">{f.desc}</p>
                </article>
              );
            }}
          </For>
        </div>
      </section>

      <footer class="lp-footer">
        <div class="lp-footer-brand">
          <Logo size={28} />
          <span>{settings.t("brand.name")}</span>
        </div>
        <span class="lp-footer-tag">{settings.t("landing.footer.tagline")}</span>
      </footer>
    </div>
  );
}

const styles = `
.lp-root {
  width: 100%;
  height: 100vh;
  overflow-y: auto;
  background: var(--cream);
  color: var(--ink);
  font-family: var(--font-body);
  background-image: radial-gradient(rgba(0,0,0,0.05) 1px, transparent 1px);
  background-size: 4px 4px;
}
[data-theme="dark"] .lp-root {
  background-image: radial-gradient(rgba(237,231,208,0.05) 1px, transparent 1px);
}

.lp-header {
  position: sticky; top: 0; z-index: 10;
  display: flex; align-items: center; justify-content: space-between; gap: 16px;
  padding: 18px 40px;
  background: var(--cream);
  border-bottom: 3px solid var(--line);
}
.lp-brand { display: flex; align-items: center; gap: 12px; text-decoration: none; color: var(--ink); }
.lp-brand-name { font-family: var(--font-display); font-size: 22px; font-weight: 900; letter-spacing: -0.04em; }
.lp-nav { display: flex; align-items: center; gap: 16px; }
.lp-icon-btn {
  display: inline-flex; align-items: center; justify-content: center;
  width: 40px; height: 40px; border: 3px solid var(--line);
  background: var(--cream); color: var(--ink); cursor: pointer;
  transition: background 120ms, color 120ms;
}
.lp-icon-btn:hover { background: var(--ink); color: var(--cream); }
.lp-link {
  font-family: var(--font-cond); font-weight: 700; font-size: 12px;
  letter-spacing: 0.18em; text-transform: uppercase; color: var(--ink); text-decoration: none;
}
.lp-link:hover { color: var(--red); }
.lp-login-btn {
  display: inline-flex; align-items: center; gap: 10px;
  background: var(--red); color: var(--cream); border: 3px solid var(--line);
  padding: 11px 20px;
  font-family: var(--font-cond); font-weight: 700; font-size: 13px;
  letter-spacing: 0.16em; text-transform: uppercase; text-decoration: none;
  box-shadow: 4px 4px 0 var(--line); transition: transform 90ms, box-shadow 90ms;
}
.lp-login-btn:hover { transform: translate(-2px,-2px); box-shadow: 6px 6px 0 var(--line); }

.lp-hero {
  display: grid; grid-template-columns: 1fr 1fr; gap: 48px; align-items: center;
  padding: 72px 40px; max-width: 1500px; margin: 0 auto;
}
.lp-eyebrow { display: flex; align-items: center; gap: 14px; margin-bottom: 22px; }
.lp-eyebrow-n {
  font-family: var(--font-display); font-weight: 900; font-size: 20px; line-height: 1;
  background: var(--red); color: var(--cream); padding: 4px 10px 6px; transform: rotate(-2deg);
}
.lp-eyebrow-text {
  font-family: var(--font-cond); font-weight: 700; font-size: 13px;
  letter-spacing: 0.28em; text-transform: uppercase;
}
.lp-h1 {
  font-family: var(--font-display); font-weight: 900;
  font-size: clamp(48px, 6vw, 96px); line-height: 0.86; letter-spacing: -0.05em;
  text-transform: uppercase; margin: 0 0 28px;
}
.lp-stack { display: block; }
.lp-h1-red { color: var(--red); }
.lp-tilt { display: inline-block; transform: rotate(-3deg); }
.lp-deck {
  font-family: var(--font-body); font-weight: 500; font-size: 18px; line-height: 1.5;
  max-width: 42ch; border-left: 4px solid var(--red); padding-left: 16px; margin: 0 0 32px;
  color: var(--ink-soft);
}
.lp-cta-row { display: flex; gap: 16px; align-items: center; flex-wrap: wrap; }
.lp-cta-primary {
  display: inline-flex; align-items: center; justify-content: space-between; gap: 16px;
  background: var(--red); color: var(--cream); border: 3px solid var(--line);
  padding: 16px 24px; min-width: 220px;
  font-family: var(--font-display); font-weight: 900; font-size: 20px;
  letter-spacing: 0.02em; text-transform: uppercase; text-decoration: none;
  box-shadow: 6px 6px 0 var(--line); transition: transform 90ms, box-shadow 90ms;
}
.lp-cta-primary:hover { transform: translate(-3px,-3px); box-shadow: 9px 9px 0 var(--line); }
.lp-ar { font-family: var(--font-mono); font-size: 20px; }
.lp-cta-secondary {
  font-family: var(--font-cond); font-weight: 700; font-size: 13px;
  letter-spacing: 0.18em; text-transform: uppercase; color: var(--ink);
  text-decoration: none; border-bottom: 3px solid var(--red); padding-bottom: 2px;
}
.lp-cta-secondary:hover { color: var(--red); }

.lp-media {
  position: relative; aspect-ratio: 16 / 9;
  border: 3px solid var(--line); box-shadow: 9px 9px 0 var(--line);
  background: var(--ink); overflow: hidden;
}
.lp-media-fallback {
  position: absolute; inset: 0;
  display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 16px;
  background: var(--cream-2);
  background-image: radial-gradient(rgba(0,0,0,0.06) 1px, transparent 1px);
  background-size: 6px 6px;
}
.lp-media-tag {
  font-family: var(--font-cond); font-weight: 700; font-size: 13px;
  letter-spacing: 0.28em; text-transform: uppercase; color: var(--ink-soft);
}
.lp-video { position: absolute; inset: 0; width: 100%; height: 100%; object-fit: cover; display: block; background: transparent; }

.lp-features { padding: 24px 40px 72px; max-width: 1500px; margin: 0 auto; }
.lp-section-title {
  font-family: var(--font-display); font-weight: 900;
  font-size: clamp(28px, 4vw, 48px); letter-spacing: -0.035em; text-transform: uppercase;
  margin: 0 0 28px; position: relative; padding-bottom: 18px; border-bottom: 3px solid var(--line);
}
.lp-section-title::after { content: ""; position: absolute; left: 0; bottom: -3px; width: 110px; height: 6px; background: var(--red); }
.lp-feature-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 20px; }
.lp-feature-card {
  background: var(--cream-2); border: 3px solid var(--line);
  padding: 24px; box-shadow: 4px 4px 0 var(--line);
  transition: transform 120ms, box-shadow 120ms;
}
.lp-feature-card:hover { transform: translate(-2px,-2px); box-shadow: 6px 6px 0 var(--line); }
.lp-feature-icon {
  width: 44px; height: 44px; border: 3px solid var(--line);
  display: flex; align-items: center; justify-content: center;
  background: var(--red); color: var(--cream); margin-bottom: 18px;
}
.lp-feature-title {
  font-family: var(--font-display); font-weight: 700; font-size: 18px;
  text-transform: uppercase; letter-spacing: -0.015em; margin-bottom: 10px;
}
.lp-feature-desc { font-family: var(--font-body); font-size: 14px; line-height: 1.55; color: var(--ink-soft); }

.lp-footer {
  display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap;
  padding: 28px 40px; border-top: 3px solid var(--line); background: var(--cream);
}
.lp-footer-brand { display: flex; align-items: center; gap: 10px; font-family: var(--font-display); font-weight: 900; font-size: 16px; letter-spacing: -0.03em; }
.lp-footer-tag { font-family: var(--font-mono); font-size: 12px; color: var(--ink-faint); }

@media (max-width: 900px) {
  .lp-hero { grid-template-columns: 1fr; padding: 40px 24px; gap: 32px; }
  .lp-header { padding: 14px 20px; }
  .lp-features { padding: 16px 24px 56px; }
  .lp-link { display: none; }
}
`;
