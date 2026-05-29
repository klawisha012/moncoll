import { onMount, onCleanup } from "solid-js";

declare global {
  interface Window {
    turnstile?: {
      render: (container: HTMLElement, options: { sitekey: string; callback: (token: string) => void }) => string;
      remove: (widgetId: string) => void;
    };
  }
}

export default function TurnstileWidget(props: {
  siteKey: string;
  onToken: (token: string) => void;
}) {
  let ref: HTMLDivElement | undefined;

  onMount(() => {
    let widgetId: string | undefined;

    const renderWidget = () => {
      if (!ref || !window.turnstile) return;
      widgetId = window.turnstile.render(ref, { sitekey: props.siteKey, callback: props.onToken });
    };

    if (window.turnstile) {
      renderWidget();
    } else {
      const s = document.createElement("script");
      s.src = "https://challenges.cloudflare.com/turnstile/v0/api.js";
      s.async = true;
      s.onload = renderWidget;
      document.head.appendChild(s);
    }

    onCleanup(() => {
      if (widgetId && window.turnstile) {
        try {
          window.turnstile.remove(widgetId);
        } catch (e) {
          console.error("Failed to remove turnstile widget:", e);
        }
      }
    });
  });

  return <div ref={ref} />;
}
