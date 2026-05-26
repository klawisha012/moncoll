import { onMount } from "solid-js";

declare global {
  interface Window {
    turnstile?: {
      render: (container: HTMLElement, options: { sitekey: string; callback: (token: string) => void }) => void;
    };
  }
}

export default function TurnstileWidget(props: {
  siteKey: string;
  onToken: (token: string) => void;
}) {
  let ref: HTMLDivElement | undefined;

  onMount(() => {
    const renderWidget = () => {
      if (!ref || !window.turnstile) return;
      window.turnstile.render(ref, { sitekey: props.siteKey, callback: props.onToken });
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
  });

  return <div ref={ref} />;
}
