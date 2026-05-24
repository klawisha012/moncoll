import { useEffect, useRef } from "react";

declare global {
  interface Window {
    turnstile?: {
      render: (container: HTMLElement, options: { sitekey: string; callback: (token: string) => void }) => void;
    };
  }
}

export default function TurnstileWidget({
  siteKey,
  onToken,
}: {
  siteKey: string;
  onToken: (token: string) => void;
}) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const renderWidget = () => {
      if (!ref.current || !window.turnstile) return;
      window.turnstile.render(ref.current, { sitekey: siteKey, callback: onToken });
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
  }, [siteKey, onToken]);

  return <div ref={ref} />;
}
