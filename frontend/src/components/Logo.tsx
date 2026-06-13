import type { JSX } from "solid-js";

/**
 * moncoll brand mark — a crest shield with a signal-red "M".
 *
 * Theme-aware by design: the shield body/outline use the cream/ink CSS
 * variables (so it inverts cleanly between the light and dark themes) while
 * the "M" stays signal-red. Rendered inline (not as an <img>) precisely so
 * those CSS custom properties resolve against the current theme.
 */
export default function Logo(props: { size?: number; title?: string; class?: string }): JSX.Element {
  const size = () => props.size ?? 44;
  return (
    <svg
      width={size() * (120 / 140)}
      height={size()}
      viewBox="0 0 120 140"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      role="img"
      aria-label={props.title ?? "moncoll"}
      class={props.class}
    >
      <title>{props.title ?? "moncoll"}</title>
      {/* Shield body — cream fill, ink outline (both flip with the theme). */}
      <path
        d="M16 24 L60 35 L104 24 L104 64 C104 92 86 112 60 124 C34 112 16 92 16 64 Z"
        style={{
          fill: "var(--cream)",
          stroke: "var(--ink)",
          "stroke-width": "7",
          "stroke-linejoin": "round",
        }}
      />
      {/* The "M" — always signal-red. */}
      <path
        d="M42 84 L42 52 L60 70 L78 52 L78 84"
        style={{
          fill: "none",
          stroke: "var(--red)",
          "stroke-width": "12",
          "stroke-linecap": "round",
          "stroke-linejoin": "round",
        }}
      />
    </svg>
  );
}
