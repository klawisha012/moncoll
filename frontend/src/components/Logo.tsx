import type { JSX } from "solid-js";

/**
 * moncoll brand mark — an angular crest shield with a signal-red "M".
 *
 * Theme-aware by design: the shield outline uses the --ink CSS variable, so it
 * flips from near-black on the light theme to cream-white on the dark theme —
 * mirroring the two-file brand artwork (#0c0c0c / #f3f3f3). The "M" stays
 * signal-red via --red. Rendered inline (not as an <img>) precisely so those
 * CSS custom properties resolve against the current theme.
 */
export default function Logo(props: { size?: number; title?: string; class?: string }): JSX.Element {
  const size = () => props.size ?? 44;
  return (
    <svg
      width={size() * (144 / 197)}
      height={size()}
      viewBox="0 0 144 197"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      role="img"
      aria-label={props.title ?? "moncoll"}
      class={props.class}
    >
      <title>{props.title ?? "moncoll"}</title>
      {/* Shield outline — flips ink↔cream with the theme. */}
      <path
        d="M139.441 33.2394L71.9408 4.81836L4.4408 33.2394V100.739L71.9408 189.555L139.441 100.739V33.2394Z"
        style={{
          fill: "none",
          stroke: "var(--ink)",
          "stroke-width": "8.88158",
        }}
      />
      {/* The "M" — always signal-red. */}
      <path
        d="M32.4408 137.318L17.9408 51.8184L71.9408 93.0421L125.941 51.8184L111.441 137.318"
        style={{
          fill: "none",
          stroke: "var(--red)",
          "stroke-width": "14.2105",
        }}
      />
    </svg>
  );
}
