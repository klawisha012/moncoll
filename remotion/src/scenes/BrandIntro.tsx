import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { palette } from "../palette";
import { FONTS } from "../fonts";

const Shield = () => (
  <svg width="154" height="210" viewBox="0 0 144 197" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path
      d="M139.441 33.2394L71.9408 4.81836L4.4408 33.2394V100.739L71.9408 189.555L139.441 100.739V33.2394Z"
      fill="none"
      stroke={palette.ink}
      strokeWidth={8.88158}
    />
    <path
      d="M32.4408 137.318L17.9408 51.8184L71.9408 93.0421L125.941 51.8184L111.441 137.318"
      fill="none"
      stroke={palette.red}
      strokeWidth={14.2105}
    />
  </svg>
);

export const BrandIntro = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const scale = spring({ frame, fps, config: { damping: 200 } });
  const wordmark = interpolate(frame, [0.6 * fps, 1.4 * fps], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const tagline = interpolate(frame, [1.2 * fps, 2 * fps], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  return (
    <AbsoluteFill
      style={{
        backgroundColor: palette.cream,
        alignItems: "center",
        justifyContent: "center",
        flexDirection: "column",
        gap: 28,
        backgroundImage: "radial-gradient(rgba(0,0,0,0.06) 1px, transparent 1px)",
        backgroundSize: "8px 8px",
      }}
    >
      <div style={{ transform: `scale(${scale})` }}>
        <Shield />
      </div>
      <div
        style={{
          fontFamily: FONTS.display,
          fontWeight: 900,
          fontSize: 120,
          letterSpacing: "-0.05em",
          color: palette.ink,
          opacity: wordmark,
          transform: `translateY(${(1 - wordmark) * 20}px)`,
        }}
      >
        moncoll
      </div>
      <div
        style={{
          fontFamily: FONTS.cond,
          fontWeight: 700,
          fontSize: 30,
          letterSpacing: "0.3em",
          textTransform: "uppercase",
          color: palette.red,
          opacity: tagline,
        }}
      >
        Web Application Firewall
      </div>
    </AbsoluteFill>
  );
};
