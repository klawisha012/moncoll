import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { palette } from "../palette";
import { FONTS } from "../fonts";

const Shield = () => (
  <svg width="180" height="210" viewBox="0 0 120 140" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path
      d="M16 24 L60 35 L104 24 L104 64 C104 92 86 112 60 124 C34 112 16 92 16 64 Z"
      fill={palette.cream}
      stroke={palette.ink}
      strokeWidth={7}
      strokeLinejoin="round"
    />
    <path
      d="M42 84 L42 52 L60 70 L78 52 L78 84"
      fill="none"
      stroke={palette.red}
      strokeWidth={12}
      strokeLinecap="round"
      strokeLinejoin="round"
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
