import { AbsoluteFill, interpolate, useCurrentFrame, useVideoConfig, Easing } from "remotion";
import { palette } from "../palette";
import { FONTS } from "../fonts";

export const Outro = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const o = interpolate(frame, [0, 0.6 * fps], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.bezier(0.16, 1, 0.3, 1),
  });

  return (
    <AbsoluteFill
      style={{
        backgroundColor: palette.red,
        alignItems: "center",
        justifyContent: "center",
        flexDirection: "column",
        gap: 24,
        opacity: o,
      }}
    >
      <div
        style={{
          fontFamily: FONTS.display,
          fontWeight: 900,
          fontSize: 110,
          letterSpacing: "-0.05em",
          textTransform: "uppercase",
          color: palette.cream,
          textAlign: "center",
          lineHeight: 0.9,
        }}
      >
        Protect your
        <br />
        traffic
      </div>
      <div
        style={{
          fontFamily: FONTS.cond,
          fontWeight: 700,
          fontSize: 34,
          letterSpacing: "0.24em",
          textTransform: "uppercase",
          color: palette.ink,
          backgroundColor: palette.cream,
          padding: "10px 22px",
        }}
      >
        moncoll
      </div>
    </AbsoluteFill>
  );
};
