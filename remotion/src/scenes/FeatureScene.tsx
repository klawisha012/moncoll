import { AbsoluteFill, Img, staticFile, interpolate, useCurrentFrame, useVideoConfig, Easing } from "remotion";
import { palette } from "../palette";
import { FONTS } from "../fonts";

export const FeatureScene = (props: { index: number; keyword: string; label: string; asset: string }) => {
  const frame = useCurrentFrame();
  const { fps, durationInFrames } = useVideoConfig();

  const enter = interpolate(frame, [0, 0.5 * fps], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.bezier(0.16, 1, 0.3, 1),
  });
  const exit = interpolate(frame, [durationInFrames - 0.4 * fps, durationInFrames], [1, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const opacity = Math.min(enter, exit);
  const x = interpolate(enter, [0, 1], [60, 0]);

  return (
    <AbsoluteFill style={{ backgroundColor: palette.ink }}>
      <Img
        src={staticFile(props.asset)}
        style={{ position: "absolute", inset: 0, width: "100%", height: "100%", objectFit: "cover", opacity: 0.55 }}
      />
      <AbsoluteFill style={{ justifyContent: "flex-end", padding: 120, opacity }}>
        <div style={{ transform: `translateX(${x}px)` }}>
          <div
            style={{
              display: "inline-block",
              backgroundColor: palette.red,
              color: palette.cream,
              fontFamily: FONTS.cond,
              fontWeight: 700,
              fontSize: 28,
              letterSpacing: "0.28em",
              padding: "8px 18px",
              marginBottom: 24,
            }}
          >
            {`0${props.index + 1}`}
          </div>
          <div
            style={{
              fontFamily: FONTS.display,
              fontWeight: 900,
              fontSize: 140,
              lineHeight: 0.9,
              letterSpacing: "-0.05em",
              textTransform: "uppercase",
              color: palette.cream,
            }}
          >
            {props.keyword}
          </div>
          <div
            style={{
              fontFamily: FONTS.cond,
              fontWeight: 700,
              fontSize: 40,
              letterSpacing: "0.04em",
              textTransform: "uppercase",
              color: palette.red,
              marginTop: 12,
            }}
          >
            {props.label}
          </div>
        </div>
      </AbsoluteFill>
    </AbsoluteFill>
  );
};
