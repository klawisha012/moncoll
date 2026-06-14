import { AbsoluteFill, Img, staticFile, interpolate, useCurrentFrame, useVideoConfig, Easing } from "remotion";
import { palette } from "../palette";
import { FONTS } from "../fonts";

type Props = {
  index: number;
  keyword: string;
  label: string;
  asset: string;
  route: string;
};

const Dot = ({ color }: { color: string }) => (
  <div style={{ width: 15, height: 15, borderRadius: "50%", backgroundColor: color }} />
);

export const FeatureScene = (props: Props) => {
  const frame = useCurrentFrame();
  const { fps, durationInFrames } = useVideoConfig();

  const enter = interpolate(frame, [0, 0.55 * fps], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.bezier(0.16, 1, 0.3, 1),
  });
  const exit = interpolate(frame, [durationInFrames - 0.45 * fps, durationInFrames], [1, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const opacity = Math.min(enter, exit);

  const textX = (1 - enter) * -60;
  const winX = (1 - enter) * 90;
  const winScale = interpolate(enter, [0, 1], [0.94, 1]);

  // Slow Ken Burns drift on the screenshot so static captures feel alive.
  const kb = interpolate(frame, [0, durationInFrames], [0, 1]);
  const imgScale = 1 + kb * 0.06;
  const imgY = -kb * 16;

  return (
    <AbsoluteFill
      style={{
        backgroundColor: palette.cream,
        backgroundImage: "radial-gradient(rgba(0,0,0,0.06) 1px, transparent 1px)",
        backgroundSize: "8px 8px",
        flexDirection: "row",
        alignItems: "center",
        justifyContent: "center",
        padding: "0 96px",
        gap: 80,
        opacity,
      }}
    >
      {/* Caption column */}
      <div style={{ width: 520, flexShrink: 0, transform: `translateX(${textX}px)` }}>
        <div
          style={{
            display: "inline-block",
            backgroundColor: palette.red,
            color: palette.cream,
            fontFamily: FONTS.cond,
            fontWeight: 700,
            fontSize: 26,
            letterSpacing: "0.28em",
            padding: "7px 16px",
            marginBottom: 26,
          }}
        >
          {`0${props.index + 1}`}
        </div>
        <div
          style={{
            fontFamily: FONTS.display,
            fontWeight: 900,
            fontSize: 56,
            lineHeight: 1.0,
            letterSpacing: "-0.04em",
            color: palette.ink,
          }}
        >
          {props.keyword}
        </div>
        <div
          style={{
            fontFamily: FONTS.cond,
            fontWeight: 700,
            fontSize: 30,
            letterSpacing: "0.05em",
            textTransform: "uppercase",
            color: palette.red,
            marginTop: 16,
          }}
        >
          {props.label}
        </div>
        <div style={{ width: 96, height: 5, backgroundColor: palette.ink, marginTop: 28 }} />
      </div>

      {/* Browser window with the real page */}
      <div
        style={{
          flex: 1,
          transform: `translateX(${winX}px) scale(${winScale})`,
          transformOrigin: "left center",
        }}
      >
        <div
          style={{
            border: `5px solid ${palette.ink}`,
            backgroundColor: palette.ink,
            boxShadow: `18px 18px 0 ${palette.red}`,
            overflow: "hidden",
          }}
        >
          {/* Title bar */}
          <div
            style={{
              height: 56,
              backgroundColor: palette.ink,
              display: "flex",
              alignItems: "center",
              padding: "0 22px",
              gap: 12,
            }}
          >
            <Dot color={palette.red} />
            <Dot color={palette.cream2} />
            <Dot color="#6b6657" />
            <div
              style={{
                marginLeft: 18,
                flex: 1,
                backgroundColor: "#242320",
                color: palette.cream2,
                fontFamily: FONTS.cond,
                fontWeight: 600,
                fontSize: 22,
                letterSpacing: "0.02em",
                padding: "8px 20px",
                borderRadius: 6,
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
              }}
            >
              {`●  moncoll.app${props.route}`}
            </div>
          </div>
          {/* Page screenshot */}
          <div style={{ width: "100%", aspectRatio: "16 / 9", backgroundColor: palette.ink, overflow: "hidden" }}>
            <Img
              src={staticFile(props.asset)}
              style={{
                width: "100%",
                height: "100%",
                objectFit: "cover",
                objectPosition: "top center",
                transform: `translateY(${imgY}px) scale(${imgScale})`,
                transformOrigin: "top center",
              }}
            />
          </div>
        </div>
      </div>
    </AbsoluteFill>
  );
};
