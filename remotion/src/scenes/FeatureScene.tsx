import { AbsoluteFill, interpolate, useCurrentFrame, useVideoConfig, Easing } from "remotion";
import { palette } from "../palette";
import { FONTS } from "../fonts";

type Props = {
  index: number;
  keyword: string;
  label: string;
  route: string;
};

const Dot = ({ color }: { color: string }) => (
  <div style={{ width: 15, height: 15, borderRadius: "50%", backgroundColor: color }} />
);

// ── Feature mocks ────────────────────────────────────────────
// Branded, self-contained graphics — no app screenshots, so the under-the-hood
// stack never leaks into the promo. `frame` drives subtle motion per scene.

const MockThreatMap = ({ frame, fps }: { frame: number; fps: number }) => {
  // A radar-style globe with attack origins lighting up in sequence.
  const blips = [
    { x: 30, y: 34 },
    { x: 64, y: 28 },
    { x: 47, y: 55 },
    { x: 74, y: 62 },
    { x: 22, y: 66 },
    { x: 58, y: 44 },
  ];
  return (
    <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div
        style={{
          width: "62%",
          aspectRatio: "1",
          borderRadius: "50%",
          border: `3px solid ${palette.inkSoft}`,
          boxShadow: `inset 0 0 80px rgba(214,54,42,0.18)`,
          position: "relative",
        }}
      >
        {[0.33, 0.66].map((r) => (
          <div
            key={r}
            style={{
              position: "absolute",
              inset: `${(1 - r) * 50}%`,
              borderRadius: "50%",
              border: `2px solid ${palette.inkSoft}`,
              opacity: 0.5,
            }}
          />
        ))}
        {blips.map((b, i) => {
          const t = (frame - i * 0.18 * fps) % (1.6 * fps);
          const on = interpolate(t, [0, 0.15 * fps, 0.7 * fps], [0, 1, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
          return (
            <div
              key={i}
              style={{
                position: "absolute",
                left: `${b.x}%`,
                top: `${b.y}%`,
                width: 18,
                height: 18,
                borderRadius: "50%",
                backgroundColor: palette.red,
                boxShadow: `0 0 ${10 + on * 22}px ${palette.red}`,
                opacity: 0.35 + on * 0.65,
                transform: `translate(-50%,-50%) scale(${0.8 + on * 0.6})`,
              }}
            />
          );
        })}
      </div>
    </div>
  );
};

const MockRuleEngine = ({ frame, fps }: { frame: number; fps: number }) => {
  const rows = [0, 1, 2, 3, 4, 5];
  return (
    <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", justifyContent: "center", gap: 18, padding: "0 9%" }}>
      {rows.map((i) => {
        const on = interpolate(frame, [(0.2 + i * 0.12) * fps, (0.5 + i * 0.12) * fps], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
        return (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: 18, opacity: 0.25 + on * 0.75 }}>
            <div style={{ width: 26, height: 26, backgroundColor: palette.red, flexShrink: 0, transform: `scale(${on})` }} />
            <div style={{ flex: 1, height: 16, backgroundColor: palette.inkSoft }} />
            <div style={{ width: `${20 + i * 8}%`, height: 16, backgroundColor: palette.cream2, opacity: 0.5 }} />
          </div>
        );
      })}
    </div>
  );
};

const MockBehavior = ({ frame, fps }: { frame: number; fps: number }) => {
  const bars = [40, 62, 35, 78, 50, 95, 44, 70, 58, 88];
  return (
    <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "flex-end", justifyContent: "center", gap: "2.4%", padding: "16% 9% 14%" }}>
      {bars.map((h, i) => {
        const grow = interpolate(frame, [(0.2 + i * 0.06) * fps, (0.6 + i * 0.06) * fps], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
        const flagged = h > 80;
        return (
          <div
            key={i}
            style={{
              flex: 1,
              height: `${h * grow}%`,
              backgroundColor: flagged ? palette.red : palette.inkSoft,
              boxShadow: flagged ? `0 0 26px rgba(214,54,42,0.5)` : "none",
            }}
          />
        );
      })}
    </div>
  );
};

const MockRealtime = ({ frame, fps }: { frame: number; fps: number }) => {
  const tiles = ["1.2M", "843", "16ms"];
  const pts = [60, 48, 66, 40, 72, 52, 80, 58, 88, 64, 92];
  const sweep = interpolate(frame, [0.3 * fps, 1.4 * fps], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const shown = Math.max(2, Math.round(pts.length * sweep));
  const line = pts.slice(0, shown).map((y, i) => `${(i / (pts.length - 1)) * 100},${100 - y}`).join(" ");
  return (
    <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", gap: "5%", padding: "8% 8%" }}>
      <div style={{ display: "flex", gap: "4%" }}>
        {tiles.map((v, i) => {
          const on = interpolate(frame, [(0.2 + i * 0.14) * fps, (0.55 + i * 0.14) * fps], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
          return (
            <div key={i} style={{ flex: 1, border: `3px solid ${palette.inkSoft}`, padding: "5% 6%", opacity: 0.3 + on * 0.7 }}>
              <div style={{ height: 10, width: "55%", backgroundColor: palette.inkSoft, marginBottom: 16 }} />
              <div style={{ fontFamily: FONTS.display, fontWeight: 900, fontSize: 46, color: palette.cream }}>{v}</div>
            </div>
          );
        })}
      </div>
      <div style={{ flex: 1, border: `3px solid ${palette.inkSoft}`, padding: "3%" }}>
        <svg viewBox="0 0 100 100" preserveAspectRatio="none" style={{ width: "100%", height: "100%" }}>
          <polyline points={line} fill="none" stroke={palette.red} strokeWidth={2.4} vectorEffect="non-scaling-stroke" />
        </svg>
      </div>
    </div>
  );
};

const MOCKS = [MockThreatMap, MockRuleEngine, MockBehavior, MockRealtime];

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

  const Mock = MOCKS[props.index % MOCKS.length];

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

      {/* Browser window with a branded feature mock */}
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
          {/* Feature mock canvas */}
          <div
            style={{
              width: "100%",
              aspectRatio: "16 / 9",
              backgroundColor: "#161512",
              backgroundImage: "radial-gradient(rgba(241,234,216,0.05) 1px, transparent 1px)",
              backgroundSize: "26px 26px",
              position: "relative",
              overflow: "hidden",
            }}
          >
            <Mock frame={frame} fps={fps} />
          </div>
        </div>
      </div>
    </AbsoluteFill>
  );
};
