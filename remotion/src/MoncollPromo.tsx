import { AbsoluteFill, Sequence, useVideoConfig } from "remotion";
import { BrandIntro } from "./scenes/BrandIntro";
import { FeatureScene } from "./scenes/FeatureScene";
import { Outro } from "./scenes/Outro";
import { palette } from "./palette";
import { FONTS } from "./fonts";
import manifest from "../assets.manifest.json";

const INTRO_SECONDS = 4;
const FEATURE_SECONDS = 3.5;
const OUTRO_SECONDS = 4;

export const MoncollPromo = () => {
  const { fps } = useVideoConfig();
  const scenes = manifest.scenes;
  const introFrames = INTRO_SECONDS * fps;
  const featureFrames = FEATURE_SECONDS * fps;
  const outroStart = introFrames + featureFrames * scenes.length;

  return (
    <AbsoluteFill style={{ backgroundColor: palette.cream, fontFamily: FONTS.cond }}>
      <Sequence durationInFrames={introFrames} layout="none">
        <BrandIntro />
      </Sequence>

      {scenes.map((s, i) => (
        <Sequence key={s.id} from={introFrames + featureFrames * i} durationInFrames={featureFrames} layout="none">
          <FeatureScene index={i} keyword={s.keyword} label={s.label} route={s.route} />
        </Sequence>
      ))}

      <Sequence from={outroStart} durationInFrames={OUTRO_SECONDS * fps} layout="none">
        <Outro />
      </Sequence>
    </AbsoluteFill>
  );
};

export const PROMO_SECONDS = INTRO_SECONDS + FEATURE_SECONDS * manifest.scenes.length + OUTRO_SECONDS;
