import { Composition } from "remotion";
import { MoncollPromo, PROMO_SECONDS } from "./MoncollPromo";
import manifest from "../assets.manifest.json";

export const RemotionRoot = () => {
  const fps = manifest.promo.fps;
  return (
    <Composition
      id={manifest.promo.id}
      component={MoncollPromo}
      durationInFrames={Math.round(PROMO_SECONDS * fps)}
      fps={fps}
      width={manifest.promo.width}
      height={manifest.promo.height}
    />
  );
};
