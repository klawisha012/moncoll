import { loadFont as loadUnbounded } from "@remotion/google-fonts/Unbounded";
import { loadFont as loadOswald } from "@remotion/google-fonts/Oswald";

const { fontFamily: display } = loadUnbounded();
const { fontFamily: cond } = loadOswald();

export const FONTS = { display, cond } as const;
