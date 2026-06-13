import { mkdirSync, copyFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const dest = resolve(root, "..", "frontend", "public", "landing");
mkdirSync(dest, { recursive: true });

const pairs = [
  ["out/moncoll-promo.mp4", "moncoll-promo.mp4"],
  ["out/poster.jpg", "poster.jpg"],
];

for (const [src, name] of pairs) {
  const from = resolve(root, src);
  if (existsSync(from)) {
    copyFileSync(from, resolve(dest, name));
    console.log("copied", name, "->", dest);
  } else {
    console.warn("missing (skipped):", from);
  }
}
