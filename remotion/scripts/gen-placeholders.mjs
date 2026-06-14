import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const manifest = JSON.parse(readFileSync(resolve(root, "assets.manifest.json"), "utf8"));

const svg = (label) => `<svg xmlns="http://www.w3.org/2000/svg" width="1920" height="1080" viewBox="0 0 1920 1080">
  <rect width="1920" height="1080" fill="#0c0c0c"/>
  <g stroke="#d6362a" stroke-width="3" opacity="0.45">
    ${Array.from({ length: 24 }, (_, i) => `<line x1="0" y1="${i * 45}" x2="1920" y2="${i * 45}"/>`).join("\n    ")}
  </g>
  <text x="96" y="560" font-family="Oswald, sans-serif" font-size="120" font-weight="700" fill="#f1ead8" letter-spacing="6">${label}</text>
  <text x="96" y="660" font-family="Oswald, sans-serif" font-size="44" fill="#d6362a" letter-spacing="10">PLACEHOLDER ASSET</text>
</svg>`;

for (const s of manifest.scenes) {
  const file = resolve(root, "public", s.asset);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, svg(String(s.keyword).toUpperCase()));
  console.log("wrote", s.asset);
}
