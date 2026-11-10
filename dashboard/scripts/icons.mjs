#!/usr/bin/env node
// Copy the official AWS icons the console uses (from the `aws-icons`
// package) into the console's public folder, served at
// /icons/aws/, and the brand logos ("brand/python", from `simple-icons`,
// in their brand color) into /icons/brand/. Run after adding an icon:
//   node scripts/icons.mjs
import { copyFileSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const source = join(root, "node_modules/aws-icons/icons");
const target = join(root, "apps/console/public/icons/aws");
const kinds = { service: "architecture-service", category: "category", resource: "resource", group: "architecture-group" };

// Every "kind/Name" string literal in the UI package, the services and the console.
const used = new Set();
function scan(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (["node_modules", ".next", "public"].includes(entry.name)) continue;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) scan(path);
    else if (/\.(tsx?|json)$/.test(entry.name)) {
      for (const m of readFileSync(path, "utf8").matchAll(/["'`](service|category|resource|group|brand)\/([A-Za-z0-9-]+)["'`]/g)) used.add(`${m[1]}/${m[2]}`);
    }
  }
}
scan(join(root, "packages"));
scan(join(root, "services"));
scan(join(root, "apps"));

rmSync(target, { recursive: true, force: true });
const brands = join(root, "apps/console/public/icons/brand");
rmSync(brands, { recursive: true, force: true });
const simple = Object.values(await import("simple-icons"));
let missing = 0;
for (const icon of [...used].sort()) {
  const [kind, name] = icon.split("/");
  if (kind === "brand") {
    const logo = simple.find((i) => i?.slug === name);
    if (!logo) {
      console.error(`missing icon: ${icon}`);
      missing++;
      continue;
    }
    // Near-black logos would vanish in dark mode: draw them grey.
    const [r, g, b] = [0, 2, 4].map((i) => parseInt(logo.hex.slice(i, i + 2), 16));
    const fill = 0.2126 * r + 0.7152 * g + 0.0722 * b < 40 ? "8e8e93" : logo.hex;
    mkdirSync(brands, { recursive: true });
    writeFileSync(join(brands, `${name}.svg`), logo.svg.replace("<svg ", `<svg fill="#${fill}" `));
    continue;
  }
  const from = join(source, kinds[kind], `${name}.svg`);
  try {
    mkdirSync(join(target, kind), { recursive: true });
    copyFileSync(from, join(target, kind, `${name}.svg`));
  } catch {
    console.error(`missing icon: ${icon}`);
    missing++;
  }
}
console.log(`copied ${used.size - missing} icons to apps/console/public/icons`);
process.exit(missing ? 1 : 0);
