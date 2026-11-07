#!/usr/bin/env node
// Run every zone of the dashboard at once: `node scripts/zones.mjs dev` for
// development, `node scripts/zones.mjs start` for the production build (after
// `npm run build`). Open the shell (http://localhost:3000); it forwards each
// zone's base path to that zone's server.
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const mode = process.argv[2] ?? "dev";
if (!["dev", "start"].includes(mode)) {
  console.error("usage: zones.mjs dev|start");
  process.exit(2);
}
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const zones = JSON.parse(readFileSync(join(root, "packages/ui/zones.json"), "utf8"));
const next = createRequire(join(root, "apps/shell/package.json")).resolve("next/dist/bin/next");
const colors = [36, 33, 35, 32, 34, 31];

const children = zones.map((zone, i) => {
  const child = spawn(process.execPath, [next, mode, "-p", String(zone.port), "-H", "127.0.0.1"], {
    cwd: join(root, "apps", zone.id),
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const tag = `\x1b[${colors[i % colors.length]}m${zone.id.padEnd(13)}\x1b[0m`;
  for (const stream of [child.stdout, child.stderr]) {
    let buffered = "";
    stream.on("data", (chunk) => {
      buffered += chunk;
      const lines = buffered.split("\n");
      buffered = lines.pop() ?? "";
      for (const line of lines) process.stdout.write(`${tag} ${line}\n`);
    });
  }
  child.on("exit", (code, signal) => {
    console.log(`${tag} exited (${signal ?? code})`);
    shutdown(code ?? 1);
  });
  return child;
});

console.log(`MWS console: http://localhost:${zones.find((z) => z.id === "shell").port}`);

let stopping = false;
function shutdown(code) {
  if (stopping) return;
  stopping = true;
  for (const child of children) child.kill("SIGTERM");
  setTimeout(() => process.exit(code), 500);
}
process.on("SIGINT", () => shutdown(0));
process.on("SIGTERM", () => shutdown(0));
