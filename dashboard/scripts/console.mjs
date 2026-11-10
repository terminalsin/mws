#!/usr/bin/env node
// Run the console: `node scripts/console.mjs dev` for development (mounts
// the service packages and keeps the mounts current as routes are added or
// removed), `node scripts/console.mjs start` for the production build (after
// `npm run build`). One Next.js server serves every service on port 3000
// (MWS_DASHBOARD_PORT to change it).
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { writeConstraints } from "./constraints.mjs";
import { generate, watchServices } from "./services.mjs";

const mode = process.argv[2] ?? "dev";
if (!["dev", "start"].includes(mode)) {
  console.error("usage: console.mjs dev|start");
  process.exit(2);
}
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const app = join(root, "apps/console");
const next = createRequire(join(app, "package.json")).resolve("next/dist/bin/next");
const port = process.env.MWS_DASHBOARD_PORT ?? "3000";

const children = [];
function run(args) {
  const child = spawn(process.execPath, args, { cwd: app, env: process.env, stdio: "inherit" });
  child.on("exit", (code, signal) => shutdown(code ?? (signal ? 1 : 0)));
  children.push(child);
  return child;
}

if (mode === "dev") {
  try {
    generate();
    writeConstraints();
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
  watchServices();
}
run([next, mode, "-p", port, "-H", "127.0.0.1"]);
console.log(`MWS console: http://localhost:${port}`);

let stopping = false;
function shutdown(code) {
  if (stopping) return;
  stopping = true;
  for (const child of children) child.kill("SIGTERM");
  setTimeout(() => process.exit(code), 500);
}
process.on("SIGINT", () => shutdown(0));
process.on("SIGTERM", () => shutdown(0));
