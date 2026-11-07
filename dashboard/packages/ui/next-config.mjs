// Next.js settings shared by the zones. Plain JavaScript so that every
// app's next.config.ts can import it without transpiling the package.
import { readFileSync } from "node:fs";

/** @type {{ id: string, basePath: string, port: number }[]} */
export const zones = JSON.parse(readFileSync(new URL("./zones.json", import.meta.url), "utf8"));

/** Where the shell finds a zone's server (MWS_DASHBOARD_<ZONE>_URL). */
export function zoneUrl(id) {
  const z = zones.find((x) => x.id === id);
  if (!z) throw new Error(`unknown zone ${id}`);
  return (process.env[`MWS_DASHBOARD_${id.toUpperCase()}_URL`] ?? `http://127.0.0.1:${z.port}`).replace(/\/$/, "");
}

/** Hosts the browser may send server actions from. Requests reach a zone
 * through the shell's rewrites, so the browser's origin is the shell's, not
 * the zone's own. */
function allowedOrigins() {
  const shell = zones.find((z) => z.id === "shell");
  const extra = (process.env.MWS_DASHBOARD_ORIGINS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  return [`localhost:${shell.port}`, `127.0.0.1:${shell.port}`, ...extra];
}

/** The Next.js config for zone `id`: its base path, the workspace packages
 * it compiles, and server action limits. */
export function zoneConfig(id, extra = {}) {
  const z = zones.find((x) => x.id === id);
  if (!z) throw new Error(`unknown zone ${id}`);
  return {
    ...(z.basePath ? { basePath: z.basePath } : {}),
    transpilePackages: ["@mws-dashboard/ui", "@mws-dashboard/aws", "@mws-dashboard/ai"],
    poweredByHeader: false,
    experimental: {
      serverActions: { allowedOrigins: allowedOrigins(), bodySizeLimit: "64mb" },
    },
    ...extra,
  };
}
