import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";

import type { NextConfig } from "next";

// The one console app. Every AWS service's pages are their own package
// (services/<id>/), mounted under app/(services)/ by scripts/services.mjs.
const servicesDir = join(__dirname, "../../services");
const services = readdirSync(servicesDir)
  .filter((id) => existsSync(join(servicesDir, id, "package.json")))
  .map((id) => `@mws-dashboard/service-${id}`);

/** Hosts the browser may send server actions from, beyond the console's own
 * (MWS_DASHBOARD_ORIGINS, comma-separated host:port, for a proxy in front). */
const origins = (process.env.MWS_DASHBOARD_ORIGINS ?? "").split(",").map((s) => s.trim()).filter(Boolean);

const config: NextConfig = {
  transpilePackages: ["@mws-dashboard/ui", "@mws-dashboard/aws", "@mws-dashboard/ai", ...services],
  poweredByHeader: false,
  experimental: {
    serverActions: { allowedOrigins: origins, bodySizeLimit: "64mb" },
    // Turbopack's on-disk dev cache went stale across changes to the shared
    // packages and kept telling open pages to reload (#118); compile fresh.
    turbopackFileSystemCacheForDev: false,
  },
};

export default config;
