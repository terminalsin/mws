import type { NextConfig } from "next";
import { zoneConfig, zoneUrl, zones } from "@mws-dashboard/ui/next-config";

// The shell owns `/` and stitches the other zones into one site: each zone
// is its own Next.js app served under its base path, and these rewrites
// forward that path to the zone's server (Next.js multi-zones).
const config: NextConfig = zoneConfig("shell", {
  async rewrites() {
    return zones
      .filter((z) => z.id !== "shell")
      .flatMap((z) => [
        { source: z.basePath, destination: `${zoneUrl(z.id)}${z.basePath}` },
        { source: `${z.basePath}/:path*`, destination: `${zoneUrl(z.id)}${z.basePath}/:path*` },
      ]);
  },
});

export default config;
