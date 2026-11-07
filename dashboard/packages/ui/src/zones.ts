// The routing contract between the microfrontends: which zone (Next.js app)
// owns which URL prefix, and on which port it runs. The shell's rewrites, the
// dev/start script and cross-zone links read this one list; what each zone
// shows in the navigation lives in the service catalog (catalog.ts).
import zones from "../zones.json";

/** The cookie every zone reads the selected region from. */
export const REGION_COOKIE = "mws-region";

export type ZoneId = "shell" | "storage" | "messaging" | "security" | "compute" | "observability";

export interface Zone {
  id: ZoneId;
  basePath: string;
  port: number;
}

export const ZONES = zones as Zone[];

export function zone(id: ZoneId): Zone {
  const found = ZONES.find((z) => z.id === id);
  if (!found) throw new Error(`unknown zone ${id}`);
  return found;
}

/** An absolute href (from the site root) to `path` in a zone. */
export function zoneHref(id: ZoneId, path = "/"): string {
  const base = zone(id).basePath;
  return path === "/" ? base || "/" : base + path;
}
