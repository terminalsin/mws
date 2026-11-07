// The contract between the microfrontends: which zone owns which URL prefix
// and what it puts in the navigation. The shell's rewrites, the dev/start
// script and every zone's sidebar read this one list, so adding a page to the
// navigation never means editing more than one zone plus this file.
import zones from "../zones.json";

/** The cookie every zone reads the selected region from. */
export const REGION_COOKIE = "mws-region";

export type ZoneId = "shell" | "storage" | "messaging" | "security" | "compute" | "observability";

export interface NavItem {
  label: string;
  /** The path inside the zone, without its base path. */
  path: string;
}

export interface Zone {
  id: ZoneId;
  title: string;
  basePath: string;
  port: number;
  nav: NavItem[];
}

export const ZONES = zones as Zone[];

export function zone(id: ZoneId): Zone {
  const found = ZONES.find((z) => z.id === id);
  if (!found) throw new Error(`unknown zone ${id}`);
  return found;
}

/** An absolute href (from the site root) to `path` in another zone. */
export function zoneHref(id: ZoneId, path = "/"): string {
  const base = zone(id).basePath;
  return path === "/" ? base || "/" : base + path;
}
