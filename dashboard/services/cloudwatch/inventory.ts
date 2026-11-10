import "server-only";

import { alarms, dashboards, logGroups } from "./lib/inventory";

/** What the console's home page and search list for this service. */
export const inventory = [logGroups, alarms, dashboards];
