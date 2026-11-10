import "server-only";

import { logGroups, alarms } from "./lib/inventory";

/** What the console's home page and search list for this service. */
export const inventory = [logGroups, alarms];
