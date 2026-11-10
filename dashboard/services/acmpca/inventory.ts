import "server-only";

import { authorities, connectors } from "./lib/inventory";

/** What the console's home page and search list for this service. */
export const inventory = [authorities, connectors];
