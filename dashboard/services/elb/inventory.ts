import "server-only";

import { loadBalancers } from "./lib/inventory";

/** What the console's home page and search list for this service. */
export const inventory = [loadBalancers];
