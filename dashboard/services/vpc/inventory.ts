import "server-only";

import { addresses, peerings, vpcs } from "./lib/inventory";

/** What the console's home page and search list for this service. */
export const inventory = [vpcs, addresses, peerings];
