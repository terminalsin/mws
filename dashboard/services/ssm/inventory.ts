import "server-only";

import { documents, nodes, opsItems, parameters, windows } from "./lib/inventory";

/** What the console's home page and search list for this service. */
export const inventory = [parameters, documents, nodes, windows, opsItems];
