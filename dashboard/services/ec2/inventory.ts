import "server-only";

import { images, instances, securityGroups, templates, volumes } from "./lib/inventory";

/** What the console's home page and search list for this service. */
export const inventory = [instances, volumes, templates, images, securityGroups];
