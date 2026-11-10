import "server-only";

import { components, pipelines, recipes } from "./lib/inventory";

/** What the console's home page and search list for this service. */
export const inventory = [pipelines, recipes, components];
