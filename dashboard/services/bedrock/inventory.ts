import "server-only";

import { customModels, guardrails, provisioned } from "./lib/inventory";

/** What the console's home page and search list for this service. */
export const inventory = [guardrails, customModels, provisioned];
