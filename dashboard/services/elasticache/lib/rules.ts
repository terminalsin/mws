import type { Rule } from "@mws-dashboard/ui";

// The model leaves identifiers unconstrained; ElastiCache's rules are in its
// docs (and MWS enforces them): a letter first, then letters, digits and
// single hyphens, no hyphen at the end, at most 40 characters. ElastiCache
// stores them in lower case, so the console asks for them that way (and a
// taken name is then caught whatever case it was typed in).
export const NAME: Rule = {
  maxLength: 40,
  pattern: "^[a-z](?!.*--)[a-z0-9-]*(?<!-)$",
  hint: "Starts with a letter; a–z, 0–9 and single hyphens",
  generate: "name",
};

/** Snapshot names: up to 255 characters, ElastiCache's identifier rules. */
export const SNAPSHOT: Rule = {
  required: true,
  maxLength: 255,
  pattern: "^[a-z](?!.*--)[a-z0-9-]*(?<!-)$",
  hint: "Starts with a letter; a–z, 0–9 and single hyphens",
  generate: "name",
};
