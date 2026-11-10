import type { Rule } from "@mws-dashboard/ui";
import { CreateTrail } from "@mws-dashboard/ui/model/cloudtrail";

// The model leaves trail names unconstrained; these are the checks
// CreateTrail applies (3-128 characters, letters, digits, . _ -, a letter or
// digit at both ends, no separators side by side, not an IP address).
export const TRAIL_NAME: Rule = {
  ...CreateTrail.Name,
  minLength: 3,
  maxLength: 128,
  pattern: "^(?!\\d+\\.\\d+\\.\\d+\\.\\d+$)[A-Za-z0-9](?:[A-Za-z0-9]|[._-](?=[A-Za-z0-9]))*$",
  hint: "Letters, digits, . _ and -, starting and ending with a letter or digit",
  generate: "name",
};

/** The CloudTrail record behind a LookupEvents entry. */
export function parseRecord(json: string | undefined): Record<string, unknown> {
  try {
    const v = JSON.parse(json ?? "{}");
    return v && typeof v === "object" ? v : {};
  } catch {
    return {};
  }
}
