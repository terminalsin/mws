import "server-only";

import type { ActionResult } from "@mws-dashboard/ui";

/** Auto Scaling's size errors are plain ValidationErrors whose messages
 * carry the bounds; read them back onto the field they concern, with the
 * bound as its rule so the field offers the clamp. */
export function sizeIssue(e: unknown): ActionResult | null {
  if (!(e instanceof Error)) return null;
  const desired = /Desired capacity:\s*(-?\d+) must be between the specified min size:\s*(-?\d+) and max size:\s*(-?\d+)/.exec(e.message);
  if (desired) {
    const [, , min, max] = desired.map(Number);
    return {
      ok: false,
      message: e.message,
      issues: [
        {
          field: "desired",
          code: "range",
          message: `${min}–${max}`,
          rule: { type: "integer", min, max },
        },
      ],
    };
  }
  const bound = /Max bound, (-?\d+), must be greater than or equal to min bound, (-?\d+)/.exec(e.message);
  if (bound) {
    const min = Number(bound[2]);
    return {
      ok: false,
      message: e.message,
      issues: [
        {
          field: "max",
          code: "range",
          message: `At least ${min}`,
          rule: { type: "integer", min },
        },
      ],
    };
  }
  return null;
}
