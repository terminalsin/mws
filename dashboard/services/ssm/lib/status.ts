import type { Tone } from "@mws-dashboard/ui";

/** Tones for the statuses Run Command, Automation, State Manager,
 * maintenance windows, sessions and OpsCenter report. */
const TONES: Record<string, Tone> = {
  Success: "good",
  SUCCESS: "good",
  Online: "good",
  Active: "good",
  Approved: "good",
  Resolved: "good",
  Completed: "good",
  Failed: "bad",
  FAILED: "bad",
  TimedOut: "bad",
  TIMED_OUT: "bad",
  "Delivery Timed Out": "bad",
  "Execution Timed Out": "bad",
  Undeliverable: "bad",
  Terminated: "neutral",
  Cancelled: "neutral",
  CANCELLED: "neutral",
  Cancelling: "warn",
  CANCELLING: "warn",
  ConnectionLost: "warn",
  Inactive: "neutral",
  Waiting: "warn",
  Pending: "info",
  PENDING: "info",
  InProgress: "info",
  IN_PROGRESS: "info",
  Running: "info",
  Open: "warn",
  Rejected: "bad",
  Skipped: "neutral",
  SKIPPED_OVERLAPPING: "neutral",
  PendingApproval: "warn",
  Scheduled: "info",
  CompletedWithSuccess: "good",
  CompletedWithFailure: "bad",
  Exited: "neutral",
  RunbookInProgress: "info",
  Connected: "good",
  Terminating: "warn",
  Disconnected: "neutral",
  ENABLED: "good",
  DISABLED: "neutral",
};

export const tone = (s: string | undefined): Tone => TONES[s ?? ""] ?? "neutral";

/** Still on its way: pages refresh while anything shown is in one of these. */
export const RUNNING = new Set(["Pending", "InProgress", "Delayed", "Cancelling", "Waiting", "Running", "PENDING", "IN_PROGRESS", "CANCELLING", "Connected", "Terminating", "Scheduled", "RunbookInProgress", "ChangeCalendarOverride"]);

/** "InProgress" → "In progress", "TIMED_OUT" → "Timed out". */
export const words = (s: string | undefined) =>
  !s ? "" : (s.includes("_") ? s.toLowerCase().replace(/_/g, " ") : s.replace(/([a-z])([A-Z])/g, "$1 $2").toLowerCase()).replace(/^./, (c) => c.toUpperCase());

/** Targets as one line: `InstanceIds=i-1,i-2 · tag:env=prod`. */
export const targetsText = (targets: { Key?: string; Values?: string[] }[] | undefined) => (targets ?? []).map((t) => `${t.Key}=${(t.Values ?? []).join(",")}`).join(" · ");

/** "InstanceIds=i-1,i-2" or "tag:env=prod" lines (or a bare instance list) as SSM targets. */
export function parseTargets(input: string) {
  const lines = input
    .split(/\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  if (lines.length === 1 && !lines[0].includes("=")) return [{ Key: "InstanceIds", Values: lines[0].split(/[\s,]+/).filter(Boolean) }];
  return lines.map((l) => {
    const i = l.indexOf("=");
    if (i < 0) return { Key: "InstanceIds", Values: l.split(/[\s,]+/).filter(Boolean) };
    return { Key: l.slice(0, i).trim(), Values: l.slice(i + 1).split(",").map((v) => v.trim()).filter(Boolean) };
  });
}

/** `name=value` lines as SSM document parameters (each value a one-item list;
 * a value with newlines, like a script, is split into lines for `commands`). */
export function parseParameters(input: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  let last: string | undefined;
  for (const raw of input.split("\n")) {
    const m = raw.match(/^([A-Za-z0-9_.-]+)\s*=\s*(.*)$/);
    if (m) {
      last = m[1];
      out[last] = [m[2]];
    } else if (last && raw.trim()) out[last].push(raw.replace(/^\s{2}/, ""));
  }
  return out;
}
