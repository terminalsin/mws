// Console-side rules for ECS forms. The ECS model leaves names and sizes
// unconstrained; these are the limits the ECS documentation (and MWS)
// enforce, so problems show on the field before the request is sent.

import type { Rule } from "@mws-dashboard/ui";

/** Cluster, service, family and container names. */
export const NAME: Rule = { pattern: "^[A-Za-z0-9_-]+$", maxLength: 255, hint: "Letters, digits, - and _", generate: "name" };

/** A container image reference: `[registry/]repository[:tag][@digest]`. */
export const IMAGE: Rule = {
  maxLength: 255,
  pattern:
    "^(?:[A-Za-z0-9.-]+(?::[0-9]+)?/)?[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$",
  hint: "registry/repository:tag, lowercase",
};

const steps = (lo: number, hi: number, step: number) => Array.from({ length: (hi - lo) / step + 1 }, (_, i) => String(lo + i * step));

/** Fargate task sizes: the memory (MiB) each CPU (units) allows. */
export const FARGATE_MEMORY: Record<string, string[]> = {
  "256": ["512", "1024", "2048"],
  "512": steps(1024, 4096, 1024),
  "1024": steps(2048, 8192, 1024),
  "2048": steps(4096, 16384, 1024),
  "4096": steps(8192, 30720, 1024),
  "8192": steps(16384, 61440, 4096),
  "16384": steps(32768, 122880, 8192),
};

const gb = (mib: string) => `${Number(mib) / 1024}`;

/** "0.5, 1 or 2 GB" / "2–8 GB" for a CPU's memory choices. */
export function memoryHint(cpu: string): string {
  const options = FARGATE_MEMORY[cpu] ?? [];
  if (options.length <= 3) return `${options.slice(0, -1).map(gb).join(", ")} or ${gb(options.at(-1) ?? "0")} GB`;
  return `${gb(options[0])}–${gb(options.at(-1)!)} GB`;
}
