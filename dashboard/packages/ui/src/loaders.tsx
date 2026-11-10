// Dot-matrix loaders: a 4×4 grid of dots whose colour pulses on one shared
// cycle, each dot offset in time. The pattern says what is happening:
//   scan    columns sweep left to right: reading, searching
//   orbit   a dot runs round the edge: a long task in progress (a command)
//   pulse   rings breathe out from the centre: waiting on an answer
//   twinkle dots light at random: loading a listing
// No hooks, so server and client components can both render one.
import type { CSSProperties } from "react";

export type DotPattern = "scan" | "orbit" | "pulse" | "twinkle";

const N = 4;
const PERIMETER = [0, 1, 2, 3, 7, 11, 15, 14, 13, 12, 8, 4];
// Fixed "random" offsets, so server and client render the same markup.
const TWINKLE = [7, 2, 11, 5, 14, 0, 9, 3, 12, 6, 1, 10, 4, 13, 8, 15];

/** The phase (0 to 1) of dot `i` in `pattern`, or null for a dot that stays dim. */
function phase(pattern: DotPattern, i: number): number | null {
  const x = i % N;
  const y = Math.floor(i / N);
  switch (pattern) {
    case "scan":
      return x / N;
    case "orbit": {
      const at = PERIMETER.indexOf(i);
      return at < 0 ? null : at / PERIMETER.length;
    }
    case "pulse": {
      const d = Math.max(Math.abs(x - 1.5), Math.abs(y - 1.5));
      return d < 1 ? 0 : 0.35;
    }
    case "twinkle":
      return TWINKLE[i] / 16;
  }
}

export function DotMatrix({ pattern = "pulse", label, size = 3 }: { pattern?: DotPattern; label?: string; size?: number }) {
  return (
    <span
      className="dot-matrix"
      data-pattern={pattern}
      role={label ? "img" : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
      style={{ "--dot": `${size}px` } as CSSProperties}
    >
      {Array.from({ length: N * N }, (_, i) => {
        const p = phase(pattern, i);
        return <i key={i} data-dim={p === null || undefined} style={p === null ? undefined : ({ "--p": p } as CSSProperties)} />;
      })}
    </span>
  );
}
