import { Gauge } from "lucide-react";

import type { MeteringRecord } from "../../lib/marketplace";

/** Usage per dimension, largest first. */
export function Usage({ records }: { records: MeteringRecord[] }) {
  const totals = new Map<string, number>();
  for (const r of records) totals.set(r.dimension, (totals.get(r.dimension) ?? 0) + r.quantity);
  const rows = [...totals].sort((a, b) => b[1] - a[1]);
  const top = Math.max(1, ...rows.map(([, v]) => v));
  return (
    <ul className="hbars" aria-label="Usage by dimension">
      {rows.map(([dimension, value]) => (
        <li key={dimension} title={`${dimension}: ${value}`}>
          <Gauge size={16} aria-hidden />
          <span className="hbar-name">{dimension}</span>
          <span className="hbar-track">
            <span className="hbar" style={{ width: `${(value / top) * 100}%` }} />
          </span>
          <span className="hbar-value">{value.toLocaleString()}</span>
        </li>
      ))}
    </ul>
  );
}
