/** One series over time as a thin line on a soft area: no client JavaScript;
 * each point carries a hover target with its value. */
export function LineChart({
  points,
  label,
  unit,
  threshold,
  band,
}: {
  points: { t: Date; v: number }[];
  label: string;
  unit?: string;
  threshold?: number;
  /** An anomaly detection band: the expected range at each time. */
  band?: { t: Date; lo: number; hi: number }[];
}) {
  const w = 720;
  const h = 180;
  const left = 40;
  const right = 12;
  const top = 12;
  const bottom = 24;
  const ts = [
    ...points.map((p) => p.t.getTime()),
    ...(band ?? []).map((b) => b.t.getTime()),
  ];
  const vs = [
    ...points.map((p) => p.v),
    ...(band ?? []).flatMap((b) => [b.lo, b.hi]),
  ];
  const [t0, t1] = [Math.min(...ts), Math.max(...ts)];
  const extra = threshold === undefined ? [] : [threshold];
  const v1 = Math.max(...vs, ...extra, 0) || 1;
  const v0 = Math.min(0, ...vs, ...extra);
  const x = (t: number) =>
    left + ((t - t0) / Math.max(t1 - t0, 1)) * (w - left - right);
  const y = (v: number) =>
    h - bottom - ((v - v0) / Math.max(v1 - v0, 1e-9)) * (h - top - bottom);
  const line = points
    .map(
      (p, i) =>
        `${i ? "L" : "M"}${x(p.t.getTime()).toFixed(1)},${y(p.v).toFixed(1)}`,
    )
    .join(" ");
  const area = points.length
    ? `${line} L${x(t1).toFixed(1)},${y(v0)} L${x(t0).toFixed(1)},${y(v0)} Z`
    : "";
  const ticks = [v0, (v0 + v1) / 2, v1];
  const fmt = (v: number) =>
    Math.abs(v) >= 1000 ? `${(v / 1000).toFixed(1)}k` : `${+v.toFixed(2)}`;
  const day = t1 - t0 > 86_400_000;
  const time = (t: number) =>
    day
      ? new Date(t).toISOString().slice(5, 16).replace("T", " ")
      : new Date(t).toISOString().slice(11, 16);
  return (
    <svg
      className="chart"
      viewBox={`0 0 ${w} ${h}`}
      width="100%"
      role="img"
      aria-label={label}
    >
      {ticks.map((v) => (
        <g key={v}>
          <line
            x1={left}
            x2={w - right}
            y1={y(v)}
            y2={y(v)}
            className="chart-grid"
          />
          <text
            x={left - 6}
            y={y(v) + 4}
            textAnchor="end"
            className="chart-axis"
          >
            {fmt(v)}
          </text>
        </g>
      ))}
      {points.length > 1 && (
        <>
          <text x={left} y={h - 6} className="chart-axis">
            {time(t0)}
          </text>
          <text x={w - right} y={h - 6} textAnchor="end" className="chart-axis">
            {time(t1)}
          </text>
        </>
      )}
      {threshold !== undefined && (
        <g aria-label={`Threshold ${threshold}`}>
          <line
            x1={left}
            x2={w - right}
            y1={y(threshold)}
            y2={y(threshold)}
            stroke="var(--bad)"
            strokeDasharray="4 3"
            strokeWidth={1}
          />
          <text
            x={w - right}
            y={y(threshold) - 4}
            textAnchor="end"
            className="chart-axis"
            fill="var(--bad)"
          >
            {fmt(threshold)}
          </text>
        </g>
      )}
      {band && band.length > 1 && (
        <path
          aria-label="Expected band"
          d={`${band.map((b, i) => `${i ? "L" : "M"}${x(b.t.getTime()).toFixed(1)},${y(b.hi).toFixed(1)}`).join(" ")} ${[
            ...band,
          ]
            .reverse()
            .map((b) => `L${x(b.t.getTime()).toFixed(1)},${y(b.lo).toFixed(1)}`)
            .join(" ")} Z`}
          fill="var(--accent)"
          fillOpacity={0.12}
          stroke="none"
        />
      )}
      <path d={area} className="chart-area" />
      <path d={line} className="chart-line" />
      {points.map((p, i) => (
        <g key={i} className="chart-point">
          <circle
            cx={x(p.t.getTime())}
            cy={y(p.v)}
            r={points.length < 40 ? 4 : 0}
            className="chart-dot"
          />
          <circle
            cx={x(p.t.getTime())}
            cy={y(p.v)}
            r={10}
            className="chart-hit"
          >
            <title>{`${time(p.t.getTime())} · ${fmt(p.v)}${unit ? ` ${unit}` : ""}`}</title>
          </circle>
        </g>
      ))}
    </svg>
  );
}
