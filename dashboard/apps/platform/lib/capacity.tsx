/** A group's capacity as slots: running, wanted, allowed (AWS shows these as numbers). */
export function Capacity({ running, desired, min, max }: { running: number; desired: number; min: number; max: number }) {
  const slots = Math.min(Math.max(max, desired, running), 24);
  return (
    <span className="capacity" role="img" aria-label={`${running} of ${desired} running (min ${min}, max ${max})`} title={`${running}/${desired} · ${min}–${max}`}>
      {Array.from({ length: slots }, (_, i) => (
        <i key={i} className={i < running ? "on" : i < desired ? "want" : i < min ? "min" : undefined} />
      ))}
      <b>
        {running}/{desired}
      </b>
    </span>
  );
}
