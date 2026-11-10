/** The first free name: `base`, else `base-2`, `base-3`, ... Server and client safe. */
export function freeName(base: string, taken: string[]) {
  if (!taken.includes(base)) return base;
  for (let n = 2; ; n++) if (!taken.includes(`${base}-${n}`)) return `${base}-${n}`;
}
