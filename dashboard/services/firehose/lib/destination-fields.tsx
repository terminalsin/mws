"use client";

import { useEffect, useRef, type ReactNode } from "react";

/** Shows only the fieldsets of the chosen destination (`data-dest`), as the
 * AWS console's destination picker does; hidden ones are disabled so they
 * are neither validated nor sent. */
export function DestinationSwitch({
  name,
  children,
}: {
  name: string;
  children: ReactNode;
}) {
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const root = box.current;
    const form = root?.closest("form");
    if (!root || !form) return;
    const apply = () => {
      const picked =
        (form.elements.namedItem(name) as HTMLSelectElement | null)?.value ??
        "";
      for (const set of root.querySelectorAll<HTMLFieldSetElement>(
        "fieldset[data-dest]",
      )) {
        const on = set.dataset.dest!.split(" ").includes(picked);
        set.hidden = !on;
        set.disabled = !on;
      }
    };
    apply();
    form.addEventListener("change", apply);
    return () => form.removeEventListener("change", apply);
  }, [name]);
  return <div ref={box}>{children}</div>;
}
