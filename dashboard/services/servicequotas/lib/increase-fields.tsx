"use client";

// The request-increase field, with one-tap multiples of the current value.

import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import { RequestServiceQuotaIncrease } from "@mws-dashboard/ui/model/servicequotas";
import { useState } from "react";

const STEPS = [2, 5, 10];

export function IncreaseFields({ value }: { value: number }) {
  const min = Math.floor(value) + 1;
  const suggest = (x: number) => Math.max(min, Math.ceil(value * x) || x);
  const [v, setV] = useState(suggest(2));
  return (
    <>
      <Field key={v} label="New value" hint={`Now ${value}`} rule={{ ...RequestServiceQuotaIncrease.DesiredValue, min }} member="DesiredValue">
        <input name="value" type="number" step="any" min={min} defaultValue={v} required />
      </Field>
      <span className="chips" role="group" aria-label="Quick values">
        {STEPS.map((x) => (
          <button
            key={x}
            type="button"
            className="button plain aria-pressed:shadow-[inset_0_0_0_2px_var(--accent)]"
            aria-pressed={v === suggest(x)}
            onClick={() => setV(suggest(x))}
            title={`${x}× the current value`}
          >
            {suggest(x).toLocaleString()}
          </button>
        ))}
      </span>
    </>
  );
}
