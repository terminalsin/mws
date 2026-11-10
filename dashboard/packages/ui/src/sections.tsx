"use client";

// Long forms, split up. A sheet that would scroll past the screen breaks
// into sections:
//
//   <Sections mode="steps" testId="role">        // a guided order: 1 Trust > 2 Permissions > 3 Details
//     <Section id="trust" label="Trust" icon={<Shield />}>...</Section>
//     <Section id="permissions" label="Permissions">...</Section>
//   </Sections>
//
// mode "tabs" is for parts in no particular order (an alarm's metric,
// condition and actions). Every section stays mounted, so the form still
// submits every field, and a field that stops a submission opens its
// section. Steps put Back and Next in the form's action bar; the submit
// button shows on the last step. A Next checks only the fields in view.

import { ArrowLeft, ArrowRight, Check } from "lucide-react";
import { Children, isValidElement, useContext, useEffect, useRef, useState, type ReactElement, type ReactNode } from "react";
import { createPortal, flushSync } from "react-dom";

import { FormFooterContext } from "./client";

export interface SectionProps {
  id: string;
  label: string;
  icon?: ReactNode;
  /** A short summary shown beside the label once the step is behind you. */
  summary?: string;
  children: ReactNode;
}

/** One part of a `Sections` form. Renders nothing on its own. */
export function Section(_: SectionProps): ReactNode {
  return null;
}

const controls = (el: HTMLElement) =>
  [...el.querySelectorAll<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>("input, select, textarea")].filter((c) => !c.disabled && c.willValidate);

export function Sections({
  mode = "steps",
  testId = "section",
  children,
}: {
  mode?: "steps" | "tabs";
  testId?: string;
  children: ReactNode;
}) {
  // Sections are told apart by their props rather than their type, which a
  // server component's children may carry as a lazy reference.
  const sections = Children.toArray(children).filter(
    (c): c is ReactElement<SectionProps> => isValidElement<SectionProps>(c) && typeof c.props.id === "string" && typeof c.props.label === "string",
  );
  const [active, setActive] = useState(0);
  const [reached, setReached] = useState(0);
  const [broken, setBroken] = useState<Set<string>>(new Set());
  const panels = useRef<(HTMLDivElement | null)[]>([]);
  const root = useRef<HTMLDivElement>(null);
  const footer = useContext(FormFooterContext);
  const steps = mode === "steps";
  const last = active === sections.length - 1;
  const current = Math.min(active, sections.length - 1);

  const go = (i: number) => {
    setActive(i);
    setReached((r) => Math.max(r, i));
    // The new section starts at the top of the sheet.
    root.current?.scrollIntoView({ block: "nearest" });
  };

  // A field that stops a submission opens the section it is in, before the
  // form focuses it.
  useEffect(() => {
    const el = root.current;
    if (!el) return;
    const onInvalid = (e: Event) => {
      const i = panels.current.findIndex((p) => p?.contains(e.target as Node));
      if (i < 0) return;
      const id = sections[i]?.props.id;
      if (id) setBroken((b) => (b.has(id) ? b : new Set(b).add(id)));
      if (i !== current) flushSync(() => setActive(i));
    };
    el.addEventListener("invalid", onInvalid, true);
    return () => el.removeEventListener("invalid", onInvalid, true);
  });

  // A fixed section clears its mark.
  const recheck = (i: number) => {
    const id = sections[i]?.props.id;
    const panel = panels.current[i];
    if (!id || !panel || !broken.has(id)) return;
    if (controls(panel).every((c) => c.validity.valid)) {
      setBroken((b) => {
        const n = new Set(b);
        n.delete(id);
        return n;
      });
    }
  };

  const next = (to = current + 1) => {
    const panel = panels.current[current];
    if (panel) {
      const bad = controls(panel).filter((c) => !c.checkValidity());
      if (bad.length) {
        bad[0].focus();
        return;
      }
    }
    go(to);
  };

  const nav = steps && sections.length > 1 && (
    <span className="step-nav">
      {current > 0 && (
        <button type="button" className="button plain" data-testid={`${testId}-back`} onClick={() => go(current - 1)}>
          <ArrowLeft size={15} aria-hidden />
          <span>Back</span>
        </button>
      )}
      {!last && (
        <button type="button" className="button primary step-next" data-testid={`${testId}-next`} onClick={() => next()}>
          <span>Next</span>
          <ArrowRight size={15} aria-hidden />
        </button>
      )}
    </span>
  );

  return (
    <div className="form-sections" data-mode={mode} data-last={!steps || last} ref={root}>
      <div className={steps ? "stepper" : "section-tabs"} role="tablist" aria-label="Sections">
        {sections.map((s, i) => {
          const done = steps && i < reached && i !== current;
          return (
            <button
              key={s.props.id}
              type="button"
              role="tab"
              aria-selected={i === current}
              data-testid={`${testId}-step-${s.props.id}`}
              data-done={done || undefined}
              data-broken={broken.has(s.props.id) || undefined}
              onClick={() => (steps && i > current ? next(i) : go(i))}
            >
              {steps ? <i className="step-mark">{done ? <Check size={12} aria-hidden /> : i + 1}</i> : s.props.icon}
              <span>{s.props.label}</span>
              {done && sections.length <= 3 && s.props.summary && <small>{s.props.summary}</small>}
            </button>
          );
        })}
      </div>
      {sections.map((s, i) => (
        <div
          key={s.props.id}
          ref={(el) => {
            panels.current[i] = el;
          }}
          role="tabpanel"
          className="section-panel"
          hidden={i !== current}
          onInput={() => recheck(i)}
          onChange={() => recheck(i)}
          onKeyDown={(e) => {
            // Enter moves on rather than submitting from an early step.
            if (steps && !last && e.key === "Enter" && (e.target as HTMLElement).tagName === "INPUT") {
              e.preventDefault();
              next();
            }
          }}
        >
          {s.props.children}
        </div>
      ))}
      {nav && (footer ? createPortal(nav, footer) : <div className="form-actions">{nav}</div>)}
    </div>
  );
}
