"use client";

// Inline validation for `Field`: the field checks its control against the
// merged rule (model constraints, the control's attributes, the page's
// extras), shows the problem in place of its hint, and offers repairs as
// one-click chips. Errors the server returns after a submission land on the
// field they name, with the same repairs (see `ActionForm`).

import { CircleAlert, Lightbulb, Sparkles, WandSparkles } from "lucide-react";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import { check, didYouMean, mergeRules, sameMember, type FieldIssue, type Issue, type Repair, type Rule } from "./validation";

// ---------------------------------------------------------------------------
// The form side: server issues in, claims out.

/** Matches a server issue to a field that will show it. */
export type Claim = (issue: FieldIssue) => boolean;

export interface FormIssues {
  /** The last submission's server issues, and a number that changes with
   * each submission so a field re-reads them. */
  issues: FieldIssue[];
  seq: number;
  register: (claim: Claim) => () => void;
}

export const FormIssuesContext = createContext<FormIssues | null>(null);

/** For `ActionForm`: the context its fields read, and which server issues
 * no field claimed (those still show under the form). */
export function useFormIssues() {
  const claims = useRef(new Set<Claim>());
  const [current, setCurrent] = useState<{ issues: FieldIssue[]; seq: number }>({ issues: [], seq: 0 });
  const register = useCallback((claim: Claim) => {
    claims.current.add(claim);
    return () => {
      claims.current.delete(claim);
    };
  }, []);
  const publish = useCallback((issues: FieldIssue[]) => setCurrent((c) => ({ issues, seq: c.seq + 1 })), []);
  const unclaimed = useCallback((issues: FieldIssue[]) => issues.filter((i) => ![...claims.current].some((claim) => claim(i))), []);
  const value = useMemo<FormIssues>(() => ({ ...current, register }), [current, register]);
  return { value, publish, unclaimed };
}

// ---------------------------------------------------------------------------
// Controls.

type Control = HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;

const CONTROL = 'input:not([type="hidden"],[type="checkbox"],[type="radio"],[type="file"],[type="submit"],[type="button"]), select, textarea';

/** The rule a control's own attributes express. HTML patterns match the
 * whole value, so they are anchored here. */
function attributeRule(el: Control): Rule {
  const rule: Rule = {};
  if (el.required) rule.required = true;
  if (el instanceof HTMLSelectElement) {
    const values = [...el.options].map((o) => o.value).filter((v) => v !== "");
    if (values.length) rule.enum = values;
    return rule;
  }
  if (el.minLength > 0) rule.minLength = el.minLength;
  if (el.maxLength > 0) rule.maxLength = el.maxLength;
  if (el instanceof HTMLInputElement) {
    if (el.pattern) rule.pattern = `^(?:${el.pattern})$`;
    if (el.type === "number" || el.type === "range") {
      const step = el.step === "any" ? NaN : Number(el.step || "1");
      rule.type = Number.isInteger(step) ? "integer" : "number";
      if (el.min !== "") rule.min = Number(el.min);
      if (el.max !== "") rule.max = Number(el.max);
    }
    if (el.type === "email") rule.format = "email";
    if (el.type === "url") rule.format = "url";
  }
  return rule;
}

/** Set a control's value as if the person typed it, so React and any
 * listener see the change. */
export function setControlValue(el: Control, value: string) {
  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement : el instanceof HTMLSelectElement ? HTMLSelectElement : HTMLInputElement;
  Object.getOwnPropertyDescriptor(proto.prototype, "value")?.set?.call(el, value);
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
}

// ---------------------------------------------------------------------------
// The field.

export interface FieldRules {
  /** The member's model rule, e.g. `CreateQueue.QueueName` from
   * `@mws-dashboard/ui/model/sqs`, refined as the page needs. */
  rule?: Rule;
  /** The API member this field fills, for matching server errors
   * (defaults to the control's name). */
  member?: string;
  /** Shortcuts for the common refinements (merged over `rule`). */
  format?: Rule["format"];
  taken?: string[];
  known?: string[];
  generate?: Rule["generate"];
  arn?: string;
  /** This field is the resource's name: "already exists" errors land here. */
  unique?: boolean;
}

const LEAVE_MS = 160;

export function FieldShell({
  label,
  hint,
  children,
  rule,
  member,
  format,
  taken,
  known,
  generate,
  arn,
  unique,
}: FieldRules & { label: string; hint?: ReactNode; children: ReactNode }) {
  const box = useRef<HTMLDivElement>(null);
  const control = useRef<Control | null>(null);
  const form = useContext(FormIssuesContext);
  const extras = useMemo(
    () => mergeRules(rule, { format, generate, arn, known, taken: taken?.length ? taken : undefined }),
    [rule, format, generate, arn, known, taken],
  );
  // `shown`: the person has had a chance to finish (blurred after typing,
  // or tried to submit), so problems are visible from now on.
  const [shown, setShown] = useState(false);
  const seen = useRef(false);
  seen.current = shown;
  const [issue, setIssue] = useState<Issue | null>(null);
  const [server, setServer] = useState<{ issue: FieldIssue; value: string } | null>(null);
  const [leaving, setLeaving] = useState<Issue | null>(null);
  const dirty = useRef(false);

  const fullRule = useCallback(() => (control.current ? mergeRules(attributeRule(control.current), extras) : extras), [extras]);

  const evaluate = useCallback(() => {
    const el = control.current;
    if (!el) return null;
    const value = el.value;
    let next: Issue | null = null;
    const rule = fullRule();
    if (server && server.value === value) {
      // The server rejected this exact value: read its constraint into the
      // rule, so the repairs fix what it objected to.
      const serverRule = mergeRules(rule, server.issue.rule, server.issue.code === "taken" ? { taken: [value] } : undefined);
      next = check(value, serverRule) ?? { code: server.issue.code, message: server.issue.message, repairs: didYouMean(value, serverRule) };
    } else {
      next = check(value, rule);
    }
    el.setCustomValidity(next ? next.message : "");
    return next;
  }, [fullRule, server]);

  const last = useRef<Issue | null>(null);
  const refresh = useCallback(() => {
    const next = evaluate();
    // A cleared issue the person could see fades out rather than vanishing.
    if (last.current && !next && seen.current) setLeaving(last.current);
    last.current = next;
    setIssue(next);
  }, [evaluate]);

  // Find the control and follow it.
  useEffect(() => {
    const el = box.current?.querySelector<Control>(CONTROL) ?? null;
    control.current = el;
    if (!el) return;
    refresh();
    const onInput = () => {
      dirty.current = true;
      refresh();
    };
    const onBlur = () => {
      if (dirty.current) setShown(true);
    };
    const onInvalid = (e: Event) => {
      // Shown in place, so the browser's bubble is not needed.
      e.preventDefault();
      setShown(true);
      refresh();
    };
    const onReset = () => {
      dirty.current = false;
      setShown(false);
      setServer(null);
      // The reset value lands after the event.
      setTimeout(refresh, 0);
    };
    el.addEventListener("input", onInput);
    el.addEventListener("change", onInput);
    el.addEventListener("blur", onBlur);
    el.addEventListener("invalid", onInvalid);
    el.form?.addEventListener("reset", onReset);
    const owner = el.form;
    return () => {
      el.removeEventListener("input", onInput);
      el.removeEventListener("change", onInput);
      el.removeEventListener("blur", onBlur);
      el.removeEventListener("invalid", onInvalid);
      owner?.removeEventListener("reset", onReset);
    };
  }, [refresh]);

  // Claim the server issues meant for this field.
  const claim = useCallback<Claim>(
    (i) => {
      const el = control.current;
      if (!el) return false;
      if (i.field) return i.field === el.name;
      if (i.member) return sameMember(i.member, member ?? el.name);
      return i.code === "taken" && (unique || !!taken);
    },
    [member, unique, taken],
  );
  useEffect(() => form?.register(claim), [form, claim]);
  const seq = form?.seq ?? 0;
  useEffect(() => {
    if (!form || seq === 0) return;
    const mine = form.issues.find(claim);
    const el = control.current;
    if (!mine || !el) {
      setServer(null);
      return;
    }
    setServer({ issue: mine, value: el.value });
    setShown(true);
    // Only `seq` means a new submission.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [seq]);
  useEffect(() => {
    refresh();
  }, [server, refresh]);

  useEffect(() => {
    if (!leaving) return;
    const t = setTimeout(() => setLeaving(null), LEAVE_MS);
    return () => clearTimeout(t);
  }, [leaving]);

  const apply = (r: Repair) => {
    const el = control.current;
    if (!el) return;
    setControlValue(el, r.value);
    el.focus();
  };

  const visible = shown ? issue : null;
  const note = visible ?? (shown ? leaving : null);
  return (
    <div ref={box} className="field" data-invalid={visible ? visible.code : undefined}>
      <label className="field-control">
        <span className="field-label">{label}</span>
        {children}
      </label>
      {note ? (
        <IssueNote issue={note} leaving={!visible} apply={apply} />
      ) : (
        hint && <span className="field-hint">{hint}</span>
      )}
    </div>
  );
}

const ICONS = { fix: WandSparkles, suggest: Lightbulb, generate: Sparkles };

function IssueNote({ issue, leaving, apply }: { issue: Issue; leaving: boolean; apply: (r: Repair) => void }) {
  return (
    <span className="field-issue" role={leaving ? undefined : "alert"} data-state={leaving ? "leaving" : "shown"}>
      <span className="field-issue-text">
        <CircleAlert size={14} aria-hidden />
        <span>{issue.message}</span>
      </span>
      {issue.repairs.length > 0 && (
        <span className="repairs">
          {issue.repairs.map((r) => {
            const Icon = ICONS[r.kind];
            // Short values are their own best label; long ones (JSON) say
            // what the repair does.
            const literal = r.value.length <= 40 && !r.value.includes("\n");
            return (
              <button
                key={r.value}
                type="button"
                className="repair"
                data-kind={r.kind}
                title={r.label}
                aria-label={literal ? `${r.label}: ${r.value}` : r.label}
                disabled={leaving}
                onClick={() => apply(r)}
              >
                <Icon size={13} aria-hidden />
                <span className={literal ? "repair-value" : undefined}>{literal ? r.value : r.label}</span>
              </button>
            );
          })}
        </span>
      )}
    </span>
  );
}
