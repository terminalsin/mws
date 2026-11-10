"use client";

// The event pattern builder: pick where events come from (logos), which
// kinds, then filter on their fields with EventBridge's operators. The
// JSON below stays the form's value. A sample event of the chosen kind is
// tested against the pattern by EventBridge itself as you build, and a
// describe-it box drafts the pattern from a sentence.

import { FieldShell, setControlValue } from "@mws-dashboard/ui/fields";
import { iconUrl } from "@mws-dashboard/ui/catalog";
import type { Rule } from "@mws-dashboard/ui/validation";
import { Braces, CircleCheck, CircleSlash, LayoutList, Plus, Sparkles, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState, useTransition } from "react";

import { EVENT_SOURCES, sourceInfo, type EventField } from "./event-catalog";
import { testPatternLive } from "./pattern-test";

type Op = "equals" | "anything-but" | "prefix" | "suffix" | "wildcard" | "equals-ignore-case" | "exists" | "not-exists" | ">" | ">=" | "<" | "<=";

const OPS: { id: Op; label: string; numeric?: boolean; novalue?: boolean }[] = [
  { id: "equals", label: "is" },
  { id: "anything-but", label: "is not" },
  { id: "prefix", label: "starts with" },
  { id: "suffix", label: "ends with" },
  { id: "wildcard", label: "matches (*)" },
  { id: "equals-ignore-case", label: "is (any case)" },
  { id: "exists", label: "exists", novalue: true },
  { id: "not-exists", label: "is missing", novalue: true },
  { id: ">", label: ">", numeric: true },
  { id: ">=", label: "≥", numeric: true },
  { id: "<", label: "<", numeric: true },
  { id: "<=", label: "≤", numeric: true },
];

interface Filter {
  path: string;
  op: Op;
  values: string[];
}

interface Model {
  sources: string[];
  types: string[];
  filters: Filter[];
}

const num = (v: string) => (v.trim() !== "" && !Number.isNaN(Number(v)) ? Number(v) : v);

function matcher(f: Filter): unknown[] {
  switch (f.op) {
    case "equals":
      return f.values.map(num);
    case "anything-but":
      return [{ "anything-but": f.values.length === 1 ? num(f.values[0]) : f.values.map(num) }];
    case "prefix":
    case "suffix":
    case "wildcard":
    case "equals-ignore-case":
      return f.values.map((v) => ({ [f.op]: v }));
    case "exists":
      return [{ exists: true }];
    case "not-exists":
      return [{ exists: false }];
    default:
      return [{ numeric: [f.op, Number(f.values[0] ?? 0)] }];
  }
}

function serialize(m: Model): string {
  const out: Record<string, unknown> = {};
  if (m.sources.length) out.source = m.sources;
  if (m.types.length) out["detail-type"] = m.types;
  for (const f of m.filters) {
    if (!f.path) continue;
    const keys = f.path.split(".");
    let at = out;
    for (const k of keys.slice(0, -1)) at = (at[k] ??= {}) as Record<string, unknown>;
    const leaf = keys.at(-1)!;
    at[leaf] = [...((at[leaf] as unknown[]) ?? []), ...matcher(f)];
  }
  return JSON.stringify(out, null, 2);
}

/** The builder's model of a pattern, or null for one it cannot show (then JSON only). */
function parse(text: string): Model | null {
  let doc: Record<string, unknown>;
  try {
    doc = JSON.parse(text || "{}");
  } catch {
    return null;
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return null;
  const m: Model = { sources: [], types: [], filters: [] };
  const strings = (v: unknown) => (Array.isArray(v) && v.every((x) => typeof x === "string") ? (v as string[]) : null);
  const walk = (o: Record<string, unknown>, path: string[]): boolean => {
    for (const [k, v] of Object.entries(o)) {
      const p = [...path, k];
      if (!path.length && k === "source" && strings(v)) m.sources = strings(v)!;
      else if (!path.length && k === "detail-type" && strings(v)) m.types = strings(v)!;
      else if (Array.isArray(v)) {
        const plain = v.filter((x) => typeof x !== "object" || x === null);
        if (plain.length) m.filters.push({ path: p.join("."), op: "equals", values: plain.map(String) });
        for (const x of v.filter((x) => x && typeof x === "object")) {
          const [[op, arg]] = Object.entries(x as Record<string, unknown>);
          if (op === "exists") m.filters.push({ path: p.join("."), op: arg ? "exists" : "not-exists", values: [] });
          else if (op === "anything-but" && (typeof arg !== "object" || Array.isArray(arg))) m.filters.push({ path: p.join("."), op, values: (Array.isArray(arg) ? arg : [arg]).map(String) });
          else if (["prefix", "suffix", "wildcard", "equals-ignore-case"].includes(op) && typeof arg === "string") m.filters.push({ path: p.join("."), op: op as Op, values: [arg] });
          else if (op === "numeric" && Array.isArray(arg) && arg.length === 2) m.filters.push({ path: p.join("."), op: arg[0] as Op, values: [String(arg[1])] });
          else return false;
        }
      } else if (v && typeof v === "object") {
        if (!walk(v as Record<string, unknown>, p)) return false;
      } else return false;
    }
    return true;
  };
  return walk(doc, []) ? m : null;
}

/** "S3 uploads to the uploads bucket under images/ larger than 1000" → a model. */
function draft(text: string): Model | null {
  const t = text.toLowerCase();
  const src = EVENT_SOURCES.find((s) => t.includes(s.label.toLowerCase()) || t.includes(s.source)) ?? (/\b(upload|object|bucket)/.test(t) ? sourceInfo("aws.s3") : /\b(instance|ec2)\b/.test(t) ? sourceInfo("aws.ec2") : /\balarm/.test(t) ? sourceInfo("aws.cloudwatch") : /\b(api call|cloudtrail)\b/.test(t) ? sourceInfo("aws.iam") : undefined);
  if (!src) return null;
  const type =
    src.types.find((ty) => ty.detailType.toLowerCase().split(/\W+/).some((w) => w.length > 3 && t.includes(w))) ??
    (/\b(delete|removed)/.test(t) ? src.types.find((ty) => /Deleted|Terminate/.test(ty.detailType)) : undefined) ??
    src.types[0];
  const filters: Filter[] = [];
  const quoted = [...text.matchAll(/["“']([^"”']+)["”']/g)].map((m) => m[1]);
  for (const f of type.fields) {
    const leaf = f.path.split(".").pop()!.toLowerCase().replace(/name$/, "");
    const near = t.match(new RegExp(`\\b${leaf.replace(/[-.]/g, "\\W?")}\\w*\\s+(?:is\\s+|named\\s+|called\\s+)?([\\w./:-]+)`));
    const before = t.match(new RegExp(`\\b([\\w.-]+)\\s+${leaf}\\b`));
    if (f.numeric) {
      const cmp = t.match(/\b(more than|over|above|larger than|bigger than|greater than|at least|under|below|less than|smaller than|at most)\s+(\d+(?:\.\d+)?)/);
      if (cmp) {
        const op: Op = /at least/.test(cmp[1]) ? ">=" : /at most/.test(cmp[1]) ? "<=" : /under|below|less|smaller/.test(cmp[1]) ? "<" : ">";
        filters.push({ path: f.path, op, values: [cmp[2]] });
      }
    } else if (near && !["the", "a", "an", "is", "to", "in", "of", "for"].includes(near[1])) filters.push({ path: f.path, op: "equals", values: [near[1]] });
    else if (before && !["the", "a", "an", "my", "any"].includes(before[1]) && leaf.length > 3) filters.push({ path: f.path, op: "equals", values: [before[1]] });
  }
  const prefix = t.match(/\b(?:under|in folder|with prefix|starting with|prefix)\s+([\w./-]+)/);
  const keyField = type.fields.find((f) => /key|name$/.test(f.path) && f.path.includes("object"));
  if (prefix && keyField) filters.push({ path: keyField.path, op: "prefix", values: [prefix[1]] });
  const suffix = t.match(/\b(?:ending in|ending with|with extension|suffix)\s+([\w.]+)/) ?? t.match(/\b(\.(?:png|jpe?g|csv|json|zip|pdf|txt|parquet))\b/);
  if (suffix && keyField) filters.push({ path: keyField.path, op: "suffix", values: [suffix[1]] });
  for (const q of quoted) if (!filters.some((f) => f.values.includes(q)) && type.fields[0]) filters.push({ path: type.fields[0].path, op: "equals", values: [q] });
  // State words ("stopped", "alarm", "failed") for fields that hold one.
  const stateField = type.fields.find((f) => /state|status|lastStatus/i.test(f.path));
  const state = t.match(/\b(stopped|stopping|running|terminated|pending|alarm|ok|insufficient_data|failed|succeeded|timed_out|aborted)\b/);
  if (stateField && state && !filters.some((f) => f.path === stateField.path)) filters.push({ path: stateField.path, op: "equals", values: [/[a-z]/.test(stateField.example) && stateField.example === stateField.example.toLowerCase() ? state[1] : state[1].toUpperCase()] });
  return { sources: [src.source], types: [type.detailType], filters };
}

function sampleEvent(m: Model): string {
  const src = m.sources[0] ?? "my.app";
  const info = sourceInfo(src);
  const type = info?.types.find((t) => t.detailType === m.types[0]) ?? info?.types[0];
  return JSON.stringify(
    { version: "0", id: "6a7e8feb-b491-4cf7-a9f1-bf3703467718", "detail-type": m.types[0] ?? type?.detailType ?? "Event", source: src, account: "123456789012", time: "2026-11-10T12:00:00Z", region: "us-east-1", resources: [], detail: type?.detail ?? {} },
    null,
    2,
  );
}

function Chip({ label, icon, remove }: { label: string; icon?: string; remove: () => void }) {
  return (
    <span className="policy-chip" title={label}>
      {icon && <img src={iconUrl(icon)} alt="" width={14} height={14} />}
      <span className="mono">{label}</span>
      <button type="button" aria-label={`Remove ${label}`} onClick={remove}>
        <X size={12} aria-hidden />
      </button>
    </span>
  );
}

export function EventPatternEditor({ name = "pattern", label = "Event pattern", rule, defaultValue, required, rows = 6 }: { name?: string; label?: string; rule?: Rule; defaultValue?: string; required?: boolean; rows?: number }) {
  const area = useRef<HTMLTextAreaElement>(null);
  const initial = useMemo(() => parse(defaultValue ?? ""), [defaultValue]);
  const [mode, setMode] = useState<"visual" | "json">(initial ? "visual" : "json");
  const [model, setModel] = useState<Model>(initial ?? { sources: [], types: [], filters: [] });
  const [custom, setCustom] = useState("");
  const [intent, setIntent] = useState("");
  const [sample, setSample] = useState<string | null>(null);
  const [result, setResult] = useState<{ match?: boolean; error?: string } | null>(null);
  const [, start] = useTransition();
  const [problem, setProblem] = useState<string | null>(null);

  const write = (m: Model) => {
    setModel(m);
    if (area.current) setControlValue(area.current, serialize(m));
  };

  const event = sample ?? sampleEvent(model);
  const pattern = serialize(model);
  // EventBridge tests the pattern on the sample, a moment after the last change.
  useEffect(() => {
    if (mode !== "visual" || pattern === "{}") {
      setResult(null);
      return;
    }
    const t = setTimeout(() => start(async () => setResult(await testPatternLive(pattern, event))), 350);
    return () => clearTimeout(t);
  }, [pattern, event, mode]);

  const source = sourceInfo(model.sources[0] ?? "");
  const types = model.sources.flatMap((s) => sourceInfo(s)?.types ?? []);
  const fields: EventField[] = types.filter((t) => !model.types.length || model.types.includes(t.detailType)).flatMap((t) => t.fields);
  const drafted = intent.trim().length > 3 ? draft(intent) : null;

  return (
    <div className="policy-editor pattern-editor" data-mode={mode}>
      <div className="policy-head">
        <span className="field-label">{label}</span>
        <span className="segments-mini" role="tablist" aria-label="Editor">
          <button
            type="button"
            role="tab"
            aria-selected={mode === "visual"}
            aria-pressed={mode === "visual"}
            onClick={() => {
              const m = parse(area.current?.value ?? "");
              if (!m) return setProblem("This pattern uses operators the builder does not show; edit it as JSON.");
              setProblem(null);
              setModel(m);
              setMode("visual");
            }}
          >
            <LayoutList size={14} aria-hidden /> Visual
          </button>
          <button type="button" role="tab" aria-selected={mode === "json"} aria-pressed={mode === "json"} onClick={() => setMode("json")}>
            <Braces size={14} aria-hidden /> JSON
          </button>
        </span>
      </div>
      {problem && mode === "json" && <span className="field-hint">{problem}</span>}
      {mode === "visual" && (
        <div className="policy-statements">
          <div className="policy-assistant">
            <span className="policy-assistant-input">
              <Sparkles size={15} aria-hidden />
              <input
                value={intent}
                onChange={(e) => setIntent(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    if (drafted) {
                      write(drafted);
                      setSample(null);
                      setIntent("");
                    }
                  }
                }}
                placeholder="S3 uploads to the uploads bucket ending in .png"
                aria-label="Describe the events"
                spellCheck={false}
                data-testid="pattern-assistant"
              />
              {drafted && (
                <button
                  type="button"
                  className="repair"
                  data-kind="generate"
                  onClick={() => {
                    write(drafted);
                    setSample(null);
                    setIntent("");
                  }}
                >
                  <Plus size={12} aria-hidden /> Use it
                </button>
              )}
            </span>
            {drafted && (
              <span className="policy-notes">
                <span>{sourceInfo(drafted.sources[0])?.label}</span>
                <span>{drafted.types[0]}</span>
                {drafted.filters.map((f) => (
                  <span key={f.path + f.op + f.values.join()}>
                    {f.path.replace(/^detail\./, "")} {OPS.find((o) => o.id === f.op)?.label} {f.values.join(", ")}
                  </span>
                ))}
              </span>
            )}
          </div>
          <div className="policy-statement" data-effect="Allow">
            <div className="policy-row">
              <span className="policy-row-label">Source</span>
              <div className="policy-row-body">
                <span className="policy-chips">
                  {model.sources.map((s) => (
                    <Chip key={s} label={s} icon={sourceInfo(s)?.icon} remove={() => write({ ...model, sources: model.sources.filter((x) => x !== s), types: model.types.filter((t) => !sourceInfo(s)?.types.some((ty) => ty.detailType === t)) })} />
                  ))}
                </span>
                <span className="pattern-sources" role="group" aria-label="Event sources">
                  {EVENT_SOURCES.filter((s) => !model.sources.includes(s.source)).map((s) => (
                    <button key={s.source} type="button" className="pattern-source" title={s.source} onClick={() => write({ ...model, sources: [...model.sources, s.source] })} data-testid={`pattern-source-${s.source}`}>
                      <img src={iconUrl(s.icon)} alt="" width={18} height={18} />
                      <span>{s.label}</span>
                    </button>
                  ))}
                  <input
                    value={custom}
                    onChange={(e) => setCustom(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && custom.trim()) {
                        e.preventDefault();
                        write({ ...model, sources: [...new Set([...model.sources, custom.trim()])] });
                        setCustom("");
                      }
                    }}
                    placeholder="other.source ↵"
                    aria-label="Another source"
                    spellCheck={false}
                  />
                </span>
              </div>
            </div>
            {types.length > 0 && (
              <div className="policy-row">
                <span className="policy-row-label">Detail type</span>
                <div className="policy-row-body">
                  <span className="repairs">
                    {types.map((t) => {
                      const on = model.types.includes(t.detailType);
                      return (
                        <button
                          key={t.detailType}
                          type="button"
                          className="repair"
                          aria-pressed={on}
                          data-on={on ? "" : undefined}
                          onClick={() => write({ ...model, types: on ? model.types.filter((x) => x !== t.detailType) : [...model.types, t.detailType] })}
                        >
                          {on ? <CircleCheck size={12} aria-hidden /> : <Plus size={12} aria-hidden />} {t.detailType}
                        </button>
                      );
                    })}
                  </span>
                </div>
              </div>
            )}
            <div className="policy-row">
              <span className="policy-row-label">Filters</span>
              <div className="policy-row-body">
                {model.filters.map((f, i) => {
                  const set = (p: Partial<Filter>) => write({ ...model, filters: model.filters.map((x, j) => (j === i ? { ...x, ...p } : x)) });
                  const op = OPS.find((o) => o.id === f.op)!;
                  return (
                    <span key={i} className="policy-condition">
                      <input list="pattern-fields" value={f.path} onChange={(e) => set({ path: e.target.value })} aria-label="Field" placeholder="detail.state" spellCheck={false} />
                      <select value={f.op} onChange={(e) => set({ op: e.target.value as Op })} aria-label="Operator">
                        {OPS.map((o) => (
                          <option key={o.id} value={o.id}>
                            {o.label}
                          </option>
                        ))}
                      </select>
                      {op.novalue ? (
                        <span />
                      ) : (
                        <input
                          value={f.values.join(", ")}
                          inputMode={op.numeric ? "decimal" : undefined}
                          onChange={(e) => set({ values: e.target.value.split(",").map((v) => v.trim()).filter((v, k, a) => v || k === a.length - 1) })}
                          aria-label="Values"
                          placeholder={fields.find((x) => x.path === f.path)?.example ?? "value, value"}
                          spellCheck={false}
                        />
                      )}
                      <button type="button" className="icon-button plain" aria-label="Remove filter" onClick={() => write({ ...model, filters: model.filters.filter((_, j) => j !== i) })}>
                        <X size={14} aria-hidden />
                      </button>
                    </span>
                  );
                })}
                <span className="repairs">
                  {fields
                    .filter((f) => !model.filters.some((x) => x.path === f.path))
                    .slice(0, 6)
                    .map((f) => (
                      <button key={f.path} type="button" className="repair" data-kind="suggest" onClick={() => write({ ...model, filters: [...model.filters, { path: f.path, op: "equals", values: [f.example] }] })}>
                        <Plus size={12} aria-hidden /> {f.path.replace(/^detail\./, "")}
                      </button>
                    ))}
                  <button type="button" className="repair" onClick={() => write({ ...model, filters: [...model.filters, { path: "detail.", op: "equals", values: [""] }] })}>
                    <Plus size={12} aria-hidden /> Other field
                  </button>
                </span>
                <datalist id="pattern-fields">
                  {fields.map((f) => (
                    <option key={f.path} value={f.path} />
                  ))}
                </datalist>
              </div>
            </div>
          </div>
          {result && (
            <details className="pattern-test" data-match={result.error ? "error" : result.match ? "yes" : "no"}>
              <summary>
                {result.error ? <CircleSlash size={14} aria-hidden /> : result.match ? <CircleCheck size={14} aria-hidden /> : <CircleSlash size={14} aria-hidden />}
                {result.error ?? (result.match ? `A sample ${source?.label ?? ""} event matches` : `The sample ${source?.label ?? ""} event does not match`)}
              </summary>
              <textarea className="code-editor" rows={8} value={event} onChange={(e) => setSample(e.target.value)} aria-label="Sample event" spellCheck={false} />
            </details>
          )}
        </div>
      )}
      <FieldShell label={label} rule={rule} member="EventPattern" format="eventPattern">
        <textarea
          ref={area}
          name={name}
          rows={rows}
          required={required}
          aria-label={label}
          className={mode === "json" ? "code-editor" : "code-editor policy-json-hidden"}
          spellCheck={false}
          defaultValue={defaultValue}
          placeholder='{"source": ["my.app"]}'
          tabIndex={mode === "json" ? undefined : -1}
          onInvalid={() => setMode("json")}
        />
      </FieldShell>
    </div>
  );
}
