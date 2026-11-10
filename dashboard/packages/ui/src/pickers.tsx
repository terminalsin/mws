"use client";

// Searchable pickers for fields that take a resource: a role ARN, a key, a
// queue, a subnet. The control is still a plain text input (so `Field`
// validates it, forms submit it and anything can be pasted), with a list of
// the real resources from MWS under it, filtered as you type, and a "New
// ..." row that makes one from the typed name where a name is all it takes.
//
//   <Field label="Execution role" format="arn">
//     <ResourcePicker kind="iam-role" service="lambda.amazonaws.com" name="role" required />
//   </Field>

import { Check, Loader2, Plus, Search } from "lucide-react";
import { useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type ChangeEvent, type KeyboardEvent } from "react";

import { iconUrl } from "./catalog";
import { setControlValue } from "./fields";
import { RESOURCE_KINDS, optionValue, optionValues, type ResourceKind, type ResourceOption, type ResourceValue } from "./resources";

// ---------------------------------------------------------------------------
// Loading, shared by every picker on the page.

const lists = new Map<string, { at: number; items: Promise<ResourceOption[]> }>();
const TTL = 5_000;

function fetchKinds(kinds: ResourceKind[], fresh = false): Promise<ResourceOption[]> {
  const key = [...kinds].sort().join(",");
  const hit = lists.get(key);
  if (!fresh && hit && Date.now() - hit.at < TTL) return hit.items;
  const items = fetch(`/api/resources?kind=${encodeURIComponent(key)}`, { cache: "no-store" })
    .then((r) => (r.ok ? r.json() : { items: [] }))
    .then((j: { items?: ResourceOption[] }) => j.items ?? [])
    .catch(() => [] as ResourceOption[]);
  lists.set(key, { at: Date.now(), items });
  return items;
}

function forget(kind: ResourceKind) {
  for (const key of [...lists.keys()]) if (key.split(",").includes(kind)) lists.delete(key);
}

/** The resources of these kinds, loaded when `active` first turns true. */
export function useResources(kinds: ResourceKind[], active = true) {
  const key = kinds.join(",");
  const [items, setItems] = useState<ResourceOption[] | null>(null);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!active || !key) return;
    let live = true;
    fetchKinds(key.split(",") as ResourceKind[], tick > 0).then((i) => live && setItems(i));
    return () => {
      live = false;
    };
  }, [key, active, tick]);
  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { items, reload, setItems };
}

// ---------------------------------------------------------------------------
// Recently picked values, per kind, in this browser (a convenience only).

const RECENT = (kind: string) => `mws:picker:recent:${kind}`;

function recentValues(kinds: ResourceKind[]): string[] {
  try {
    return kinds.flatMap((k) => JSON.parse(localStorage.getItem(RECENT(k)) ?? "[]") as string[]);
  } catch {
    return [];
  }
}

function remember(kind: ResourceKind, value: string) {
  try {
    const list = [value, ...(JSON.parse(localStorage.getItem(RECENT(kind)) ?? "[]") as string[]).filter((v) => v !== value)].slice(0, 5);
    localStorage.setItem(RECENT(kind), JSON.stringify(list));
  } catch {
    /* storage unavailable */
  }
}

// ---------------------------------------------------------------------------
// Matching.

function score(o: ResourceOption, q: string): number {
  if (!q) return 1;
  const name = o.name.toLowerCase();
  if (name === q) return 100;
  if (name.startsWith(q)) return 60;
  const values = optionValues(o).map((v) => v.toLowerCase());
  if (values.some((v) => v === q)) return 90;
  if (name.includes(q)) return 40;
  if (values.some((v) => v.includes(q))) return 25;
  if (o.detail?.toLowerCase().includes(q)) return 10;
  // Every word somewhere ("lambda exec" finds lambda-execution-role).
  const words = q.split(/[\s/:_-]+/).filter(Boolean);
  const hay = `${name} ${values.join(" ")} ${o.detail ?? ""}`.toLowerCase();
  return words.length > 1 && words.every((w) => hay.includes(w)) ? 5 : 0;
}

const MAX = 60;

// ---------------------------------------------------------------------------
// The picker.

export interface ResourcePickerProps {
  /** What to list; several kinds for fields that take any of them (a rule target). */
  kind: ResourceKind | ResourceKind[];
  name: string;
  /** The value the field takes (the kind's usual one when left out). */
  use?: ResourceValue;
  defaultValue?: string;
  /** Controlled use: the current value and its setter. */
  value?: string;
  onValueChange?: (value: string, option?: ResourceOption) => void;
  required?: boolean;
  placeholder?: string;
  autoFocus?: boolean;
  disabled?: boolean;
  /** Several values, separated by commas (or `separator`). */
  multiple?: boolean;
  separator?: string;
  /** Roles: the service principal the role should trust. Matching roles
   * come first, and a new role trusts it. */
  service?: string;
  /** Only resources in this VPC (subnets, security groups, instances). */
  vpc?: string;
  /** Hide resources whose group or detail says this (e.g. "AWS managed"). */
  exclude?: string;
  /** Offer the "New ..." row (default: when the kind supports it). */
  create?: boolean;
  /** Also offer these values first, e.g. "*" or an AWS managed alias. */
  extra?: { value: string; label: string; detail?: string }[];
  id?: string;
  testId?: string;
  "aria-label"?: string;
}

type Row = { option: ResourceOption; value: string; recent?: boolean } | { extra: { value: string; label: string; detail?: string } };

export function ResourcePicker(props: ResourcePickerProps) {
  const {
    kind,
    name,
    use,
    defaultValue,
    value: controlled,
    onValueChange,
    required,
    placeholder,
    autoFocus,
    disabled,
    multiple,
    separator = ",",
    service,
    vpc,
    exclude,
    extra,
    id,
    testId,
  } = props;
  const kinds = useMemo(() => (Array.isArray(kind) ? kind : [kind]), [kind]);
  const first = RESOURCE_KINDS[kinds[0]];
  const creatable = kinds.length === 1 && !!first.create && props.create !== false;
  const input = useRef<HTMLInputElement>(null);
  const pop = useRef<HTMLDivElement>(null);
  const listId = useId();
  const [open, setOpen] = useState(false);
  const [touched, setTouched] = useState(false);
  const { items, setItems } = useResources(kinds, touched);
  const [own, setOwn] = useState(defaultValue ?? "");
  const value = controlled ?? own;
  const [active, setActive] = useState(0);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recent, setRecent] = useState<string[]>([]);
  useEffect(() => {
    if (open) setRecent(recentValues(kinds));
  }, [open, kinds]);

  const parts = multiple ? value.split(separator) : [value];
  const query = (parts.at(-1) ?? "").trim();
  const chosen = new Set(parts.map((p) => p.trim()).filter(Boolean));

  const valueOf = useCallback((o: ResourceOption) => optionValue(o, kinds.length === 1 ? use : undefined), [kinds.length, use]);

  // The resource the value names, for the icon in the field.
  const match = useMemo(() => {
    if (multiple || !items || !value) return undefined;
    return items.find((o) => optionValues(o).includes(value.trim()));
  }, [items, value, multiple]);

  const rows = useMemo(() => {
    const q = query.toLowerCase();
    const pool = (items ?? []).filter((o) => (!vpc || !o.vpc || o.vpc === vpc) && (!exclude || (o.group !== exclude && o.detail !== exclude)));
    // A value already picked should not filter the list down to itself.
    const exact = !multiple && pool.some((o) => valueOf(o) === query);
    const ranked = pool
      .map((o) => ({ o, s: exact ? 1 : score(o, q) }))
      .filter((r) => r.s > 0)
      .sort((a, b) => {
        if (service) {
          const sa = a.o.services?.includes(service) ? 1 : 0;
          const sb = b.o.services?.includes(service) ? 1 : 0;
          if (sa !== sb) return sb - sa;
        }
        return b.s - a.s || a.o.name.localeCompare(b.o.name);
      })
      .slice(0, MAX)
      .map(({ o }) => ({ option: o, value: valueOf(o) }) as { option: ResourceOption; value: string; recent?: boolean });
    // With nothing typed, what was picked lately comes first.
    if (!q || exact) {
      const lately = recent.map((v) => ranked.find((r) => r.value === v)).filter((r): r is (typeof ranked)[number] => !!r);
      if (lately.length && ranked.length > 4) {
        const rest = ranked.filter((r) => !lately.includes(r));
        ranked.splice(0, ranked.length, ...lately.map((r) => ({ ...r, recent: true })), ...rest);
      }
    }
    const extras = (extra ?? []).filter((e) => exact || !q || e.value.toLowerCase().includes(q) || e.label.toLowerCase().includes(q)).map((e) => ({ extra: e }));
    return [...extras, ...ranked] as Row[];
  }, [items, query, vpc, exclude, extra, service, multiple, valueOf, recent]);

  const groupOf = useCallback(
    (r: Row) => {
      if ("extra" in r) return "";
      if (r.recent) return "Recent";
      const o = r.option;
      if (service && o.kind === "iam-role") return o.services?.includes(service) ? `Trusts ${service}` : "Other roles";
      if (kinds.length > 1) return RESOURCE_KINDS[o.kind].noun.replace(/^./, (c) => c.toUpperCase()) + "s";
      return o.group ?? "";
    },
    [service, kinds.length],
  );

  const pattern = first.create?.pattern ? new RegExp(first.create.pattern) : null;
  const canCreate =
    creatable && !!query && !query.startsWith("arn:") && (!pattern || pattern.test(query)) && !(items ?? []).some((o) => o.name === query || optionValues(o).includes(query));
  const count = rows.length + (canCreate ? 1 : 0);

  useEffect(() => setActive(0), [query, open]);

  // The list floats in the top layer, so a sheet's scroll box never clips it.
  const place = useCallback(() => {
    const el = input.current;
    const p = pop.current;
    if (!el || !p) return;
    const r = el.getBoundingClientRect();
    const below = window.innerHeight - r.bottom;
    const up = below < 240 && r.top > below;
    p.style.left = `${r.left}px`;
    p.style.width = `${Math.max(r.width, 280)}px`;
    p.style.maxHeight = `${Math.min(320, (up ? r.top : below) - 12)}px`;
    p.style.top = up ? "" : `${r.bottom + 2}px`;
    p.style.bottom = up ? `${window.innerHeight - r.top + 2}px` : "";
  }, []);

  useLayoutEffect(() => {
    const p = pop.current;
    if (!p) return;
    if (open && !p.matches(":popover-open")) {
      try {
        p.showPopover();
      } catch {
        /* not connected yet */
      }
    }
    if (!open && p.matches(":popover-open")) p.hidePopover();
    if (!open) return;
    place();
    const onMove = () => place();
    window.addEventListener("resize", onMove);
    window.addEventListener("scroll", onMove, true);
    return () => {
      window.removeEventListener("resize", onMove);
      window.removeEventListener("scroll", onMove, true);
    };
  }, [open, place, rows.length]);

  const write = (next: string, option?: ResourceOption) => {
    const el = input.current;
    if (controlled === undefined) setOwn(next);
    if (el) setControlValue(el, next);
    onValueChange?.(next, option);
  };

  const pick = (v: string, option?: ResourceOption) => {
    if (option) remember(option.kind, v);
    if (multiple) {
      const kept = parts.slice(0, -1).map((p) => p.trim()).filter(Boolean);
      const next = kept.includes(v) ? kept.filter((k) => k !== v) : [...kept, v];
      write(next.join(`${separator} `) + (next.length ? `${separator} ` : ""), option);
      input.current?.focus();
      return;
    }
    write(v, option);
    setOpen(false);
  };

  const create = async () => {
    setCreating(true);
    setError(null);
    try {
      const res = await fetch("/api/resources", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ kind: kinds[0], name: query, service }) });
      const j = (await res.json()) as { item?: ResourceOption; error?: string };
      if (!j.item) throw new Error(j.error ?? "Could not create it");
      forget(kinds[0]);
      setItems((list) => [j.item!, ...(list ?? [])]);
      pick(valueOf(j.item), j.item);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setCreating(false);
    }
  };

  const choose = (i: number) => {
    if (i < rows.length) {
      const r = rows[i];
      if ("extra" in r) pick(r.extra.value);
      else pick(r.value, r.option);
    } else if (canCreate) void create();
  };

  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (!open) {
        setTouched(true);
        setOpen(true);
        return;
      }
      if (!count) return;
      setActive((a) => (a + (e.key === "ArrowDown" ? 1 : -1) + count) % count);
    } else if (e.key === "Enter" && open && count && (query || multiple)) {
      e.preventDefault();
      choose(active);
    } else if (e.key === "Escape" && open) {
      e.preventDefault();
      e.stopPropagation();
      setOpen(false);
    } else if (e.key === "Tab") {
      setOpen(false);
    }
  };

  useEffect(() => {
    pop.current?.querySelector<HTMLElement>(`[data-index="${active}"]`)?.scrollIntoView({ block: "nearest" });
  }, [active]);

  const onChange = (e: ChangeEvent<HTMLInputElement>) => {
    if (controlled === undefined) setOwn(e.target.value);
    onValueChange?.(e.target.value);
    setError(null);
    if (!open) setOpen(true);
  };

  const icon = match ? RESOURCE_KINDS[match.kind].icon : first.icon;
  let lastGroup = "\u0000";
  return (
    <span className="picker" data-testid={testId} data-matched={match ? "" : undefined}>
      <img className="picker-icon" src={iconUrl(icon)} alt="" width={18} height={18} aria-hidden />
      <input
        ref={input}
        id={id}
        name={name}
        role="combobox"
        aria-expanded={open}
        aria-controls={listId}
        aria-autocomplete="list"
        aria-activedescendant={open && count ? `${listId}-${active}` : undefined}
        aria-label={props["aria-label"]}
        autoComplete="off"
        spellCheck={false}
        value={value}
        onChange={onChange}
        onFocus={() => {
          setTouched(true);
          setOpen(true);
        }}
        onClick={() => setOpen(true)}
        onBlur={(e) => {
          if (!pop.current?.contains(e.relatedTarget as Node)) setOpen(false);
        }}
        onKeyDown={onKey}
        required={required}
        placeholder={placeholder ?? `Search ${kinds.map((k) => RESOURCE_KINDS[k].noun + "s").join(", ")} or paste ${use === "name" || (!use && first.value === "name") ? "a name" : use === "id" || (!use && first.value === "id") ? "an ID" : "an ARN"}`}
        autoFocus={autoFocus}
        disabled={disabled}
      />
      {match && match.name !== value && <span className="picker-name">{match.name}</span>}
      <div
        ref={pop}
        popover="manual"
        className="picker-pop"
        id={listId}
        role="listbox"
        aria-multiselectable={multiple || undefined}
        onMouseDown={(e) => e.preventDefault()}
        tabIndex={-1}
      >
        {items === null ? (
          <div className="picker-empty">
            <Loader2 size={14} className="spin" aria-hidden /> Loading {first.noun}s…
          </div>
        ) : null}
        {rows.map((r, i) => {
          const g = groupOf(r);
          const head = g !== lastGroup && g ? <div className="picker-group">{g}</div> : null;
          lastGroup = g;
          const v = "extra" in r ? r.extra.value : r.value;
          const label = "extra" in r ? r.extra.label : r.option.name;
          const detail = "extra" in r ? r.extra.detail : r.option.detail;
          const selected = chosen.has(v);
          const kindIcon = "extra" in r ? first.icon : RESOURCE_KINDS[r.option.kind].icon;
          return (
            <div key={`${v}|${i}`} style={{ display: "contents" }}>
              {head}
              <div
                id={`${listId}-${i}`}
                data-index={i}
                role="option"
                aria-selected={selected}
                className="picker-row"
                data-active={i === active ? "" : undefined}
                onMouseEnter={() => setActive(i)}
                onClick={() => choose(i)}
                title={v}
              >
                <img src={iconUrl(kindIcon)} alt="" width={18} height={18} aria-hidden />
                <span className="picker-row-text">
                  <span className="picker-row-name">{label}</span>
                  {detail && <span className="picker-row-detail">{detail}</span>}
                </span>
                {selected && <Check size={14} className="picker-check" aria-label="Selected" />}
              </div>
            </div>
          );
        })}
        {items !== null && rows.length === 0 && !canCreate && (
          <div className="picker-empty">
            <Search size={14} aria-hidden />
            {query ? `No ${first.noun} matches. The value is used as typed.` : creatable ? `No ${first.noun}s yet. Type a name to create one.` : `No ${first.noun}s in this Region.`}
          </div>
        )}
        {canCreate && (
          <div
            id={`${listId}-${rows.length}`}
            data-index={rows.length}
            role="option"
            aria-selected={false}
            className="picker-row picker-create"
            data-active={active === rows.length ? "" : undefined}
            onMouseEnter={() => setActive(rows.length)}
            onClick={() => void create()}
            data-testid={testId ? `${testId}-create` : undefined}
          >
            {creating ? <Loader2 size={16} className="spin" aria-hidden /> : <Plus size={16} aria-hidden />}
            <span className="picker-row-text">
              <span className="picker-row-name">
                {first.create!.label} <b>{query}</b>
              </span>
              <span className="picker-row-detail">{error ?? (service && kinds[0] === "iam-role" ? `Trusts ${service}` : first.create!.hint)}</span>
            </span>
          </div>
        )}
        {error && !canCreate && <div className="picker-empty picker-error">{error}</div>}
      </div>
    </span>
  );
}
