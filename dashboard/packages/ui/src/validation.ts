// Field validation for the console's forms, and the repairs it offers.
//
// A field's rule comes from three places, merged in this order:
//   1. the Smithy model MWS serves (`@mws-dashboard/ui/model/<model>`, made
//      by scripts/constraints.mjs): required, length, pattern, range, enum;
//   2. the control's own attributes (required, maxLength, min, type=...);
//   3. what the page knows on top: a `format` (json, arn, cidr, ...), names
//      that are `taken`, a `generate` recipe.
// `check` returns the first problem with a short message and the repairs
// that would fix it: a corrected value ("fix"), close matches ("suggest")
// or a fresh valid value ("generate"). Every repair is checked against the
// whole rule before it is offered, so clicking one always clears the issue.
//
// Errors MWS returns after a submission are AWS validation messages
// (`Value 'x' at 'queueName' failed to satisfy constraint: ...`);
// `parseServerIssues` turns them back into rules, so a backend error gets
// the same inline message and repairs as a client-side check.
//
// Pure functions only: this module is shared by server actions and the
// browser.

/** A member's constraints, as generated from the model or written by hand. */
export interface Rule {
  type?:
    | "string"
    | "integer"
    | "number"
    | "boolean"
    | "timestamp"
    | "blob"
    | "document"
    | "structure"
    | "union"
    | "list"
    | "set"
    | "map";
  required?: boolean;
  minLength?: number;
  maxLength?: number;
  min?: number;
  max?: number;
  /** Smithy semantics: ECMA 262, unanchored (write ^...$ to anchor). */
  pattern?: string;
  enum?: string[];
  sensitive?: boolean;
  default?: string | number | boolean;
  /** What a number counts, so "12h" or "256 KiB" convert to it and ranges
   * read as durations or sizes. */
  unit?: Unit;
  /** A console-side format with its own checks and repairs. */
  format?: Format;
  /** For `format: "arn"`: the ARN a bare name expands to, with `{}` where
   * the name goes, e.g. `arn:aws:iam::123456789012:role/{}`. */
  arn?: string;
  /** Values that already exist (a create form's name field). */
  taken?: string[];
  /** `taken` ignores case (the service treats `Alice` and `alice` as the
   * same name, as Identity Store does). */
  takenIgnoreCase?: boolean;
  /** Prefixes AWS keeps for itself (`alias/aws/`, `aws:`): a value starting
   * with one is offered without it. */
  reserved?: string[];
  /** Values the field usually refers to (existing roles, keys, queues):
   * close ones are offered when a value is rejected as unknown. */
  known?: string[];
  /** How to make a fresh valid value when the field is empty or taken. */
  generate?: Generate;
  /** Overrides the message for a pattern mismatch (the model's patterns
   * read badly as text). */
  hint?: string;
  /** Nested members (structures), list items and map keys/values. */
  fields?: Rules;
  item?: Rule;
  key?: Rule;
  value?: Rule;
}

export type Rules = Record<string, Rule>;

export type Unit = "seconds" | "bytes";

export type Format =
  | "json"
  | "list"
  | "yaml"
  | "keyvalue"
  | "policy"
  | "path"
  | "arn"
  | "cidr"
  | "ipv4"
  | "email"
  | "emails"
  | "domain"
  | "email-or-domain"
  | "url"
  | "s3url"
  | "bucket"
  | "name"
  | "port"
  | "country"
  | "csr"
  | "phone"
  | "pairs"
  | "tags"
  | "branch"
  | "dir";

/** "name": a readable resource name; "token": random letters and digits;
 * "password": meets the usual complexity rules; or a fixed prefix/suffix
 * around a readable name. */
export type Generate = "name" | "token" | "password" | "uuid" | "account" | { prefix?: string; suffix?: string; kind?: "name" | "token" };

export type IssueCode =
  | "required"
  | "tooShort"
  | "tooLong"
  | "pattern"
  | "enum"
  | "range"
  | "type"
  | "format"
  | "taken"
  | "reserved"
  | "missing"
  | "server";

export interface Repair {
  /** The value the field takes when the repair is applied. */
  value: string;
  /** What the repair does, for its tooltip and accessible name. */
  label: string;
  kind: "fix" | "suggest" | "generate";
}

export interface Issue {
  code: IssueCode;
  message: string;
  repairs: Repair[];
}

/** An error the server reported against one field (in `ActionResult.issues`). */
export interface FieldIssue {
  /** The form field's name, when the action knows it. */
  field?: string;
  /** The API member path (`queueName`, `Tags.1.member.Key`). */
  member?: string;
  /** The value the server rejected, when it said. */
  value?: string;
  /** The constraint it failed, as a rule, so the field can offer repairs. */
  rule?: Rule;
  code: IssueCode;
  message: string;
  /** Repairs the action worked out itself (it knows what the field's value
   * refers to); offered as they are. */
  repairs?: Repair[];
}

// ---------------------------------------------------------------------------
// Merging rules.

/** Combine rules, later ones winning; `taken` lists are joined. */
export function mergeRules(...rules: (Rule | undefined | null | false)[]): Rule {
  const out: Rule = {};
  for (const r of rules) {
    if (!r) continue;
    for (const [k, v] of Object.entries(r) as [keyof Rule, unknown][]) {
      if (v === undefined) continue;
      if (k === "taken") out.taken = [...(out.taken ?? []), ...(v as string[])];
      else (out as Record<string, unknown>)[k] = v;
    }
  }
  return out;
}

/** The rule at a dotted member path (`VpcConfig.SubnetIds`) of an
 * operation's rules; list indices and `member` segments are skipped. */
export function ruleAt(rules: Rules | undefined, path: string): Rule | undefined {
  let level: Rules | undefined = rules;
  let rule: Rule | undefined;
  for (const segment of memberPath(path)) {
    if (!level) return undefined;
    const key = Object.keys(level).find((k) => k.toLowerCase() === segment);
    if (!key) return undefined;
    rule = level[key];
    while (rule?.item) rule = rule.item;
    level = rule?.fields;
  }
  return rule;
}

/** Normalized member path segments: lowercase, without list indices or the
 * query protocol's `member`/`entry` segments. */
export function memberPath(path: string): string[] {
  return path
    .split(/[.[\]/]+/)
    .filter((s) => s && !/^\d+$/.test(s) && s !== "member" && s !== "entry")
    .map((s) => s.toLowerCase());
}

/** Does a server-reported member path name this field's member? */
export function sameMember(reported: string, member: string): boolean {
  const a = memberPath(reported).join(".");
  const b = memberPath(member).join(".");
  return a === b || (b.length > 0 && a.endsWith("." + b)) || (a.length > 0 && b.endsWith("." + a));
}

// ---------------------------------------------------------------------------
// Checking.

export interface Options {
  /** Skip the `required` check (the field may be filled in later). */
  partial?: boolean;
}

const cache = new Map<string, RegExp | null>();
function regex(pattern: string): RegExp | null {
  if (!cache.has(pattern)) {
    let re: RegExp | null = null;
    try {
      re = new RegExp(pattern, "u");
    } catch {
      try {
        re = new RegExp(pattern);
      } catch {
        re = null;
      }
    }
    cache.set(pattern, re);
  }
  return cache.get(pattern) ?? null;
}

const length = (s: string) => [...s].length;
const isNumeric = (r: Rule) => r.type === "integer" || r.type === "number" || r.format === "port";

/** The first problem with `value` under `rule`, with repairs, or null. */
export function check(value: string, rule: Rule, options: Options = {}): Issue | null {
  const issue = problem(value, rule, options);
  if (!issue) return null;
  return { ...issue, repairs: repairs(value, rule, issue.code) };
}

/** Is `value` acceptable (no issue at all)? */
export function valid(value: string, rule: Rule): boolean {
  return problem(value, rule, {}) === null;
}

function problem(value: string, rule: Rule, options: Options): Omit<Issue, "repairs"> | null {
  if (value === "") {
    if (rule.required && !options.partial) return { code: "required", message: "Required" };
    return null;
  }
  if (isTaken(value, rule)) return { code: "taken", message: "Already exists" };
  const reserved = rule.reserved?.find((p) => value.startsWith(p));
  if (reserved) return { code: "reserved", message: `${reserved} is reserved for AWS` };
  if (rule.enum && rule.enum.length > 0 && !rule.enum.includes(value)) {
    return { code: "enum", message: rule.enum.length <= 4 ? `One of ${rule.enum.join(", ")}` : "Not an allowed value" };
  }
  if (isNumeric(rule) || rule.min !== undefined || rule.max !== undefined) {
    if (isNumeric(rule) || /^-?\d/.test(value)) {
      const n = Number(value);
      const integer = rule.type === "integer" || rule.format === "port";
      if (!/^-?(\d+\.?\d*|\.\d+)(e[-+]?\d+)?$/i.test(value.trim()) || Number.isNaN(n))
        return { code: "type", message: rule.unit && inUnit(value, rule.unit) !== null ? `In ${rule.unit}` : integer ? "Whole number" : "Number" };
      if (integer && !Number.isInteger(n)) return { code: "type", message: "Whole number" };
      const min = rule.min ?? (rule.format === "port" ? 0 : undefined);
      const max = rule.max ?? (rule.format === "port" ? 65535 : undefined);
      const [lo, hi] = [min, max].map((v) => (v === undefined ? "" : amount(v, rule.unit)));
      if (min !== undefined && n < min) return { code: "range", message: max !== undefined ? `${lo}–${hi}` : `At least ${lo}` };
      if (max !== undefined && n > max) return { code: "range", message: min !== undefined ? `${lo}–${hi}` : `At most ${hi}` };
    }
  }
  const len = length(value);
  if (rule.minLength !== undefined && len < rule.minLength)
    return { code: "tooShort", message: `At least ${rule.minLength} character${rule.minLength === 1 ? "" : "s"}` };
  if (rule.maxLength !== undefined && len > rule.maxLength)
    return { code: "tooLong", message: `${len - rule.maxLength} over the ${rule.maxLength}-character limit` };
  if (rule.format) {
    const message = FORMATS[rule.format].check(value, rule);
    if (message) return { code: "format", message };
  }
  if (rule.pattern) {
    const re = regex(rule.pattern);
    if (re && !re.test(value)) return { code: "pattern", message: rule.hint ?? describePattern(rule.pattern) };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Repairs.

const MAX_REPAIRS = 3;

/** Repairs for a value that fails `rule` with `code`: each one valid. */
export function repairs(value: string, rule: Rule, code: IssueCode): Repair[] {
  const out: Repair[] = [];
  const offer = (r: Repair | null | undefined) => {
    if (!r || r.value === value || out.some((o) => o.value === r.value)) return;
    if (!valid(r.value, rule)) return;
    out.push(r);
  };
  switch (code) {
    case "required":
      offer(fresh(rule));
      if (rule.default !== undefined) offer({ value: String(rule.default), label: "Use the default", kind: "fix" });
      if (rule.enum?.length) for (const e of rule.enum.slice(0, MAX_REPAIRS)) offer({ value: e, label: `Use ${e}`, kind: "suggest" });
      break;
    case "taken":
      offer(nextFree(value, rule));
      offer(fresh(rule));
      break;
    case "reserved": {
      const prefix = rule.reserved!.filter((p) => value.startsWith(p)).sort((a, b) => b.length - a.length)[0];
      const rest = value.slice(prefix.length);
      offer({ value: valid(rest, rule) ? rest : (reshape(rest, rule)[0]?.value ?? rest), label: `Drop ${prefix}`, kind: "fix" });
      offer(fresh(rule));
      break;
    }
    case "enum": {
      const near = nearestNumbers(value, rule.enum ?? []);
      if (near) for (const s of near) offer({ value: s, label: `Use ${s}`, kind: "fix" });
      else for (const s of closest(value, rule.enum ?? [])) offer({ value: s, label: `Did you mean ${s}?`, kind: "suggest" });
      break;
    }
    case "type":
    case "range":
      offer(numeric(value, rule));
      break;
    case "format": {
      const format = rule.format && FORMATS[rule.format];
      for (const r of format?.repair?.(value, rule) ?? []) offer(r);
      // Multi-line values (JSON, tags) do not reshape into anything useful,
      // and a list's separators are meaningful (cleanups would join its items).
      if (out.length === 0 && !value.includes("\n") && rule.format !== "list") for (const r of reshape(value, rule).slice(0, 1)) offer(r);
      break;
    }
    case "tooLong":
      // Over-long JSON (a policy document) usually fits once minified.
      if (rule.format === "json") {
        try {
          offer({ value: JSON.stringify(JSON.parse(value)), label: "Minify the JSON", kind: "fix" });
        } catch {
          // Not JSON yet: nothing to minify.
        }
        break;
      }
    // falls through
    default:
      // A value in the right format can still miss the page's pattern (an
      // http:// URL where only https:// is allowed): the format knows the
      // better fix. Otherwise the least invasive cleanup that works; a
      // second one would only be a worse version of it.
      if (rule.format) for (const r of FORMATS[rule.format].repair?.(value, rule) ?? []) offer(r);
      if (out.length === 0) for (const r of reshape(value, rule).slice(0, 1)) offer(r);
      if (out.length === 0 && (code === "tooShort" || code === "pattern")) offer(fresh(rule));
  }
  if (out.length === 0 && code !== "taken") for (const r of didYouMean(value, rule)) offer(r);
  return out.slice(0, MAX_REPAIRS);
}

/** For a number outside a set of allowed numbers (Fargate memory sizes,
 * instance counts): the allowed values just below and above it, nearest
 * first. Null when the value or the set is not numeric. */
export function nearestNumbers(value: string, allowed: string[]): string[] | null {
  const n = Number(value.trim().replace(/[,_\s]/g, ""));
  const nums = allowed.map(Number);
  if (value.trim() === "" || Number.isNaN(n) || nums.length === 0 || nums.some(Number.isNaN)) return null;
  const below = allowed.filter((_, i) => nums[i] < n).sort((a, b) => Number(b) - Number(a))[0];
  const above = allowed.filter((_, i) => nums[i] > n).sort((a, b) => Number(a) - Number(b))[0];
  return [below, above].filter((x): x is string => x !== undefined).sort((a, b) => Math.abs(Number(a) - n) - Math.abs(Number(b) - n));
}

/** Close matches among the values a field usually refers to. */
export function didYouMean(value: string, rule: Rule): Repair[] {
  const known = rule.known ?? [];
  const near = closest(value, known).map((s) => ({ value: s, label: `Did you mean ${s}?`, kind: "suggest" as const }));
  if (near.length || known.length > MAX_REPAIRS) return near;
  // Only a few to choose from: offer them all.
  return known.filter((k) => k !== value).map((s) => ({ value: s, label: `Use ${s}`, kind: "suggest" as const }));
}

/** Cleanups tried in order of how much they change, each checked against
 * the rule: the least invasive valid one is offered first. */
function reshape(value: string, rule: Rule): Repair[] {
  const allowed = allowedChars(rule);
  const sep = allowed ? (["-", "_", ".", ""] as const).find((s) => s === "" || allowed.test(s)) ?? "" : "-";
  const max = rule.maxLength;
  const steps: [string, (v: string) => string][] = [
    ["Trim spaces", (v) => v.trim()],
    ["Replace spaces", (v) => v.trim().replace(/\s+/g, sep)],
    // Names that forbid separators side by side or at the ends ("my-_trail").
    ["Tidy separators", (v) => v.trim().replace(/\s+/g, sep).replace(/([-_.])[-_.]+/g, "$1").replace(/^[-_.]+|[-_.]+$/g, "")],
    ["Lowercase", (v) => v.trim().replace(/\s+/g, sep).toLowerCase()],
    ["Uppercase", (v) => v.trim().replace(/\s+/g, sep).toUpperCase()],
    ["Remove unsupported characters", (v) => clean(v, allowed, sep, false)],
    ["Remove unsupported characters", (v) => clean(v, allowed, sep, true)],
  ];
  const out: Repair[] = [];
  const seen = new Set<string>([value]);
  const push = (label: string, v: string) => {
    if (!v || seen.has(v)) return;
    seen.add(v);
    if (valid(v, rule)) out.push({ value: v, label, kind: "fix" });
  };
  for (const [label, step] of steps) {
    const v = step(value);
    push(label, v);
    if (max !== undefined && length(v) > max) push(`Shorten to ${max} characters`, cut(v, max, sep));
  }
  // A URL scheme the pattern starts with (`^(s3|https|http)://`).
  for (const scheme of schemes(rule.pattern, value)) if (!/^[a-z][\w+.-]*:\/\//i.test(value.trim())) push(`Add ${scheme}://`, `${scheme}://${value.trim().replace(/^\/+/, "")}`);
  // A required literal ending (a FIFO queue's ".fifo") or beginning.
  const literal = literalEnds(rule.pattern);
  for (const v of [...seen]) {
    if (literal.suffix && !v.endsWith(literal.suffix)) push(`Add ${literal.suffix}`, fit(v, max, literal.suffix.length, sep) + literal.suffix);
    if (literal.prefix && !v.startsWith(literal.prefix)) push(`Add ${literal.prefix}`, literal.prefix + v);
  }
  if (max !== undefined && length(value) > max) push(`Shorten to ${max} characters`, cut(value, max, sep));
  // A required first character (most AWS identifiers start with a letter):
  // drop whatever comes before it.
  const lead = rule.pattern?.match(/^\^\(?\[((?:\\.|[^\]\\])+)\]/)?.[1];
  const first = lead && !lead.startsWith("^") ? regex(`^[${lead}]$`) : null;
  if (first) {
    const label = /^(?:a-z|A-Z)+$/.test(lead!) ? "Start with a letter" : "Remove leading characters";
    for (const v of [...seen]) {
      const chars = [...v];
      const i = chars.findIndex((c) => first.test(c));
      if (i > 0) push(label, chars.slice(i).join(""));
    }
  }
  // Hierarchical names (/app/prod/db-host): a missing leading slash, doubled
  // or trailing ones.
  if (allowed?.test("/")) {
    for (const v of [...seen]) push(v.startsWith("/") ? "Tidy the slashes" : "Start with /", "/" + v.split("/").filter(Boolean).join("/"));
  }
  return out;
}

function clean(value: string, allowed: RegExp | null, sep: string, lower: boolean): string {
  let v = value.normalize("NFKD").replace(/[\u0300-\u036f]/g, "").trim();
  if (lower) v = v.toLowerCase();
  // A letter in the wrong case changes case rather than disappearing.
  if (allowed)
    v = [...v]
      .map((c) => (allowed.test(c) ? c : allowed.test(c.toLowerCase()) ? c.toLowerCase() : allowed.test(c.toUpperCase()) ? c.toUpperCase() : sep))
      .join("");
  if (sep) {
    const s = sep.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    v = v.replace(new RegExp(`${s}{2,}`, "g"), sep).replace(new RegExp(`^${s}+|${s}+$`, "g"), "");
  }
  return v;
}

function cut(value: string, max: number, sep: string): string {
  const chars = [...value].slice(0, max).join("");
  return sep ? chars.replace(new RegExp(`[${sep.replace(/[-\]\\^]/g, "\\$&")}]+$`), "") : chars;
}

function fit(value: string, max: number | undefined, reserve: number, sep: string): string {
  return max !== undefined && length(value) + reserve > max ? cut(value, max - reserve, sep) : value;
}

/** The characters a pattern's character classes allow, as a one-character
 * test, when the pattern is built from classes (most AWS name patterns). */
export function allowedChars(rule: Rule): RegExp | null {
  if (rule.format === "bucket") return /[a-z0-9.-]/;
  if (rule.format === "name") return /[A-Za-z0-9_-]/;
  if (!rule.pattern) return null;
  const classes = [...rule.pattern.matchAll(/\[((?:\\.|[^\]\\])+)\]/g)].map((m) => m[1]).filter((c) => !c.startsWith("^"));
  if (classes.length === 0) {
    const shorthand = rule.pattern.match(/\\[wd]/g);
    if (!shorthand) return null;
    return new RegExp(`[${[...new Set(shorthand)].join("")}]`, "u");
  }
  // One class per alternative: joined into one, a trailing "-" of one and
  // the next class's first character would read as a range.
  const union = `^(?:${[...new Set(classes)].map((c) => `[${c}]`).join("|")})$`;
  return regex(union);
}

function schemes(pattern: string | undefined, value: string): string[] {
  const m = pattern?.match(/^\^\(?((?:[a-z][a-z0-9+.-]*\|)*[a-z][a-z0-9+.-]*)\)?:(?:\\\/|\/){2}/i);
  if (!m) return [];
  // A host name (example.com/...) reads as https first; anything else
  // (bucket/key) keeps the pattern's order.
  const web = /^[\w-]+(\.[\w-]+)*\.[a-z]{2,}(:\d+)?(\/|$)/i.test(value.trim());
  return m[1].split("|").sort((a, b) => (web ? Number(b === "https") - Number(a === "https") : 0));
}

function literalEnds(pattern: string | undefined): { prefix?: string; suffix?: string } {
  if (!pattern) return {};
  const unescape = (s: string) => s.replace(/\\(.)/g, "$1");
  const suffix = pattern.match(/((?:\\[.\-/:]|[A-Za-z0-9_\-/:])+)\)?\$$/)?.[1];
  const prefix = pattern.match(/^\^\(?((?:\\[.\-/:]|[A-Za-z0-9_\-/:])+)/)?.[1];
  // Only a literal that follows a class/quantifier (".fifo" after [...]+),
  // not a whole literal pattern.
  const out: { prefix?: string; suffix?: string } = {};
  if (suffix && /[\]+*}?)]/.test(pattern.slice(0, pattern.length - suffix.length - 1).slice(-2))) out.suffix = unescape(suffix);
  if (prefix && /^[[(\\]/.test(pattern.slice(1 + prefix.length + (pattern[1] === "(" ? 1 : 0)))) out.prefix = unescape(prefix);
  return out;
}

const UNITS: Record<Unit, [RegExp, number][]> = {
  seconds: [
    [/^(?:s|secs?|seconds?)$/, 1],
    [/^(?:m|mins?|minutes?)$/, 60],
    [/^(?:h|hrs?|hours?)$/, 3600],
    [/^(?:d|days?)$/, 86400],
    [/^(?:w|wks?|weeks?)$/, 604800],
  ],
  bytes: [
    [/^b(?:ytes?)?$/, 1],
    [/^k(?:i?b)?$/, 1024],
    [/^m(?:i?b)?$/, 1024 ** 2],
    [/^g(?:i?b)?$/, 1024 ** 3],
  ],
};

/** "12h" in seconds, "256 KiB" in bytes: the value in the rule's unit. */
export function inUnit(value: string, unit: Unit): number | null {
  const m = value.trim().toLowerCase().match(/^(\d+(?:\.\d+)?)\s*([a-z]+)$/);
  const scale = m && UNITS[unit].find(([re]) => re.test(m[2]))?.[1];
  return m && scale ? Number(m[1]) * scale : null;
}

/** A number as people read it in its unit: 43200 → "12h", 262144 → "256 KiB". */
export function amount(n: number, unit?: Unit): string {
  if (unit === "seconds") {
    for (const [s, u] of [[604800, "w"], [86400, "d"], [3600, "h"], [60, "m"]] as const) if (n >= s && n % s === 0) return `${n / s}${u}`;
    return `${n}s`;
  }
  if (unit === "bytes") {
    for (const [s, u] of [[1024 ** 3, "GiB"], [1024 ** 2, "MiB"], [1024, "KiB"]] as const) if (n >= s && n % s === 0) return `${n / s} ${u}`;
    return `${n} B`;
  }
  return String(n);
}

function numeric(value: string, rule: Rule): Repair | null {
  const converted = rule.unit ? inUnit(value, rule.unit) : null;
  const digits = converted !== null ? String(converted) : value.replace(/[,_\s]/g, "").match(/-?\d+(\.\d+)?/)?.[0];
  if (digits === undefined) {
    return rule.min !== undefined ? { value: String(rule.min), label: `Use ${rule.min}`, kind: "fix" } : null;
  }
  let n = Number(digits);
  if (rule.type === "integer" || rule.format === "port") n = Math.round(n);
  const min = rule.min ?? (rule.format === "port" ? 0 : undefined);
  const max = rule.max ?? (rule.format === "port" ? 65535 : undefined);
  let label = converted !== null ? `${value.trim()} in ${rule.unit}` : `Use ${n}`;
  if (min !== undefined && n < min) [n, label] = [min, `Raise to the minimum, ${min}`];
  if (max !== undefined && n > max) [n, label] = [max, `Lower to the maximum, ${max}`];
  return { value: String(n), label, kind: "fix" };
}

function isTaken(value: string, rule: Rule): boolean {
  if (!rule.taken) return false;
  if (!rule.takenIgnoreCase) return rule.taken.includes(value);
  const v = value.toLowerCase();
  return rule.taken.some((t) => t.toLowerCase() === v);
}

/** The next free variant of a taken name: queue → queue-2 → queue-3. */
function nextFree(value: string, rule: Rule): Repair | null {
  // A taken email address: plus-address it (owner+2@example.com).
  const at = value.lastIndexOf("@");
  if (rule.format === "email" && at > 0) {
    const [user, n0] = [value.slice(0, at).replace(/\+(\d+)$/, ""), Number(value.slice(0, at).match(/\+(\d+)$/)?.[1] ?? 1)];
    for (let n = n0 + 1; n < n0 + 50; n++) {
      const v = `${user}+${n}${value.slice(at)}`;
      if (!rule.taken?.includes(v) && valid(v, rule)) return { value: v, label: `Use ${v}`, kind: "fix" };
    }
    return null;
  }
  const allowed = allowedChars(rule);
  const sep = !allowed || allowed.test("-") ? "-" : allowed.test("_") ? "_" : "";
  // Keep a required ending (".fifo") or an extension at the end.
  const required = literalEnds(rule.pattern).suffix;
  const ending = [required, value.match(/\.[A-Za-z0-9]{1,8}$/)?.[0]].find((e) => e && value.endsWith(e)) ?? "";
  const stem0 = ending ? value.slice(0, -ending.length) : value;
  const m = stem0.match(new RegExp(`^(.*?)${sep ? `\\${sep}` : ""}(\\d+)$`));
  const stem = m ? m[1] : stem0;
  let n = m ? Number(m[2]) + 1 : 2;
  for (let i = 0; i < 50; i++, n++) {
    const suffix = `${sep}${n}`;
    for (const end of ending || !required ? [ending] : ["", required]) {
      const v = fit(stem, rule.maxLength, suffix.length + end.length, sep) + suffix + end;
      if (!isTaken(v, rule) && valid(v, rule)) return { value: v, label: `Use ${v}`, kind: "fix" };
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Did you mean.

/** Damerau-Levenshtein distance (with adjacent transpositions). */
export function distance(a: string, b: string): number {
  const d: number[][] = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return d[a.length][b.length];
}

const squash = (s: string) => s.toLowerCase().replace(/[^\p{L}\p{N}]+/gu, "");

/** The candidates closest to `value`, best first: same letters ignoring case
 * and separators, then prefixes and substrings, then small edit distances. */
export function closest(value: string, candidates: string[], limit = MAX_REPAIRS): string[] {
  const v = squash(value);
  if (!v) return [];
  const scored: [number, string][] = [];
  for (const c of new Set(candidates)) {
    if (c === value) continue;
    const s = squash(c);
    let score: number;
    if (s === v) score = 0;
    else if (s.startsWith(v) || v.startsWith(s)) score = 1 + Math.abs(s.length - v.length) / 100;
    else if (s.includes(v) || (v.length >= 4 && v.includes(s) && s.length >= 3)) score = 2 + Math.abs(s.length - v.length) / 100;
    else {
      const dist = distance(v, s);
      const budget = Math.max(1, Math.floor(Math.max(v.length, s.length) / 3));
      if (dist > budget) continue;
      score = 3 + dist;
    }
    scored.push([score, c]);
  }
  return scored
    .sort((a, b) => a[0] - b[0] || a[1].localeCompare(b[1]))
    .slice(0, limit)
    .map(([, c]) => c);
}

// ---------------------------------------------------------------------------
// Fresh values.

const ADJECTIVES = ["amber", "brisk", "calm", "clear", "crisp", "deft", "even", "keen", "lucid", "mellow", "nimble", "quiet", "rapid", "steady", "swift", "vivid"];
const NOUNS = ["arch", "brook", "cedar", "comet", "delta", "ember", "fjord", "grove", "harbor", "lagoon", "meadow", "orbit", "pine", "ridge", "summit", "willow"];

function random(n: number): number {
  const c = globalThis.crypto;
  if (c?.getRandomValues) return c.getRandomValues(new Uint32Array(1))[0] % n;
  return Math.floor(Math.random() * n);
}
const pick = <T,>(list: T[]) => list[random(list.length)];
const token = (n: number, alphabet = "abcdefghijklmnopqrstuvwxyz0123456789") => Array.from({ length: n }, () => alphabet[random(alphabet.length)]).join("");

/** A fresh value that satisfies the rule, or null when none can be made. */
export function fresh(rule: Rule): Repair | null {
  const recipe = rule.generate;
  if (!recipe) return null;
  const label = "Generate";
  for (let attempt = 0; attempt < 8; attempt++) {
    let v: string;
    if (recipe === "uuid") v = globalThis.crypto?.randomUUID?.() ?? `${token(8, "0123456789abcdef")}-${token(4, "0123456789abcdef")}-4${token(3, "0123456789abcdef")}-a${token(3, "0123456789abcdef")}-${token(12, "0123456789abcdef")}`;
    else if (recipe === "password") v = password(rule);
    else if (recipe === "account") v = token(1, "123456789") + token(11, "0123456789");
    else if (recipe === "token") v = token(Math.min(rule.maxLength ?? 16, Math.max(rule.minLength ?? 16, 16)));
    else {
      const spec = typeof recipe === "object" ? recipe : {};
      const body = spec.kind === "token" ? token(8) : `${pick(ADJECTIVES)}-${pick(NOUNS)}-${token(4)}`;
      v = `${spec.prefix ?? ""}${body}${spec.suffix ?? ""}`;
      // Fit the rule's character set and length.
      const repaired = valid(v, rule) ? v : reshape(v, { ...rule, generate: undefined })[0]?.value;
      if (!repaired) continue;
      v = repaired;
    }
    if (valid(v, rule)) return { value: v, label, kind: "generate" };
  }
  return null;
}

function password(rule: Rule): string {
  const n = Math.min(rule.maxLength ?? 24, Math.max(rule.minLength ?? 20, 20));
  const sets = ["ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789", "!#%+-=_"];
  const chars = sets.map((s) => token(1, s));
  while (chars.length < n) chars.push(token(1, sets.join("")));
  for (let i = chars.length - 1; i > 0; i--) {
    const j = random(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}

// ---------------------------------------------------------------------------
// Formats.

interface FormatSpec {
  check: (value: string, rule: Rule) => string | null;
  repair?: (value: string, rule: Rule) => Repair[];
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const octets = (ip: string) => ip.match(IPV4)?.slice(1).map(Number);
const ipOk = (o: number[] | undefined) => !!o && o.every((n) => n <= 255);

const DOMAINS = ["gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com", "example.com", "amazon.com"];

// ISO 3166 alpha-2 codes with their English names, from the runtime's
// region names (codes it only knows as withdrawn or grouping regions left out).
const NOT_COUNTRIES = new Set("AN BU CP CS DD DG EA EU EZ FX IC QO SU TA TP UK UN XA XB YD YU ZR ZZ".split(" "));
let regions: Map<string, string> | null = null;
function regionName(code: string): string | undefined {
  try {
    const name = new Intl.DisplayNames(["en"], { type: "region" }).of(code);
    return name && name !== code ? name : undefined;
  } catch {
    return undefined;
  }
}
function countries(): Map<string, string> {
  if (regions) return regions;
  regions = new Map();
  for (let a = 65; a <= 90; a++)
    for (let b = 65; b <= 90; b++) {
      const code = String.fromCharCode(a, b);
      const name = !NOT_COUNTRIES.has(code) && regionName(code);
      if (name) regions.set(code, name);
    }
  return regions;
}

/** The country codes a value most likely means: its own letters in capitals,
 * a withdrawn code's successor (UK → GB), a country name (Germany → DE), or
 * an alpha-3 code's first letters (USA → US, AUT → AU or AT). */
export function countryCodes(value: string): string[] {
  const all = countries();
  const v = value.trim();
  const upper = v.toUpperCase();
  const out: string[] = [];
  const add = (c: string | undefined) => c && all.has(c) && !out.includes(c) && out.push(c);
  if (/^[A-Za-z]{2}$/.test(v)) {
    add(upper);
    const old = regionName(upper);
    if (old) for (const [code, name] of all) if (name === old) add(code);
  }
  if (/^[A-Za-z]{3}$/.test(v)) {
    add(upper.slice(0, 2));
    add(upper[0] + upper[2]);
  }
  if (v.length <= 3) return out.slice(0, MAX_REPAIRS);
  const byName = new Map([...all].map(([code, name]) => [name, code]));
  for (const [name, code] of byName) if (squash(name) === squash(v)) add(code);
  for (const name of closest(v, [...byName.keys()])) add(byName.get(name));
  return out.slice(0, MAX_REPAIRS);
}

const PEM_BLOCK = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/;
const CSR_LABEL = /^(NEW )?CERTIFICATE REQUEST$/;
const pem = (label: string, body: string) => `-----BEGIN ${label}-----\n${body.replace(/\s+/g, "").match(/.{1,64}/g)?.join("\n") ?? ""}\n-----END ${label}-----`;

export const FORMATS: Record<Format, FormatSpec> = {
  json: {
    check(value) {
      try {
        JSON.parse(value);
        return null;
      } catch (e) {
        return jsonMessage(value, e);
      }
    },
    repair(value) {
      const fixed = repairJson(value);
      return fixed === null ? [] : [{ value: fixed, label: "Fix the JSON", kind: "fix" }];
    },
  },
  policy: {
    check(value) {
      let doc: unknown;
      try {
        doc = JSON.parse(value);
      } catch (e) {
        return jsonMessage(value, e);
      }
      return policyProblem(doc);
    },
    repair(value) {
      const fixed = repairPolicy(value);
      return fixed === null ? [] : [{ value: fixed, label: "Fix the policy", kind: "fix" }];
    },
  },
  path: {
    check(value) {
      if (!value.startsWith("/") || !value.endsWith("/")) return "Starts and ends with /, like /team/";
      if (value.includes("//")) return "No empty segments";
      return /^[\x21-\x7E]+$/.test(value) ? null : "No spaces or special characters";
    },
    repair(value) {
      const v = `/${value.trim().replace(/\s+/g, "-").replace(/[^\x21-\x7E]/g, "")}/`.replace(/\/{2,}/g, "/");
      return [{ value: v, label: "Fix the path", kind: "fix" }];
    },
  },
  yaml: {
    check(value, rule) {
      if (/^\s*[{[]/.test(value)) return FORMATS.json.check(value, rule);
      const tab = value.split("\n").findIndex((l) => /^ *\t/.test(l));
      return tab >= 0 ? `Tab indenting line ${tab + 1}` : null;
    },
    repair(value, rule) {
      if (/^\s*[{[]/.test(value)) return FORMATS.json.repair!(value, rule);
      const fixed = value.replace(/^[ \t]+/gm, (indent) => indent.replace(/\t/g, "  "));
      return [{ value: fixed, label: "Indent with spaces", kind: "fix" }];
    },
  },
  keyvalue: {
    check(value) {
      const lines = value.split("\n").map((l) => l.trim());
      const bad = lines.findIndex((l) => l && !/^[^=\s]+\s*=/.test(l));
      if (bad >= 0) return `Line ${bad + 1}: Key=value`;
      const keys = lines.filter(Boolean).map((l) => l.slice(0, l.indexOf("=")).trim());
      const twice = keys.find((k, i) => keys.indexOf(k) !== i);
      return twice ? `${twice} appears twice` : null;
    },
    repair(value) {
      const pairs: [string, string][] = [];
      let object: unknown = null;
      try {
        object = JSON.parse(repairJson(value) ?? "null");
      } catch {
        object = null;
      }
      if (object && typeof object === "object" && !Array.isArray(object)) {
        for (const [k, v] of Object.entries(object)) pairs.push([k, typeof v === "string" ? v : JSON.stringify(v)]);
      } else {
        // `Key: value`, `Key = value`, `export KEY="v"`, or pairs on one line.
        for (const part of value.split(/\n|[,;](?=\s*[\w.-]+\s*[=:])/)) {
          const m = part.trim().replace(/^export\s+/, "").match(/^["']?([^\s=:"']+)["']?\s*[=:]\s*(.*)$/);
          if (m) pairs.push([m[1], m[2].trim().replace(/^(["'])(.*)\1$/, "$2")]);
          else if (part.trim()) return [];
        }
      }
      // A repeated key keeps its last value, as the API would.
      const merged = new Map(pairs);
      return merged.size ? [{ value: [...merged].map(([k, v]) => `${k}=${v}`).join("\n"), label: "One Key=value per line", kind: "fix" }] : [];
    },
  },
  arn: {
    check(value) {
      return /^arn:[\w-]+:[\w-]*:[\w-]*:(\d{12}|aws|)?:.+$/.test(value) ? null : "Not an ARN";
    },
    repair(value, rule) {
      const out: Repair[] = [];
      const name = value.trim();
      if (name && !name.startsWith("arn:")) {
        // A bare name: the known resource it names, its ARN, close names.
        const byName = new Map((rule.known ?? []).filter((k) => k.startsWith("arn:")).map((k) => [k.split(/[:/]/).pop()!, k]));
        const exact = byName.get(name);
        if (exact) out.push({ value: exact, label: `Use ${name}`, kind: "fix" });
        if (rule.arn) out.push({ value: rule.arn.replace("{}", name.replace(/^\/+/, "")), label: "Expand to an ARN", kind: "fix" });
        for (const n of closest(name, [...byName.keys()], 2)) out.push({ value: byName.get(n)!, label: `Did you mean ${n}?`, kind: "suggest" });
      }
      if (name.startsWith("arn:")) {
        // arn:aws:iam:123456789012:role/x — a missing region colon.
        const parts = name.split(":");
        if (parts.length === 5) out.push({ value: [...parts.slice(0, 3), "", ...parts.slice(3)].join(":"), label: "Add the missing colon", kind: "fix" });
      }
      return out;
    },
  },
  cidr: {
    check(value) {
      const [ip, bits, ...rest] = value.trim().split("/");
      if (rest.length || bits === undefined) return "Like 10.0.0.0/16";
      const o = octets(ip);
      const n = Number(bits);
      if (!ipOk(o) || !/^\d{1,2}$/.test(bits) || n > 32) return "Like 10.0.0.0/16";
      const base = network(o!, n);
      return base !== ip ? `Host bits set; the network is ${base}/${n}` : null;
    },
    repair(value) {
      const v = value.trim().replace(/\s+/g, "");
      const [ip, bits] = v.split("/");
      const o = octets(ip);
      if (!ipOk(o)) return [];
      if (bits === undefined || bits === "") {
        return [16, 24].map((n) => ({ value: `${network(o!, n)}/${n}`, label: `Use /${n}`, kind: "fix" as const }));
      }
      const n = Math.min(32, Number(bits) || 0);
      return [{ value: `${network(o!, n)}/${n}`, label: "Use the network address", kind: "fix" }];
    },
  },
  ipv4: {
    check(value) {
      return ipOk(octets(value.trim())) ? null : "Like 10.0.0.1";
    },
    repair(value) {
      const v = value.trim().replace(/\/\d+$/, "");
      return ipOk(octets(v)) ? [{ value: v, label: "Drop the prefix length", kind: "fix" }] : [];
    },
  },
  email: {
    check(value) {
      return emailProblem(value);
    },
    repair(value) {
      return emailRepairs(value);
    },
  },
  emails: {
    check(value) {
      const list = value.split(",").map((s) => s.trim());
      if (list.some((s) => !s)) return "Separate addresses with one comma";
      const seen = new Set<string>();
      for (const a of list) {
        const message = emailProblem(a.match(/<([^<>]+)>$/)?.[1] ?? a);
        if (message) return list.length > 1 ? `${a}: ${message}` : message;
        if (seen.has(a.toLowerCase())) return `${a} is listed twice`;
        seen.add(a.toLowerCase());
      }
      return null;
    },
    repair(value) {
      // Pull the addresses out of whatever was pasted (semicolons, new
      // lines, "Name <a@b>"), fix each one, drop repeats.
      const found = value.match(/[^\s<>,;:"'()[\]]+@[^\s<>,;:"'()[\]]+/g) ?? [];
      const fixed = new Map<string, string>();
      for (const a of found.map((a) => cleanEmail(a)).map((a) => (emailProblem(a) ? (emailRepairs(a)[0]?.value ?? a) : a))) {
        if (!fixed.has(a.toLowerCase())) fixed.set(a.toLowerCase(), a);
      }
      return fixed.size ? [{ value: [...fixed.values()].join(", "), label: "Clean up the list", kind: "fix" }] : [];
    },
  },
  domain: {
    check(value) {
      return domainProblem(value);
    },
    repair(value) {
      return domainRepairs(value);
    },
  },
  "email-or-domain": {
    check(value) {
      return value.includes("@") ? emailProblem(value) : domainProblem(value) && "An email address or a domain";
    },
    repair(value) {
      return value.includes("@") && !/^[a-z][\w+.-]*:\/\//i.test(value.trim()) ? emailRepairs(value) : domainRepairs(value);
    },
  },
  url: {
    check(value) {
      try {
        const u = new URL(value);
        return /^https?:$/.test(u.protocol) ? null : "An http(s) URL";
      } catch {
        return "An http(s) URL";
      }
    },
    repair(value, rule) {
      const v = value.trim();
      // An SSH remote (git@github.com:org/repo.git) as its HTTPS URL.
      const ssh = v.match(/^(?:ssh:\/\/)?[\w.-]+@([\w.-]+\.[a-z]{2,})[:/](.+)$/i);
      if (ssh) return [{ value: `https://${ssh[1]}/${ssh[2].replace(/^\/+/, "")}`, label: "Use the HTTPS URL", kind: "fix" }];
      // https:// first; http:// only where the rule refuses https://.
      const pick = (bare: string, add: boolean): Repair[] => {
        const https = `https://${bare}`;
        const http = `http://${bare}`;
        const v2 = valid(https, rule) || !valid(http, rule) ? https : http;
        return [{ value: v2, label: add ? `Add ${v2.slice(0, v2.indexOf("//") + 2)}` : `Use ${v2.slice(0, v2.indexOf(":"))}`, kind: "fix" }];
      };
      const scheme = v.match(/^https?:\/\/(.+)$/i);
      if (scheme) return pick(scheme[1], false);
      // Local endpoints (localhost, an IP, a bare host:port) are plain HTTP.
      if (/^(localhost|\d{1,3}(\.\d{1,3}){3}|[\w-]+:\d+)([:/?#].*)?$/i.test(v)) {
        const http = `http://${v}`;
        return valid(http, rule) ? [{ value: http, label: "Add http://", kind: "fix" }] : pick(v, true);
      }
      return /^[\w.-]+\.[a-z]{2,}([:/].*)?$/i.test(v) ? pick(v, true) : [];
    },
  },
  s3url: {
    check(value) {
      return s3Object(value)?.canonical && value.trim() === value ? null : "Like s3://bucket/key";
    },
    repair(value) {
      const found = s3Object(value.trim());
      return found ? [{ value: `s3://${found.bucket}/${found.key}`, label: "Use the s3:// URL", kind: "fix" }] : [];
    },
  },
  bucket: {
    check(value) {
      if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(value)) return "3–63 lowercase letters, digits, . and -";
      if (/\.\.|\.-|-\./.test(value)) return "No adjacent periods or hyphens";
      if (IPV4.test(value)) return "Not an IP address";
      if (/^xn--|^sthree-|-s3alias$|--ol-s3$/.test(value)) return "Reserved prefix or suffix";
      return null;
    },
  },
  name: {
    check(value) {
      return /^[A-Za-z0-9_-]+$/.test(value) ? null : "Letters, digits, - and _";
    },
  },
  // Names separated by commas or spaces, each checked against `rule.item`,
  // none twice.
  list: {
    check(value, rule) {
      const seen = new Set<string>();
      for (const item of listItems(value)) {
        if (seen.has(item)) return `${item} is listed twice`;
        seen.add(item);
        const issue = rule.item && problem(item, rule.item, {});
        if (issue) return `${item}: ${issue.message}`;
      }
      return seen.size ? null : "Required";
    },
    repair(value, rule) {
      const out: string[] = [];
      let label = "";
      for (const item of listItems(value)) {
        const fixed = !rule.item || valid(item, rule.item) ? item : check(item, rule.item)?.repairs.find((r) => r.kind === "fix");
        const v = typeof fixed === "string" ? fixed : fixed?.value;
        if (typeof fixed === "object" && fixed) label ||= `${fixed.label} in ${item}`;
        if (v === undefined) label ||= `Remove ${item}`;
        else if (out.includes(v)) label ||= `Remove the second ${v}`;
        else out.push(v);
      }
      return out.length && label ? [{ value: out.join(", "), label, kind: "fix" }] : [];
    },
  },
  port: {
    check() {
      return null;
    },
  },
  country: {
    check(value) {
      if (countries().has(value)) return null;
      const [code] = countryCodes(value);
      return code ? `Did you mean ${countries().get(code)}?` : "A two-letter country code, like US";
    },
    repair(value) {
      return countryCodes(value).map((c) => ({ value: c, label: countries().get(c)!, kind: "suggest" as const }));
    },
  },
  csr: {
    check(value) {
      const block = value.match(PEM_BLOCK);
      if (!block) return /^\s*MII[A-Za-z0-9+/=\s]+$/.test(value) ? "Missing the BEGIN/END lines" : "A PEM certificate request (-----BEGIN CERTIFICATE REQUEST-----)";
      if (/PRIVATE KEY/.test(block[1])) return "This is a private key: never paste it, paste its CSR";
      if (!CSR_LABEL.test(block[1])) return `This is a ${block[1].toLowerCase()}, not a certificate request`;
      if (/[^A-Za-z0-9+/=\r\n]/.test(block[2].trim())) return "Stray characters inside the request";
      if (value.trim() !== block[0]) return "Text around the request";
      if (!/^-----BEGIN [^\n]+-----\r?\n[\s\S]*\n-----END [^\n]+-----$/.test(block[0])) return "The BEGIN and END lines need lines of their own";
      return null;
    },
    repair(value) {
      const block = value.match(PEM_BLOCK);
      if (!block) return /^\s*MII[A-Za-z0-9+/=\s]+$/.test(value) ? [{ value: pem("CERTIFICATE REQUEST", value), label: "Add the BEGIN/END lines", kind: "fix" }] : [];
      if (!CSR_LABEL.test(block[1])) return [];
      return [{ value: pem(block[1], block[2]), label: "Tidy the request", kind: "fix" }];
    },
  },
  phone: {
    // E.164, as SMS APIs take it: +, country code, number, no formatting.
    check(value) {
      return /^\+[1-9]\d{1,14}$/.test(value) ? null : "E.164, like +14155550100";
    },
    repair(value) {
      let digits = value.replace(/[\s().\-\u2010-\u2015/]/g, "");
      if (/^00[1-9]/.test(digits)) digits = `+${digits.slice(2)}`;
      if (!/^\+?\d+$/.test(digits)) return [];
      if (digits.startsWith("+")) return [{ value: digits, label: "Remove formatting", kind: "fix" }];
      const out: Repair[] = [{ value: `+${digits}`, label: "Add +", kind: "fix" }];
      // Ten digits without a country code read as a North American number.
      if (digits.length === 10) out.unshift({ value: `+1${digits}`, label: "Add +1", kind: "suggest" });
      return out;
    },
  },
  // `key=value` per line (or comma), as headers, tags or a mapping.
  pairs: {
    check(value) {
      const bad = pairList(value).find((p) => !/^[^=\s][^=]*=/.test(p));
      return bad === undefined ? null : `"${bad}" is not key=value`;
    },
    repair(value) {
      // A JSON object, or `key: value` / `key value` lines.
      let entries: [string, string][];
      if (value.trim().startsWith("{")) {
        const json = repairJson(value);
        const o: unknown = json === null ? null : JSON.parse(json);
        if (!o || typeof o !== "object" || Array.isArray(o)) return [];
        entries = Object.entries(o).map(([k, v]) => [k, typeof v === "string" ? v : JSON.stringify(v)]);
      } else {
        entries = pairList(value).map((p) => {
          const m = p.match(/^([^=:\s]+)\s*(?:=|:|\s)\s*(.*)$/);
          return m ? [m[1], m[2]] : [p, ""];
        });
      }
      return entries.length ? [{ value: entries.map(([k, v]) => `${k}=${v}`).join("\n"), label: "Rewrite as key=value", kind: "fix" }] : [];
    },
  },
  // `key=value` per line, AWS's usual tag limits.
  tags: {
    check(value) {
      const keys = new Set<string>();
      for (const [i, raw] of value.split("\n").entries()) {
        const line = raw.trim();
        if (!line) continue;
        const eq = line.indexOf("=");
        const key = line.slice(0, eq).trim();
        if (eq < 0 || !key) return `Line ${i + 1}: key=value`;
        if (length(key) > 128) return `Line ${i + 1}: key over 128 characters`;
        if (length(line.slice(eq + 1).trim()) > 256) return `Line ${i + 1}: value over 256 characters`;
        if (/^aws:/i.test(key)) return `Line ${i + 1}: aws: is reserved for AWS`;
        if (keys.has(key)) return `Line ${i + 1}: ${key} repeats`;
        keys.add(key);
      }
      return null;
    },
    repair(value) {
      // "key: value", "key value" or a bare key become key=value; a key
      // given twice keeps its last value; blank lines go.
      const tags = new Map<string, string>();
      for (const raw of value.split("\n")) {
        const line = raw.trim();
        if (!line) continue;
        const m = line.includes("=") ? line.match(/^([^=]*)=(.*)$/) : line.match(/^(.+?)\s*(?::\s*|\s+|$)(.*)$/);
        const key = m?.[1].trim().replace(/^aws:/i, "");
        if (!key) continue;
        tags.delete(key);
        tags.set(key, m![2].trim());
      }
      const fixed = [...tags].map(([k, v]) => `${k}=${v}`).join("\n");
      return fixed ? [{ value: fixed, label: "Use key=value lines", kind: "fix" }] : [];
    },
  },
  // A Git branch name, by `git check-ref-format --branch`.
  branch: {
    check(value) {
      if (/\s/.test(value)) return "No spaces";
      const bad = value.match(/[~^:?*[\\\x00-\x1f\x7f]/)?.[0];
      if (bad) return /[\x00-\x1f\x7f]/.test(bad) ? "No control characters" : `No ${bad}`;
      if (value.includes("..")) return "No ..";
      if (value.includes("@{") || value === "@") return "No @{";
      if (value.startsWith("-")) return "Can't start with -";
      if (/(^|\/)\./.test(value)) return "No part can start with .";
      if (/\/\/|^\/|\/$/.test(value)) return "No empty parts between /";
      if (value.endsWith(".")) return "Can't end with .";
      if (/\.lock(\/|$)/.test(value)) return "No part can end with .lock";
      return null;
    },
    repair(value) {
      const v = value
        .trim()
        .replace(/@\{/g, "-")
        .replace(/[\s~^:?*[\\\x00-\x1f\x7f]+/g, "-")
        .replace(/\.{2,}/g, ".")
        .split("/")
        .map((p) => p.replace(/^[.-]+/, "").replace(/(\.lock)+$/, "").replace(/[.-]+$/, "").replace(/-{2,}/g, "-"))
        .filter(Boolean)
        .join("/");
      return v && v !== "@" ? [{ value: v, label: "Fix the branch name", kind: "fix" }] : [];
    },
  },
  dir: {
    check(value) {
      return value.startsWith("/") ? null : "An absolute path, like /data";
    },
    repair(value, rule) {
      // Backslashes, doubled or trailing slashes, spaces and shell
      // characters cleaned up; then leading dots dropped; then the path cut
      // to the depth the pattern allows. Both slash endings are tried, as
      // some APIs want one (IAM paths) and others forbid it (EFS).
      const segments = value
        .replace(/\\/g, "/")
        .split("/")
        .map((s) => s.trim().replace(/\s+/g, "-").replace(/[$#<>;`|&?{}^*\n]/g, ""))
        .filter(Boolean);
      const out: Repair[] = [];
      const add = (segs: string[], label: string) => {
        const p = "/" + segs.join("/");
        const v = [p, p + "/"].find((c) => c !== value && valid(c, rule));
        if (v) out.push({ value: v, label, kind: "fix" });
      };
      add(segments, "Clean up the path");
      const undotted = segments.map((s) => s.replace(/^\.+/, "")).filter(Boolean);
      if (out.length === 0) add(undotted, "Drop leading dots");
      for (let n = undotted.length - 1; out.length === 0 && n >= 1; n--) add(undotted.slice(0, n), `Keep ${n} level${n === 1 ? "" : "s"}`);
      return out;
    },
  },
};

const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
/** Top-level domains people mistype, and what they meant. */
const TLD_TYPOS: Record<string, string> = { con: "com", cmo: "com", ocm: "com", vom: "com", xom: "com", comm: "com", ogr: "org", rog: "org", nte: "net", ent: "net" };

function tldTypo(domain: string): string | null {
  const tld = domain.split(".").pop()?.toLowerCase() ?? "";
  return TLD_TYPOS[tld] ?? null;
}

function domainProblem(value: string): string | null {
  if (!DOMAIN.test(value)) return "Like example.com";
  const tld = tldTypo(value);
  return tld ? `Did you mean .${tld}?` : null;
}

/** A pasted URL or host reduced to its domain: no scheme, path, port,
 * trailing dot, spaces or capitals, and a mistyped TLD corrected. */
function cleanDomain(value: string): string {
  const host = value.trim().replace(/^[a-z][\w+.-]*:\/\//i, "").replace(/^[^@/]*@/, "").split(/[/?#:]/)[0];
  const d = host.replace(/\s+/g, "").replace(/\.+$/, "").toLowerCase();
  const tld = tldTypo(d);
  return tld ? d.replace(/[^.]+$/, tld) : d;
}

function domainRepairs(value: string): Repair[] {
  const d = cleanDomain(value);
  if (!d || d === value) return [];
  const tld = tldTypo(value.trim().replace(/\.+$/, ""));
  return [{ value: d, label: tld ? `Did you mean .${tld}?` : "Use the domain", kind: "fix" }];
}

function emailProblem(value: string): string | null {
  if (!/^[^\s@<>,;:]+@[^\s@<>,;:]+\.[^\s@<>,;:]+$/.test(value)) return "Like name@example.com";
  const domain = value.split("@")[1].toLowerCase();
  const tld = tldTypo(domain);
  if (tld) return `Did you mean .${tld}?`;
  // A near miss of a common domain is almost always a typo.
  const near = DOMAINS.includes(domain) ? [] : closest(domain, DOMAINS, 1).filter((d) => distance(domain, d) <= 2);
  return near.length ? `Did you mean ${near[0]}?` : null;
}

/** "mailto:", "Name <a@b>", spaces and a trailing period removed. */
function cleanEmail(value: string): string {
  let v = value.trim().replace(/^mailto:/i, "");
  v = v.match(/<([^<>]+)>/)?.[1] ?? v;
  v = v.replace(/\s+/g, "").replace(/[.,;]+$/, "");
  const at = v.lastIndexOf("@");
  return at < 0 ? v : `${v.slice(0, at)}@${v.slice(at + 1).toLowerCase()}`;
}

function emailRepairs(value: string): Repair[] {
  const v = cleanEmail(value);
  const at = v.lastIndexOf("@");
  if (at <= 0 || at === v.length - 1) return [];
  const user = v.slice(0, at);
  const domain = cleanDomain(v.slice(at + 1));
  const out: Repair[] = [];
  const tld = tldTypo(v.slice(at + 1));
  out.push({ value: `${user}@${domain}`, label: tld ? `Did you mean .${tld}?` : "Clean up the address", kind: "fix" });
  for (const d of closest(domain, DOMAINS, 1).filter((d) => distance(domain, d) <= 2)) {
    out.push({ value: `${user}@${d}`, label: `Did you mean ${d}?`, kind: "suggest" });
  }
  return out;
}
const pairList = (value: string) => value.split(/[\n,]+/).map((p) => p.trim()).filter(Boolean);

const BUCKET = "[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]";

/** The bucket and key an S3 object reference names: s3://bucket/key, or the
 * shapes people paste instead (virtual-hosted or path-style https URLs, an
 * object ARN, the console's object page, a bare bucket/key). A canonical
 * s3:// URL and the https forms are accepted as they are; `check` flags the
 * rest so the repair can rewrite them. */
function s3Object(value: string): { bucket: string; key: string; canonical: boolean } | null {
  const v = value.trim();
  const tries: [RegExp, boolean][] = [
    [new RegExp(`^s3://(${BUCKET})/(.+)$`), true],
    [new RegExp(`^https://(${BUCKET})\\.s3(?:[.-][a-z0-9-]+)?\\.amazonaws\\.com/(.+)$`), true],
    [new RegExp(`^https://s3(?:[.-][a-z0-9-]+)?\\.amazonaws\\.com/(${BUCKET})/(.+)$`), true],
    [new RegExp(`^s3:/*(${BUCKET})/(.+)$`, "i"), false],
    [new RegExp(`^arn:aws[\\w-]*:s3:::(${BUCKET})/(.+)$`), false],
    [new RegExp(`^(${BUCKET})/(.+)$`), false],
  ];
  for (const [re, canonical] of tries) {
    const m = v.match(re);
    if (m) return { bucket: m[1].toLowerCase(), key: m[2], canonical };
  }
  const consoleUrl = v.match(new RegExp(`^https://[\\w.-]*console\\.aws\\.amazon\\.com/s3/object/(${BUCKET})\\?(?:.*&)?prefix=([^&#]+)`));
  if (consoleUrl) return { bucket: consoleUrl[1], key: decodeURIComponent(consoleUrl[2]), canonical: false };
  return null;
}

/** The items of a comma- or space-separated list. */
export function listItems(value: string): string[] {
  return value.split(/[\s,]+/).filter(Boolean);
}

function network(o: number[], bits: number): string {
  const n = ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const base = (n & mask) >>> 0;
  return [base >>> 24, (base >>> 16) & 255, (base >>> 8) & 255, base & 255].join(".");
}

function jsonMessage(value: string, e: unknown): string {
  const text = e instanceof Error ? e.message : String(e);
  const at = text.match(/position (\d+)/)?.[1];
  if (at === undefined) return value.trim() ? "Invalid JSON" : "Empty JSON";
  const before = value.slice(0, Number(at));
  const line = before.split("\n").length;
  const col = Number(at) - before.lastIndexOf("\n");
  return `Invalid JSON at line ${line}, column ${col}`;
}

/** Fix the usual hand-written JSON mistakes: single quotes, unquoted keys,
 * trailing commas, comments, missing outer braces. Returns pretty JSON, or
 * null when it still does not parse. */
export function repairJson(value: string): string | null {
  const attempts: string[] = [];
  let v = value
    .replace(/^\uFEFF/, "")
    .replace(/[\u201C\u201D]/g, '"')
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
  attempts.push(v);
  v = v.replace(/'((?:\\.|[^'\\])*)'/g, (_, s: string) => JSON.stringify(s.replace(/\\'/g, "'")));
  attempts.push(v);
  v = v.replace(/([{,]\s*)([A-Za-z_$][\w$-]*)(\s*:)/g, '$1"$2"$3');
  attempts.push(v);
  v = v.replace(/,(\s*[}\]])/g, "$1");
  attempts.push(v);
  // Missing commas between lines: "a": 1\n "b": 2
  v = v.replace(/(["\d}\]el])(\s*\n\s*")/g, "$1,$2");
  attempts.push(v);
  const t = v.trim();
  if (!/^[{[]/.test(t)) attempts.push(`{${t}}`);
  if (/^{/.test(t) && !/}$/.test(t)) attempts.push(`${t}}`);
  if (/^\[/.test(t) && !/]$/.test(t)) attempts.push(`${t}]`);
  for (const a of attempts) {
    try {
      return JSON.stringify(JSON.parse(a), null, 2);
    } catch {
      // try the next one
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Policy documents (IAM, and the resource policies of S3, SQS, KMS, ...).

const POLICY_KEYS = ["Version", "Id", "Statement"];
const STATEMENT_KEYS = ["Sid", "Effect", "Principal", "NotPrincipal", "Action", "NotAction", "Resource", "NotResource", "Condition"];
const VERSIONS = ["2012-10-17", "2008-10-17"];
const ACTION = /^(\*|[a-z0-9-]+:[A-Za-z0-9*?]+)$/i;
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const list = (v: unknown): unknown[] => (v === undefined ? [] : Array.isArray(v) ? v : [v]);

function policyProblem(doc: unknown): string | null {
  if (!isObject(doc)) return "A policy is an object with a Statement";
  if (doc.Version !== undefined && !VERSIONS.includes(doc.Version as string)) return "Version is 2012-10-17";
  if (doc.Statement === undefined) return "No Statement";
  const statements = list(doc.Statement);
  if (statements.length === 0) return "No Statement";
  for (const [i, s] of statements.entries()) {
    const which = statements.length > 1 ? `Statement ${i + 1}` : "The statement";
    if (!isObject(s)) return `${which} isn't an object`;
    if (s.Effect !== "Allow" && s.Effect !== "Deny") return `${which}: Effect is Allow or Deny`;
    if (s.Action === undefined && s.NotAction === undefined) return `${which} has no Action`;
    const bad = [...list(s.Action), ...list(s.NotAction)].find((a) => typeof a !== "string" || !ACTION.test(a));
    if (bad !== undefined) return `Action ${JSON.stringify(bad)} isn't service:action`;
  }
  return null;
}

/** Canonical key names: wrong case and plurals ("actions") are corrected. */
function canonicalKeys(o: Record<string, unknown>, keys: string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(o)) {
    const bare = k.trim().toLowerCase();
    const key = keys.find((c) => c.toLowerCase() === bare || `${c.toLowerCase()}s` === bare) ?? k;
    out[key] = v;
  }
  return out;
}

/** Fix the usual policy mistakes on top of JSON ones: a bare statement or
 * statement list, a missing or mistyped Version, key and Effect casing,
 * actions written `s3.GetObject`. Null when nothing parses. */
export function repairPolicy(value: string): string | null {
  let doc: unknown;
  try {
    doc = JSON.parse(value);
  } catch {
    const json = repairJson(value);
    if (json === null) return null;
    doc = JSON.parse(json);
  }
  if (Array.isArray(doc)) doc = { Statement: doc };
  if (!isObject(doc)) return null;
  let top = canonicalKeys(doc, POLICY_KEYS);
  if (top.Statement === undefined && Object.keys(canonicalKeys(top, STATEMENT_KEYS)).some((k) => STATEMENT_KEYS.includes(k))) top = { Statement: [top] };
  const action = (a: unknown) => (typeof a === "string" && !a.includes(":") && a !== "*" ? a.trim().replace(/^([a-z0-9-]+)\s*[.\s/]\s*/i, "$1:") : a);
  const statement = (raw: unknown) => {
    if (!isObject(raw)) return raw;
    const s = canonicalKeys(raw, STATEMENT_KEYS);
    if (typeof s.Effect === "string") s.Effect = ["Allow", "Deny"].find((e) => e.toLowerCase() === (s.Effect as string).trim().toLowerCase()) ?? s.Effect;
    for (const k of ["Action", "NotAction"]) if (s[k] !== undefined) s[k] = Array.isArray(s[k]) ? (s[k] as unknown[]).map(action) : action(s[k]);
    return s;
  };
  const { Version, ...rest } = top;
  const fixed = {
    Version: VERSIONS.includes(Version as string) ? Version : "2012-10-17",
    ...rest,
    Statement: Array.isArray(rest.Statement) ? rest.Statement.map(statement) : statement(rest.Statement),
  };
  return JSON.stringify(fixed, null, 2);
}

// ---------------------------------------------------------------------------
// Describing patterns.

const CLASS_WORDS: [RegExp, string][] = [
  [/a-z/, "lowercase letters"],
  [/A-Z/, "uppercase letters"],
  [/0-9|\\d/, "digits"],
];

/** A short description of a pattern built from character classes, e.g.
 * `^[a-zA-Z0-9_-]+$` → "Letters, digits, _ and -". */
export function describePattern(pattern: string): string {
  const classes = [...pattern.matchAll(/\[((?:\\.|[^\]\\])+)\]/g)].map((m) => m[1]).filter((c) => !c.startsWith("^"));
  const literal = literalEnds(pattern).suffix;
  if (classes.length === 0 && !/\\w/.test(pattern)) return "Doesn't match the required format";
  let all = classes.join("");
  if (/\\w/.test(pattern)) all += "a-zA-Z0-9_";
  const words: string[] = [];
  const lower = /a-z/.test(all);
  const upper = /A-Z/.test(all);
  if (lower && upper) words.push("letters");
  else for (const [re, w] of CLASS_WORDS.slice(0, 2)) if (re.test(all)) words.push(w);
  if (CLASS_WORDS[2][0].test(all)) words.push("digits");
  let rest = all.replace(/a-z|A-Z|0-9|\\d|\\w/g, "");
  if (/\\s/.test(rest)) words.push("spaces");
  rest = rest.replace(/\\[sSpP](\{[^}]*\})?|\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|\\t|\\n|\\r/g, "");
  const unique = [...new Set([...rest.replace(/\\(.)/g, "$1")])].filter((c) => c.trim());
  if (words.length === 0 && unique.length === 0) return "Doesn't match the required format";
  const parts = [...words, ...unique.slice(0, 8)];
  const sentence = parts.length > 1 ? `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}` : parts[0];
  const text = sentence.charAt(0).toUpperCase() + sentence.slice(1);
  return literal ? `${text}, ending in ${literal}` : text;
}

// ---------------------------------------------------------------------------
// Server errors.

const VALUE_AT = /Value (?:'((?:[^']|'(?! at '))*)'|(null)|) ?at '([^']+)' failed to satisfy constraint: ([^;]+?)(?=; Value |;? *$)/g;

/** Turn an AWS validation message into per-member issues with the rule
 * each value broke. Messages that name no member give no issues. */
export function parseServerIssues(message: string): FieldIssue[] {
  const out: FieldIssue[] = [];
  for (const m of message.matchAll(VALUE_AT)) {
    const [, value, nil, member, constraint] = m;
    out.push({ member, value: nil ? undefined : value, ...constraintRule(constraint.trim()) });
  }
  if (out.length) return out;
  // "Invalid parameter at 'imageDigest' failed to satisfy constraint: '...'"
  for (const m of message.matchAll(/(?:Invalid parameter|parameter) at '([^']+)' failed to satisfy constraint: '?(.+?)'?$/g)) {
    out.push({ member: m[1], code: "server", message: sentence(m[2]) });
  }
  if (out.length) return out;
  // "Value (x) for parameter QueueName is invalid. Reason: ..."
  const param = message.match(/Value \(?'?([^)']*)'?\)? for parameter (\w+) is invalid\.?\s*(?:Reason: )?(.*)$/);
  if (param) out.push({ member: param[2], value: param[1], code: "server", message: sentence(param[3] || "Invalid value") });
  // "1 validation error detected: The parameter X ..." / "X is required" / "Missing required parameter X"
  const missing = message.match(/(?:Missing required (?:parameter|key|field)|The parameter|Parameter) '?([A-Za-z][\w.]*)'? (?:is (?:required|missing)|must be specified)/i) ??
    message.match(/^(?:\w+: )?'?([A-Za-z][\w.]*)'? (?:is required|must be specified|cannot be empty)/);
  if (!param && missing) out.push({ member: missing[1], code: "required", message: "Required" });
  // "Invalid value for the parameter VisibilityTimeout." (SQS attributes)
  const attribute = message.match(/^Invalid value for the parameter (\w+)\.?$/);
  if (attribute) out.push({ member: attribute[1], code: "server", message: "Invalid value" });
  return out;
}

function sentence(s: string): string {
  const t = s.trim().replace(/\.$/, "");
  return t.charAt(0).toUpperCase() + t.slice(1);
}

function constraintRule(constraint: string): Pick<FieldIssue, "rule" | "code" | "message"> {
  let m: RegExpMatchArray | null;
  if (/must not be null/.test(constraint)) return { rule: { required: true }, code: "required", message: "Required" };
  if ((m = constraint.match(/length greater than or equal to (\d+)/))) {
    const n = Number(m[1]);
    return { rule: { minLength: n }, code: "tooShort", message: `At least ${n} character${n === 1 ? "" : "s"}` };
  }
  if ((m = constraint.match(/length less than or equal to (\d+)/))) {
    const n = Number(m[1]);
    return { rule: { maxLength: n }, code: "tooLong", message: `At most ${n} characters` };
  }
  if ((m = constraint.match(/value greater than or equal to (-?[\d.]+)/))) return { rule: { min: Number(m[1]), type: "number" }, code: "range", message: `At least ${m[1]}` };
  if ((m = constraint.match(/value less than or equal to (-?[\d.]+)/))) return { rule: { max: Number(m[1]), type: "number" }, code: "range", message: `At most ${m[1]}` };
  if ((m = constraint.match(/regular expression pattern: (.+)$/))) {
    // The server already decided the value fails; read its pattern as a
    // whole-value match so the repairs fix what it objected to.
    const pattern = /^\^.*\$$/.test(m[1]) ? m[1] : `^(?:${m[1]})$`;
    return { rule: { pattern }, code: "pattern", message: describePattern(m[1]) };
  }
  if ((m = constraint.match(/enum value set: \[(.*)\]$/))) {
    const values = m[1].split(/,\s*/).filter(Boolean);
    return { rule: { enum: values }, code: "enum", message: values.length <= 4 ? `One of ${values.join(", ")}` : "Not an allowed value" };
  }
  if ((m = constraint.match(/must be a valid (\w+)/))) {
    const type = /int|long|short|byte/i.test(m[1]) ? "integer" : /float|double|decimal|number/i.test(m[1]) ? "number" : undefined;
    return { rule: type ? { type } : undefined, code: "type", message: `Not a valid ${m[1]}` };
  }
  return { code: "server", message: sentence(constraint.replace(/^Member must /, "Must ")) };
}

/** Error codes that mean "this name is taken". */
export const CONFLICT = /AlreadyExists|AlreadyOwned|NameExists|Duplicate|Conflict|EntityExists|InUse/i;
