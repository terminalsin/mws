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

export type Format = "json" | "arn" | "cidr" | "ipv4" | "email" | "url" | "bucket" | "name" | "port" | "country" | "csr";

/** "name": a readable resource name; "token": random letters and digits;
 * "password": meets the usual complexity rules; or a fixed prefix/suffix
 * around a readable name. */
export type Generate = "name" | "token" | "password" | "uuid" | { prefix?: string; suffix?: string; kind?: "name" | "token" };

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
  if (rule.enum && rule.enum.length > 0 && !rule.enum.includes(value)) {
    return { code: "enum", message: rule.enum.length <= 4 ? `One of ${rule.enum.join(", ")}` : "Not an allowed value" };
  }
  if (isNumeric(rule) || rule.min !== undefined || rule.max !== undefined) {
    if (isNumeric(rule) || /^-?\d/.test(value)) {
      const n = Number(value);
      const integer = rule.type === "integer" || rule.format === "port";
      if (!/^-?(\d+\.?\d*|\.\d+)(e[-+]?\d+)?$/i.test(value.trim()) || Number.isNaN(n))
        return { code: "type", message: integer ? "Whole number" : "Number" };
      if (integer && !Number.isInteger(n)) return { code: "type", message: "Whole number" };
      const min = rule.min ?? (rule.format === "port" ? 0 : undefined);
      const max = rule.max ?? (rule.format === "port" ? 65535 : undefined);
      if (min !== undefined && n < min) return { code: "range", message: max !== undefined ? `${min}–${max}` : `At least ${min}` };
      if (max !== undefined && n > max) return { code: "range", message: min !== undefined ? `${min}–${max}` : `At most ${max}` };
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
      for (const r of reshape(value, rule).slice(0, 1)) offer(r);
      break;
    }
    default:
      // The least invasive cleanup that works; a second one would only be a
      // worse version of it.
      for (const r of reshape(value, rule).slice(0, 1)) offer(r);
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
  return closest(value, rule.known ?? []).map((s) => ({ value: s, label: `Did you mean ${s}?`, kind: "suggest" as const }));
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
  // A required literal ending (a FIFO queue's ".fifo") or beginning.
  const literal = literalEnds(rule.pattern);
  for (const v of [...seen]) {
    if (literal.suffix && !v.endsWith(literal.suffix)) push(`Add ${literal.suffix}`, fit(v, max, literal.suffix.length, sep) + literal.suffix);
    if (literal.prefix && !v.startsWith(literal.prefix)) push(`Add ${literal.prefix}`, literal.prefix + v);
  }
  if (max !== undefined && length(value) > max) push(`Shorten to ${max} characters`, cut(value, max, sep));
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

function numeric(value: string, rule: Rule): Repair | null {
  const digits = value.replace(/[,_\s]/g, "").match(/-?\d+(\.\d+)?/)?.[0];
  if (digits === undefined) {
    return rule.min !== undefined ? { value: String(rule.min), label: `Use ${rule.min}`, kind: "fix" } : null;
  }
  let n = Number(digits);
  if (rule.type === "integer" || rule.format === "port") n = Math.round(n);
  const min = rule.min ?? (rule.format === "port" ? 0 : undefined);
  const max = rule.max ?? (rule.format === "port" ? 65535 : undefined);
  let label = `Use ${n}`;
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
  arn: {
    check(value) {
      return /^arn:[\w-]+:[\w-]*:[\w-]*:(\d{12}|aws|)?:.+$/.test(value) ? null : "Not an ARN";
    },
    repair(value, rule) {
      const out: Repair[] = [];
      const name = value.trim();
      if (rule.arn && name && !name.startsWith("arn:")) {
        out.push({ value: rule.arn.replace("{}", name.replace(/^\/+/, "")), label: "Expand to an ARN", kind: "fix" });
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
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return "Like name@example.com";
      // A near miss of a common domain is almost always a typo.
      const domain = value.split("@")[1].toLowerCase();
      const near = DOMAINS.includes(domain) ? [] : closest(domain, DOMAINS, 1).filter((d) => distance(domain, d) <= 2);
      return near.length ? `Did you mean ${near[0]}?` : null;
    },
    repair(value) {
      const v = value.trim().replace(/\s+/g, "");
      const [user, domain] = v.split("@");
      if (!user || domain === undefined) return [];
      return closest(domain, DOMAINS, 1).map((d) => ({ value: `${user}@${d}`, label: `Did you mean ${d}?`, kind: "suggest" as const }));
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
    repair(value) {
      const v = value.trim();
      return /^[\w.-]+\.[a-z]{2,}([:/].*)?$/i.test(v) || /^localhost([:/].*)?$/.test(v)
        ? [{ value: `https://${v}`, label: "Add https://", kind: "fix" }]
        : [];
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
};

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
