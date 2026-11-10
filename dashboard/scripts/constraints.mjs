#!/usr/bin/env node
// Turn the Smithy models MWS vendors (crates/services/*/model/*.json) into
// the input constraints the console's forms validate against:
// packages/ui/src/model/<model>.ts, one export per operation, mapping each
// input member to its rule (required, length, pattern, range, enum and the
// shape of nested members). Imported by name, so a page bundles only the
// operations it uses:
//   import { CreateFunction } from "@mws-dashboard/ui/model/lambda";
// The files are git-ignored: scripts/services.mjs writes them before every
// build, type check and dev server, and `node scripts/constraints.mjs`
// rewrites them by hand.
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const crates = join(root, "../crates/services");
const target = join(root, "packages/ui/src/model");
const MAX_DEPTH = 3;

const PRIMITIVE = {
  string: "string",
  enum: "string",
  integer: "integer",
  intEnum: "integer",
  long: "integer",
  short: "integer",
  byte: "integer",
  bigInteger: "integer",
  float: "number",
  double: "number",
  bigDecimal: "number",
  boolean: "boolean",
  timestamp: "timestamp",
  blob: "blob",
  document: "document",
};

function jsPattern(pattern) {
  // Smithy patterns are ECMA 262 and unanchored; keep only the ones a
  // browser can compile (with the `u` flag, as some use \p{...}).
  try {
    new RegExp(pattern, "u");
    return pattern;
  } catch {
    try {
      new RegExp(pattern);
      return pattern;
    } catch {
      return undefined;
    }
  }
}

function generate(model) {
  const shapes = model.shapes;
  const prelude = {
    "smithy.api#String": { type: "string" },
    "smithy.api#Integer": { type: "integer" },
    "smithy.api#Long": { type: "long" },
    "smithy.api#Boolean": { type: "boolean" },
    "smithy.api#PrimitiveBoolean": { type: "boolean" },
    "smithy.api#PrimitiveInteger": { type: "integer" },
    "smithy.api#PrimitiveLong": { type: "long" },
    "smithy.api#Double": { type: "double" },
    "smithy.api#Float": { type: "float" },
    "smithy.api#Timestamp": { type: "timestamp" },
    "smithy.api#Blob": { type: "blob" },
    "smithy.api#Document": { type: "document" },
    "smithy.api#Unit": { type: "structure", members: {} },
  };
  const shape = (id) => shapes[id] ?? prelude[id];

  function constraints(traits, rule) {
    if (!traits) return;
    if (traits["smithy.api#required"]) rule.required = true;
    const len = traits["smithy.api#length"];
    if (len) {
      if (len.min !== undefined) rule.minLength = len.min;
      if (len.max !== undefined) rule.maxLength = len.max;
    }
    const range = traits["smithy.api#range"];
    if (range) {
      if (range.min !== undefined) rule.min = Number(range.min);
      if (range.max !== undefined) rule.max = Number(range.max);
    }
    const pattern = traits["smithy.api#pattern"];
    if (pattern !== undefined) {
      const p = jsPattern(pattern);
      if (p !== undefined) rule.pattern = p;
    }
    const legacyEnum = traits["smithy.api#enum"];
    if (legacyEnum) rule.enum = legacyEnum.map((e) => e.value);
    if (traits["smithy.api#sensitive"]) rule.sensitive = true;
    if (traits["smithy.api#default"] !== undefined && typeof traits["smithy.api#default"] !== "object")
      rule.default = traits["smithy.api#default"];
  }

  function rule(id, memberTraits, depth, seen) {
    const s = shape(id);
    if (!s) return undefined;
    const kind = PRIMITIVE[s.type];
    const out = { type: kind ?? s.type };
    constraints(s.traits, out);
    if (s.type === "enum") {
      out.enum = Object.entries(s.members ?? {}).map(([name, m]) => m.traits?.["smithy.api#enumValue"] ?? name);
    } else if (s.type === "intEnum") {
      out.enum = Object.values(s.members ?? {}).map((m) => String(m.traits?.["smithy.api#enumValue"]));
    }
    // Member traits refine the target's.
    constraints(memberTraits, out);
    if (s.traits?.["smithy.api#required"] && !memberTraits?.["smithy.api#required"]) delete out.required;
    if (depth >= MAX_DEPTH || seen.has(id)) return out;
    const next = new Set(seen).add(id);
    if (s.type === "structure" || s.type === "union") {
      const fields = members(s, depth + 1, next);
      if (Object.keys(fields).length) out.fields = fields;
    } else if (s.type === "list" || s.type === "set") {
      const item = rule(s.member.target, s.member.traits, depth + 1, next);
      if (item && Object.keys(item).length > 1) out.item = item;
    } else if (s.type === "map") {
      const key = rule(s.key.target, s.key.traits, depth + 1, next);
      const value = rule(s.value.target, s.value.traits, depth + 1, next);
      if (key && Object.keys(key).length > 1) out.key = key;
      if (value && Object.keys(value).length > 1) out.value = value;
    }
    return out;
  }

  function members(s, depth, seen) {
    const out = {};
    for (const [name, m] of Object.entries(s.members ?? {})) {
      const r = rule(m.target, m.traits, depth, seen);
      if (r) out[name] = r;
    }
    return out;
  }

  const ops = {};
  for (const [id, s] of Object.entries(shapes)) {
    if (s.type !== "operation") continue;
    const name = id.split("#")[1];
    const input = s.input && shape(s.input.target);
    ops[name] = input ? members(input, 0, new Set([s.input.target])) : {};
  }
  return ops;
}

// IAM action prefixes that differ from the model's ARN namespace.
const PREFIX = { monitoring: "cloudwatch", "sso-oauth": "sso-oauth", awsssoportal: null };

/** Every operation of every model MWS serves, by IAM action prefix, for the
 * policy editor's action search:
 *   import { ACTIONS } from "@mws-dashboard/ui/model/actions"; // { s3: ["GetObject", ...] }
 */
function actionCatalog() {
  const actions = {};
  const names = {};
  for (const crate of readdirSync(crates).sort()) {
    const dir = join(crates, crate, "model");
    if (!existsSync(dir)) continue;
    for (const file of readdirSync(dir).sort()) {
      if (!file.endsWith(".json")) continue;
      const model = JSON.parse(readFileSync(join(dir, file), "utf8"));
      if (!model.shapes) continue;
      const service = Object.values(model.shapes).find((s) => s.type === "service");
      const traits = service?.traits ?? {};
      const ns = traits["aws.api#service"]?.arnNamespace ?? traits["aws.auth#sigv4"]?.name;
      const prefix = ns in PREFIX ? PREFIX[ns] : ns;
      if (!prefix) continue;
      const ops = Object.entries(model.shapes)
        .filter(([, s]) => s.type === "operation")
        .map(([id]) => id.split("#")[1]);
      actions[prefix] = [...new Set([...(actions[prefix] ?? []), ...ops])].sort();
      names[prefix] ??= traits["aws.api#service"]?.sdkId ?? prefix;
    }
  }
  const sorted = Object.fromEntries(Object.entries(actions).sort(([a], [b]) => a.localeCompare(b)));
  return (
    `// Generated by scripts/constraints.mjs from the models in crates/services. Do not edit.\n` +
    `/** IAM action names (without the prefix) by service prefix. */\nexport const ACTIONS: Record<string, string[]> = ${JSON.stringify(sorted)};\n` +
    `/** Each prefix's service name. */\nexport const ACTION_SERVICES: Record<string, string> = ${JSON.stringify(names)};\n`
  );
}

/** Write the constraint modules; returns how many were written. */
export function writeConstraints() {
  const files = new Map();
  for (const crate of readdirSync(crates).sort()) {
    const dir = join(crates, crate, "model");
    if (!existsSync(dir)) continue;
    for (const file of readdirSync(dir).sort()) {
      if (!file.endsWith(".json")) continue;
      const model = JSON.parse(readFileSync(join(dir, file), "utf8"));
      if (!model.shapes) continue;
      const stem = file.replace(/\.json$/, "");
      const ops = generate(model);
      let body = `// Generated by scripts/constraints.mjs from crates/services/${crate}/model/${file}. Do not edit.\nimport type { Rules } from "../validation.ts";\n`;
      for (const name of Object.keys(ops).sort()) {
        body += `\nexport const ${name}: Rules = ${JSON.stringify(ops[name])};\n`;
      }
      files.set(`${stem}.ts`, body);
    }
  }
  files.set("actions.ts", actionCatalog());
  rmSync(target, { recursive: true, force: true });
  mkdirSync(target, { recursive: true });
  for (const [f, text] of files) writeFileSync(join(target, f), text);
  return files.size;
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  console.log(`wrote ${writeConstraints()} model constraint files to packages/ui/src/model`);
}
