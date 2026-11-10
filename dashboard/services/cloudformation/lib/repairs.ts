// Repairs for the errors CloudFormation returns about a template or its
// parameters. AWS answers a broken template with one ValidationError
// ("Template format error: ..."); the console reads which name it objects
// to, finds the closest one the template (or the registry) does have, and
// offers the fixed template as a one-click repair on the field.
import { FieldError } from "@mws-dashboard/aws";
import { closest, type Repair } from "@mws-dashboard/ui/validation";

const SECTIONS = ["AWSTemplateFormatVersion", "Description", "Metadata", "Parameters", "Rules", "Mappings", "Conditions", "Transform", "Resources", "Outputs", "Hooks"];
const ATTRIBUTES = ["Type", "Properties", "DependsOn", "Metadata", "Condition", "DeletionPolicy", "UpdateReplacePolicy", "UpdatePolicy", "CreationPolicy"];

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const names = (list: string) => list.split(/,\s*/).filter(Boolean);

/** The logical ids a template section declares (`Resources`, `Parameters`),
 * from JSON or from the section's first indentation level in YAML. */
export function sectionKeys(template: string, section: string): string[] {
  try {
    const doc = JSON.parse(template) as Record<string, unknown>;
    const s = doc[section];
    return s && typeof s === "object" ? Object.keys(s) : [];
  } catch {
    // YAML
  }
  const lines = template.split("\n");
  const start = lines.findIndex((l) => new RegExp(`^${section}:\\s*(#.*)?$`).test(l));
  if (start < 0) return [];
  const out: string[] = [];
  let indent: string | undefined;
  for (const line of lines.slice(start + 1)) {
    if (/^\S/.test(line) && !line.startsWith("#")) break;
    const m = line.match(/^(\s+)["']?([A-Za-z0-9]+)["']?\s*:/);
    if (!m) continue;
    indent ??= m[1];
    if (m[1] === indent) out.push(m[2]);
  }
  return out;
}

/** Replace a name where the template uses it as a value (Ref, GetAtt, Sub,
 * DependsOn), not where it is a key. */
function replaceRef(template: string, from: string, to: string) {
  return template.replace(new RegExp(`(?<![\\w:-])${escape(from)}(?![\\w-]|\\s*:(\\s|$))`, "g"), to);
}

/** Replace a key (YAML `Key:` or JSON `"Key":`). */
function replaceKey(template: string, from: string, to: string, topLevel = false) {
  const yaml = new RegExp(`^(${topLevel ? "" : "\\s+"})${escape(from)}(\\s*:)`, "gm");
  return template.replace(yaml, `$1${to}$2`).replace(new RegExp(`"${escape(from)}"(\\s*:)`, "g"), `"${to}"$1`);
}

/** One repair per close candidate for a single name, or one that fixes every
 * name with a close candidate when there are several. */
function renames(bad: string[], candidates: string[], apply: (value: string, from: string, to: string) => string, value: string): Repair[] {
  if (bad.length === 1) {
    return closest(bad[0], candidates).map((to) => ({ value: apply(value, bad[0], to), label: `Use ${to}`, kind: "suggest" as const }));
  }
  let fixed = value;
  const done: string[] = [];
  for (const b of bad) {
    const [to] = closest(b, candidates, 1);
    if (!to) continue;
    fixed = apply(fixed, b, to);
    done.push(to);
  }
  return done.length ? [{ value: fixed, label: `Use ${done.join(", ")}`, kind: "suggest" }] : [];
}

/** A template error CloudFormation returned, as an issue on the template
 * field with the repairs that would fix it, or null when it is not one. */
export async function templateError(message: string, template: string, resourceTypes: () => Promise<string[]>): Promise<FieldError | null> {
  const m = message.match(/^Template (?:format )?error: (.*)$/s);
  if (!m) return null;
  const detail = m[1].trim();
  const field = (text: string, repairs: Repair[] = []) => new FieldError("template", text, "server", undefined, repairs);
  let x: RegExpMatchArray | null;
  if ((x = detail.match(/^Unresolved (?:resource )?dependencies \[([^\]]+)\]/))) {
    const bad = names(x[1]);
    const ids = [...sectionKeys(template, "Resources"), ...sectionKeys(template, "Parameters")];
    return field(`Nothing named ${bad.join(", ")} in the template`, renames(bad, ids, replaceRef, template));
  }
  if ((x = detail.match(/references undefined resource (\S+)/))) {
    return field(`No resource named ${x[1]}`, renames([x[1]], sectionKeys(template, "Resources"), replaceRef, template));
  }
  if ((x = detail.match(/^Unrecognized resource types: \[([^\]]+)\]/))) {
    const bad = names(x[1]);
    const known = await resourceTypes().catch(() => []);
    const swap = (v: string, from: string, to: string) => v.replace(new RegExp(`(?<![\\w:])${escape(from)}(?![\\w:])`, "g"), to);
    return field(`Unknown resource type ${bad.join(", ")}`, renames(bad, known, swap, template));
  }
  if ((x = detail.match(/Invalid template resource property '([^']+)'/))) {
    return field(`${x[1]} isn't a resource attribute`, renames([x[1]], ATTRIBUTES, (v, f, t) => replaceKey(v, f, t), template));
  }
  if ((x = detail.match(/^Invalid template property or properties \[([^\]]+)\]/))) {
    const bad = names(x[1]);
    return field(`${bad.join(", ")} isn't a template section`, renames(bad, SECTIONS, (v, f, t) => replaceKey(v, f, t, true), template));
  }
  if ((x = detail.match(/^'([^']*)' is not a valid template version/))) {
    const fixed = template.replace(/^(\s*"?AWSTemplateFormatVersion"?\s*:\s*)(["']?)[^"'\s,}]*\2/m, '$1"2010-09-09"');
    return field("The only template version is 2010-09-09", fixed !== template ? [{ value: fixed, label: "Use 2010-09-09", kind: "fix" }] : []);
  }
  return field(detail.replace(/\.$/, ""));
}

/** Parameter errors ("Parameters: [X] do not exist in the template", "...
 * must have values") as an issue on the parameters field. */
export function parametersError(message: string, template: string, parameters: string): FieldError | null {
  const m = message.match(/^Parameters: \[([^\]]+)\] (do not exist in the template|must have values)/);
  if (!m) return null;
  const bad = names(m[1]);
  const lines = parameters.split("\n");
  const key = (l: string) => l.slice(0, l.indexOf("=")).trim();
  if (m[2] === "must have values") {
    const added = [...lines.filter((l) => l.trim() && !bad.includes(key(l))), ...bad.map((b) => `${b}=`)].join("\n");
    return new FieldError("parameters", `${bad.join(", ")} need${bad.length === 1 ? "s" : ""} a value`, "required", undefined, [
      { value: added, label: `Add ${bad.join(", ")}`, kind: "fix" },
    ]);
  }
  const declared = sectionKeys(template, "Parameters");
  const rename = (v: string, from: string, to: string) =>
    v
      .split("\n")
      .map((l) => (key(l) === from ? `${to}=${l.slice(l.indexOf("=") + 1)}` : l))
      .join("\n");
  const repairs = renames(bad, declared, rename, parameters);
  repairs.push({ value: lines.filter((l) => !bad.includes(key(l))).join("\n"), label: `Remove ${bad.join(", ")}`, kind: "fix" });
  return new FieldError("parameters", `${bad.join(", ")} ${bad.length === 1 ? "isn't a parameter" : "aren't parameters"} of the template`, "server", undefined, repairs);
}
