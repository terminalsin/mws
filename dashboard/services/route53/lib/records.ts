// Console-side checks for record sets, with repairs: what Route 53 would
// reject (or quietly misread), caught in the field before submitting. MWS
// itself only answers as Route 53 does.

import { FORMATS, type Issue, type Repair } from "@mws-dashboard/ui/validation";

const fix = (value: string, label: string): Repair => ({ value, label, kind: "fix" });
const issue = (message: string, ...repairs: (Repair | null | undefined | false)[]): Issue => ({
  code: "format",
  message,
  repairs: repairs.filter((r): r is Repair => !!r),
});

const bare = (name: string) => name.trim().replace(/\.$/, "").toLowerCase();

/** Why `value` is not a DNS name as Route 53 takes it (underscore labels
 * such as _dmarc, a leading `*.` and a trailing dot allowed), or null. */
export function dnsNameProblem(value: string): string | null {
  const v = value.replace(/\.$/, "").replace(/^\*\./, "");
  if (!/^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$/.test(v)) return "Like host.example.com";
  if (v.length > 253) return `${v.length - 253} over the 253-character limit`;
  const long = v.split(".").find((l) => l.length > 63);
  return long ? `${long.slice(0, 12)}… is over 63 characters` : null;
}

const domainOk = (v: string) => !dnsNameProblem(v);

/** The host of a pasted URL, address or `host:port`, when it is a name. */
function host(v: string): string | null {
  const h = v
    .trim()
    .replace(/^[a-z][\w+.-]*:\/\//i, "")
    .replace(/^[^@/]*@/, "")
    .split(/[/?#:]/)[0]
    .replace(/\s+/g, "-")
    .replace(/\.{2,}/g, ".")
    .toLowerCase();
  return h && domainOk(h) ? h : null;
}

export function ipv4(v: string) {
  return !FORMATS.ipv4.check(v, {});
}

export function ipv6(v: string) {
  if (!v.includes(":")) return false;
  try {
    new URL(`http://[${v}]/`);
    return true;
  } catch {
    return false;
  }
}

/** Problems with a record name in `zone`: not a DNS name, outside the zone,
 * or a CNAME at the apex. */
export function nameIssue(value: string, zone: string, type: string): Issue | null {
  const v = bare(value);
  const z = bare(zone);
  if (!v) return null;
  const problem = dnsNameProblem(value.trim());
  if (problem) {
    const h = host(value);
    return issue(problem, h && h !== value && fix(h, "Use the host name"));
  }
  if (v === z && type === "CNAME") return issue("No CNAME at the zone apex; use an alias or another name", fix(`www.${z}`, "Use www"));
  if (v === z || v.endsWith(`.${z}`)) return null;
  const label = v.split(".")[0];
  return issue(
    `Not in ${z}`,
    // "www" → www.example.com; www.other.com → www.example.com
    !v.includes(".") ? fix(`${v}.${z}`, `Add .${z}`) : fix(`${label}.${z}`, `Move into ${z}`),
    v.includes(".") && fix(`${v}.${z}`, `Add .${z}`),
  );
}

const lines = (value: string) => value.split("\n").map((l) => l.trim()).filter(Boolean);

/** Replace line `i` of a multi-line value. */
const swap = (all: string[], i: number, line: string) => all.map((l, j) => (j === i ? line : l)).join("\n");

/** Quote TXT data the way Route 53 wants it: strings of at most 255
 * characters, each in double quotes. */
function quoted(text: string): string {
  const escaped = text.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  const parts: string[] = [];
  for (let i = 0; i < escaped.length; ) {
    let end = Math.min(i + 255, escaped.length);
    // Never split an escape.
    if (escaped[end - 1] === "\\" && end < escaped.length) end--;
    parts.push(escaped.slice(i, end));
    i = end;
  }
  return parts.map((p) => `"${p}"`).join(" ");
}

function txtStrings(v: string): string[] | null {
  const strings = [...v.matchAll(/"((?:\\.|[^"\\])*)"\s*/g)];
  if (strings.map((m) => m[0]).join("").trim() !== v.trim()) return null;
  return strings.map((m) => m[1]);
}

/** One value of a record of `type`: a problem and its repairs (for the
 * value in place), or null. */
function valueIssue(type: string, v: string): Issue | null {
  const fields = v.split(/\s+/);
  const u16 = (f: string) => /^\d{1,5}$/.test(f) && Number(f) <= 65535;
  switch (type) {
    case "A":
      if (ipv4(v)) return null;
      if (ipv6(v)) return issue("An IPv6 address belongs in an AAAA record");
      if (ipv4(v.replace(/\/\d+$|:\d+$/, ""))) return issue("Just the address", fix(v.replace(/\/\d+$|:\d+$/, ""), "Drop the suffix"));
      if (host(v)) return issue("A host name belongs in a CNAME or an alias");
      return issue("Like 192.0.2.1");
    case "AAAA":
      if (ipv6(v)) return null;
      if (ipv4(v)) return issue("An IPv4 address belongs in an A record", fix(`::ffff:${v}`, "Map to IPv6"));
      return issue("Like 2001:db8::1");
    case "CNAME":
    case "NS":
    case "PTR": {
      if (domainOk(v)) return null;
      const h = host(v);
      return issue("Like host.example.com", h ? fix(h, "Use the host name") : null);
    }
    case "MX": {
      if (fields.length === 2 && u16(fields[0]) && domainOk(fields[1])) return null;
      const h = fields.length === 1 ? host(v) : null;
      if (h) return issue("Priority first, like 10 mail.example.com", fix(`10 ${h}`, "Priority 10"));
      if (fields.length === 2 && u16(fields[1]) && domainOk(fields[0])) return issue("Priority first", fix(`${fields[1]} ${fields[0]}`, "Swap"));
      return issue("Like 10 mail.example.com");
    }
    case "SRV": {
      if (fields.length === 4 && fields.slice(0, 3).every(u16) && domainOk(fields[3])) return null;
      // host:port, as people usually write a service's address.
      const m = fields.length === 1 && v.match(/^(.+):(\d{1,5})$/);
      if (m && domainOk(m[1]) && u16(m[2])) return issue("Priority weight port host", fix(`10 5 ${m[2]} ${m[1]}`, "Expand"));
      return issue("Priority weight port host, like 10 5 443 svc.example.com");
    }
    case "CAA": {
      const m = v.match(/^(\d{1,3})\s+(issue|issuewild|iodef)\s+(.+)$/i);
      if (m && Number(m[1]) <= 255 && /^".*"$/.test(m[3])) return null;
      if (m) return issue("The value goes in quotes", fix(`${m[1]} ${m[2].toLowerCase()} "${m[3].replace(/^"|"$/g, "")}"`, "Add quotes"));
      if (fields.length === 1 && domainOk(v)) return issue("Flag, tag and value", fix(`0 issue "${bare(v)}"`, `Let ${bare(v)} issue`));
      return issue('Like 0 issue "amazon.com"');
    }
    case "TXT":
    case "SPF": {
      const strings = txtStrings(v);
      if (strings && strings.every((s) => s.replace(/\\./g, "x").length <= 255)) return null;
      const text = strings ? strings.join("") : v.replace(/^"|"$/g, "");
      if (strings) return issue("Each string is at most 255 characters", fix(quoted(text), "Split"));
      // Unquoted text is split on spaces by Route 53.
      if (/\s/.test(v) || text.length > 255) return issue("Text goes in quotes", fix(quoted(text), "Add quotes"));
      return null;
    }
    default:
      return null;
  }
}

/** Problems with a record's values (one per line) for `type`. */
export function valuesIssue(type: string, value: string, aliased: boolean): Issue | null {
  const all = lines(value);
  if (aliased) return null;
  if (!all.length) return { code: "required", message: "Required", repairs: [] };
  // Several addresses on one line: one per line.
  if (all.length === 1 && /[,;\s]/.test(all[0]) && (type === "A" || type === "AAAA" || type === "NS")) {
    const split = all[0].split(/[,;\s]+/).filter(Boolean);
    if (split.length > 1 && split.every((s) => !valueIssue(type, s))) return issue("One per line", fix(split.join("\n"), "Split into lines"));
  }
  if (type === "CNAME" && all.length > 1) return issue("A CNAME has one value", fix(all[0], "Keep the first"));
  for (const [i, v] of all.entries()) {
    const problem = valueIssue(type, v);
    if (problem) {
      return {
        ...problem,
        message: all.length > 1 ? `Line ${i + 1}: ${problem.message}` : problem.message,
        repairs: problem.repairs.map((r) => ({ ...r, value: swap(all, i, r.value) })),
      };
    }
  }
  const dupes = all.filter((v, i) => all.indexOf(v) !== i);
  if (dupes.length) return issue("Listed twice", fix([...new Set(all)].join("\n"), "Remove duplicates"));
  return null;
}

/** Turn a Route 53 InvalidChangeBatch message into the field it concerns. */
export function changeBatchField(message: string): { field: string; message: string } | null {
  const value = message.match(/FATAL problem: \w+ \(([^)]+)\) encountered with/);
  if (value) return { field: "values", message: value[1] };
  if (/is not permitted in zone/.test(message)) return { field: "name", message: "Not in this zone" };
  if (/at apex/.test(message)) return { field: "name", message: "No CNAME at the zone apex" };
  if (/conflicts with other records|conflicting RRSet of type CNAME/.test(message)) return { field: "type", message: "Conflicts with a CNAME of the same name" };
  if (/more than one record/.test(message)) return { field: "values", message: "A CNAME has one value" };
  return null;
}
