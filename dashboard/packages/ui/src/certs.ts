// Formats for certificate forms (ACM, and any page taking DNS names or PEM):
// `dnsName` (a domain name, wildcards allowed), PEM `certificate` (exactly
// one), `certificates` (a chain) and `privateKey` (unencrypted). Spread into
// `FORMATS` in validation.ts.

import type { FormatSpec, Repair } from "./validation.ts";

const TLD_TYPOS: Record<string, string> = { con: "com", cmo: "com", ocm: "com", vom: "com", xom: "com", comm: "com", nte: "net", ent: "net", ogr: "org", rog: "org" };

export const CERT_FORMATS: Record<"dnsName" | "certificate" | "certificates" | "privateKey", FormatSpec> = {
  dnsName: {
    check(value) {
      if (/[/:@?#]/.test(value)) return "Just the domain name";
      if (value.endsWith(".")) return "No trailing dot";
      if (value.includes("*") && !/^\*\.[^*]+$/.test(value)) return "A wildcard is the first label only: *.example.com";
      const labels = value.replace(/^\*\./, "").split(".");
      if (labels.length < 2) return "Needs a top-level domain, like example.com";
      if (labels.some((l) => l === "")) return "Two dots in a row";
      if (labels.some((l) => !/^[A-Za-z0-9-]+$/.test(l))) return "Letters, digits, - and . only";
      if (labels.some((l) => l.length > 63)) return "A label is longer than 63 characters";
      if (labels.some((l) => /^-|-$/.test(l))) return "A label starts or ends with -";
      const tld = TLD_TYPOS[labels[labels.length - 1].toLowerCase()];
      return tld ? `Did you mean .${tld}?` : null;
    },
    repair(value) {
      let v = value
        .trim()
        .toLowerCase()
        .replace(/^[a-z][\w+.-]*:\/\//, "")
        .replace(/^[^@/]*@/, "")
        .replace(/[/?#].*$/, "")
        .replace(/:\d*$/, "")
        .replace(/_/g, "-")
        .replace(/\.{2,}/g, ".")
        .replace(/^\.+|\.+$/g, "")
        .replace(/^\*(?!\.)/, "*.")
        .replace(/^.*\*\./, "*.")
        .split(".")
        .map((l) => (l === "*" ? l : l.replace(/^-+|-+$/g, "")))
        .join(".");
      const labels = v.split(".");
      const tld = TLD_TYPOS[labels[labels.length - 1]];
      if (tld) v = [...labels.slice(0, -1), tld].join(".");
      const out: Repair[] = [{ value: v, label: tld ? `Did you mean .${tld}?` : "Clean up the name", kind: tld ? "suggest" : "fix" }];
      if (v && labels.length === 1) out.push({ value: `${v}.com`, label: "Add .com", kind: "suggest" });
      return out;
    },
  },
  certificate: pemFormat("certificate"),
  certificates: pemFormat("certificates"),
  privateKey: pemFormat("privateKey"),
};

// PEM: one certificate, a chain of them, or an unencrypted private key.
type PemKind = "certificate" | "certificates" | "privateKey";

const PEM_BLOCKS = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;
const KEY_LABEL = /^(RSA |EC )?PRIVATE KEY$/;

export function pemBlocks(value: string): { label: string; body: string }[] {
  return [...value.matchAll(PEM_BLOCKS)].map((m) => ({ label: m[1], body: m[2].replace(/\s+/g, "") }));
}

function pemWrap(label: string, base64: string): string {
  return `-----BEGIN ${label}-----\n${base64.match(/.{1,64}/g)!.join("\n")}\n-----END ${label}-----\n`;
}

function pemFormat(kind: PemKind): FormatSpec {
  const want = kind === "privateKey" ? "PRIVATE KEY" : "CERTIFICATE";
  return {
    check(value) {
      if (/\\n/.test(value) && !value.trim().includes("\n")) return "Line breaks are escaped as \\n";
      const blocks = pemBlocks(value);
      if (blocks.length === 0) {
        const begin = value.match(/-----BEGIN ([A-Z0-9 ]+)-----/);
        if (begin) return `Missing -----END ${begin[1]}-----`;
        return /^[A-Za-z0-9+/=\s]+$/.test(value) ? "Missing the BEGIN and END lines" : `Not PEM; starts with -----BEGIN ${want}-----`;
      }
      for (const b of blocks) {
        if (b.label === "EC PARAMETERS" && kind === "privateKey") continue;
        if (b.label === "ENCRYPTED PRIVATE KEY") return "Encrypted; decrypt it first (openssl pkey -in key.pem)";
        if (kind === "privateKey" && !KEY_LABEL.test(b.label)) return b.label === "CERTIFICATE" ? "This is a certificate, not its key" : `A ${b.label.toLowerCase()}, not a private key`;
        if (kind !== "privateKey" && b.label !== "CERTIFICATE") return KEY_LABEL.test(b.label) ? "This is a private key, not a certificate" : `A ${b.label.toLowerCase()}, not a certificate`;
        if (!/^[A-Za-z0-9+/]+=*$/.test(b.body)) return "The base64 inside is damaged";
      }
      if (kind === "certificate" && blocks.length > 1) return `${blocks.length} certificates; the others belong in the chain`;
      return null;
    },
    repair(value) {
      const out: Repair[] = [];
      if (/\\n/.test(value)) out.push({ value: value.replace(/\\r/g, "").replace(/\\n/g, "\n"), label: "Restore the line breaks", kind: "fix" });
      const blocks = pemBlocks(value);
      const bare = value.replace(/\s+/g, "");
      if (blocks.length === 0 && /^[A-Za-z0-9+/]+=*$/.test(bare)) {
        out.push({ value: pemWrap(want, bare), label: "Add the BEGIN and END lines", kind: "fix" });
      }
      const begin = value.match(/-----BEGIN ([A-Z0-9 ]+)-----/);
      if (blocks.length === 0 && begin) out.push({ value: `${value.trimEnd()}\n-----END ${begin[1]}-----\n`, label: "Add the END line", kind: "fix" });
      if (kind === "certificate" && blocks.length > 1) out.push({ value: pemWrap(blocks[0].label, blocks[0].body), label: "Keep the first certificate", kind: "fix" });
      return out;
    },
  };
}
