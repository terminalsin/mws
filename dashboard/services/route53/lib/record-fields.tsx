"use client";

import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import type { Rule } from "@mws-dashboard/ui/validation";
import { useCallback, useState } from "react";

import { nameIssue, valuesIssue } from "./records";

const TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA", "PTR", "SOA", "DS", "NAPTR", "SPF", "HTTPS", "SVCB"];

const PLACEHOLDER: Record<string, string> = {
  A: "192.0.2.1",
  AAAA: "2001:db8::1",
  CNAME: "app.example.net",
  MX: "10 mail.example.com",
  TXT: '"v=spf1 include:amazonses.com ~all"',
  SPF: '"v=spf1 -all"',
  NS: "ns-1.awsdns-01.org",
  SRV: "10 5 443 svc.example.com",
  CAA: '0 issue "amazon.com"',
  PTR: "host.example.com",
};

// ResourceRecordSet's members, as Route 53 documents them (the generated
// model rules stop above this depth).
const NAME: Rule = { required: true, maxLength: 1024 };
const TTL: Rule = { type: "integer", min: 0, max: 2147483647, unit: "seconds" };
const ALIAS: Rule = { maxLength: 1024 };

export interface RecordDefaults {
  name: string;
  type: string;
  values: string;
  ttl: number;
  alias?: string;
  aliasZone?: string;
}

/** The record set's fields: the value checks follow the chosen type, and
 * an alias target replaces the values. */
export function RecordFields({ zone, defaults, names }: { zone: string; defaults: RecordDefaults; names: string[] }) {
  const [type, setType] = useState(defaults.type);
  const [alias, setAlias] = useState(!!defaults.alias);
  const checkName = useCallback((v: string) => nameIssue(v, zone, type), [zone, type]);
  const checkValues = useCallback((v: string) => valuesIssue(type, v, alias), [type, alias]);
  const checkAlias = useCallback((v: string) => (v.trim() ? valuesIssue("CNAME", v, false) : null), []);
  return (
    <>
      <div className="form-row">
        <Field label="Record name" rule={NAME} validate={checkName} member="Name">
          <input name="name" defaultValue={defaults.name} />
        </Field>
        <Field label="Type" member="Type">
          <select name="type" defaultValue={defaults.type} onChange={(e) => setType(e.target.value)}>
            {TYPES.map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
        </Field>
      </div>
      <Field label="Value" validate={checkValues} member="ResourceRecords">
        <textarea name="values" rows={3} placeholder={PLACEHOLDER[type]} className="code-editor" defaultValue={defaults.values} disabled={alias} />
      </Field>
      <div className="form-row">
        <Field label="TTL (seconds)" rule={TTL} member="TTL">
          <input name="ttl" type="number" defaultValue={defaults.ttl} disabled={alias} />
        </Field>
        <Field label="Alias target" rule={ALIAS} known={names} validate={checkAlias} member="AliasTarget.DNSName">
          <input
            name="alias"
            placeholder="my-alb-123.us-east-1.elb.amazonaws.com"
            defaultValue={defaults.alias}
            onInput={(e) => setAlias(e.currentTarget.value.trim() !== "")}
          />
        </Field>
      </div>
      <input type="hidden" name="aliasZone" defaultValue={defaults.aliasZone} />
    </>
  );
}
