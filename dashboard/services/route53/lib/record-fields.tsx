"use client";

import { FieldShell as Field, setControlValue } from "@mws-dashboard/ui/fields";
import type { Rule } from "@mws-dashboard/ui/validation";
import { useCallback, useRef, useState } from "react";

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
const ALIAS: Rule = { required: true, maxLength: 1024 };
const ZONE: Rule = { required: true, maxLength: 32, pattern: "^Z[A-Z0-9]{1,31}$", hint: "Like Z35SXDOTRQ7X7K" };
const SET_ID: Rule = { required: true, minLength: 1, maxLength: 128 };
const WEIGHT: Rule = { required: true, type: "integer", min: 0, max: 255 };
const LOCATION: Rule = { required: true, minLength: 1, maxLength: 16, pattern: "^[0-9A-Za-z_\\-*]+$" };

export const POLICIES = {
  simple: "Simple",
  weighted: "Weighted",
  latency: "Latency",
  failover: "Failover",
  geo: "Geolocation",
  multivalue: "Multivalue answer",
  cidr: "IP-based",
} as const;
export type Policy = keyof typeof POLICIES;

/** Where an alias can point: a target's DNS name with the hosted zone
 * Route 53 needs for it. */
export interface AliasTarget {
  group: string;
  label: string;
  dns: string;
  zone: string;
  /** Route 53 can evaluate this target's health. */
  health: boolean;
}

export interface RecordDefaults {
  name: string;
  type: string;
  values: string;
  ttl: number;
  alias?: string;
  aliasZone?: string;
  evaluate?: boolean;
  policy: Policy;
  setId?: string;
  weight?: number;
  region?: string;
  failover?: string;
  geo?: string;
  healthCheck?: string;
  cidrCollection?: string;
  cidrLocation?: string;
}

export interface RecordChoices {
  targets: AliasTarget[];
  healthChecks: { id: string; label: string }[];
  geos: { value: string; label: string }[];
  regions: string[];
  cidr: { id: string; name: string; locations: string[] }[];
}

/** The record set's fields: the value checks follow the chosen type, an
 * alias target replaces the values, and the routing policy adds what it
 * needs (set identifier, weight, Region, failover role, location). */
export function RecordFields({ zone, zoneId, defaults, names, choices }: { zone: string; zoneId: string; defaults: RecordDefaults; names: string[]; choices: RecordChoices }) {
  const [type, setType] = useState(defaults.type);
  const [alias, setAlias] = useState(!!defaults.alias);
  const [policy, setPolicy] = useState<Policy>(defaults.policy);
  const [dns, setDns] = useState(defaults.alias ?? "");
  const dnsInput = useRef<HTMLInputElement>(null);
  const zoneInput = useRef<HTMLInputElement>(null);
  const [collection, setCollection] = useState(defaults.cidrCollection ?? choices.cidr[0]?.id ?? "");
  const checkName = useCallback((v: string) => nameIssue(v, zone, type), [zone, type]);
  const checkValues = useCallback((v: string) => valuesIssue(type, v, alias), [type, alias]);
  const checkAlias = useCallback((v: string) => (v.trim() ? valuesIssue("CNAME", v, false) : null), []);
  const target = choices.targets.find((t) => t.dns.replace(/\.$/, "").toLowerCase() === dns.replace(/\.$/, "").toLowerCase());
  const groups = [...new Set(choices.targets.map((t) => t.group))];
  // Through the controls' own events, so their fields re-check the values.
  const typedDns = (value: string) => {
    setDns(value);
    const t = choices.targets.find((x) => x.dns.replace(/\.$/, "").toLowerCase() === value.trim().replace(/\.$/, "").toLowerCase());
    if (t && zoneInput.current && zoneInput.current.value !== t.zone) setControlValue(zoneInput.current, t.zone);
  };
  const pickDns = (value: string) => {
    if (dnsInput.current) setControlValue(dnsInput.current, value);
    typedDns(value);
  };
  const locations = choices.cidr.find((c) => c.id === collection)?.locations ?? [];
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
      <label className="check">
        <input type="checkbox" name="aliasOn" checked={alias} onChange={(e) => setAlias(e.target.checked)} disabled={policy === "multivalue"} /> Alias
      </label>
      {alias && policy !== "multivalue" ? (
        <>
          {choices.targets.length > 0 && (
            <Field label="Route traffic to">
              <select value={target ? target.dns : ""} onChange={(e) => e.target.value && pickDns(e.target.value)} aria-label="Alias target">
                <option value="">Enter a DNS name</option>
                {groups.map((g) => (
                  <optgroup key={g} label={g}>
                    {choices.targets
                      .filter((t) => t.group === g)
                      .map((t) => (
                        <option key={`${t.zone}:${t.dns}`} value={t.dns}>
                          {t.label}
                        </option>
                      ))}
                  </optgroup>
                ))}
              </select>
            </Field>
          )}
          <div className="form-row">
            <Field label="Alias target" rule={ALIAS} known={names} validate={checkAlias} member="AliasTarget.DNSName">
              <input ref={dnsInput} name="alias" placeholder="my-alb-123.us-east-1.elb.amazonaws.com" defaultValue={defaults.alias} onInput={(e) => typedDns(e.currentTarget.value)} />
            </Field>
            <Field label="Target hosted zone" rule={ZONE} member="AliasTarget.HostedZoneId">
              <input ref={zoneInput} name="aliasZone" defaultValue={defaults.aliasZone ?? zoneId} />
            </Field>
          </div>
          <label className="check">
            <input type="checkbox" name="evaluate" defaultChecked={defaults.evaluate ?? target?.health ?? false} /> Evaluate target health
          </label>
        </>
      ) : (
        <>
          <Field label="Value" validate={checkValues} member="ResourceRecords">
            <textarea name="values" rows={3} placeholder={PLACEHOLDER[type]} className="code-editor" defaultValue={defaults.values} />
          </Field>
          <Field label="TTL (seconds)" rule={TTL} member="TTL">
            <input name="ttl" type="number" defaultValue={defaults.ttl} />
          </Field>
        </>
      )}
      <Field label="Routing policy">
        <select name="policy" value={policy} onChange={(e) => setPolicy(e.target.value as Policy)}>
          {Object.entries(POLICIES).map(([k, v]) => (
            <option key={k} value={k}>
              {v}
            </option>
          ))}
        </select>
      </Field>
      {policy !== "simple" && (
        <div className="form-row">
          <Field label="Record ID" rule={SET_ID} member="SetIdentifier">
            <input name="setId" defaultValue={defaults.setId} placeholder="primary" />
          </Field>
          {policy === "weighted" && (
            <Field label="Weight" rule={WEIGHT} member="Weight">
              <input name="weight" type="number" defaultValue={defaults.weight ?? 100} />
            </Field>
          )}
          {policy === "latency" && (
            <Field label="Region" member="Region">
              <select name="region" defaultValue={defaults.region ?? choices.regions[0]}>
                {choices.regions.map((r) => (
                  <option key={r}>{r}</option>
                ))}
              </select>
            </Field>
          )}
          {policy === "failover" && (
            <Field label="Failover record type" member="Failover">
              <select name="failover" defaultValue={defaults.failover ?? "PRIMARY"}>
                <option value="PRIMARY">Primary</option>
                <option value="SECONDARY">Secondary</option>
              </select>
            </Field>
          )}
          {policy === "geo" && (
            <Field label="Location" member="GeoLocation">
              <select name="geo" defaultValue={defaults.geo ?? "*"}>
                {choices.geos.map((g) => (
                  <option key={g.value} value={g.value}>
                    {g.label}
                  </option>
                ))}
              </select>
            </Field>
          )}
        </div>
      )}
      {policy === "cidr" && (
        <div className="form-row">
          <Field label="CIDR collection" member="CidrRoutingConfig.CollectionId">
            <select name="cidrCollection" value={collection} onChange={(e) => setCollection(e.target.value)} required>
              {choices.cidr.length === 0 && <option value="">No CIDR collections</option>}
              {choices.cidr.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                </option>
              ))}
            </select>
          </Field>
          <Field label="CIDR location" rule={LOCATION} known={["*", ...locations]} member="CidrRoutingConfig.LocationName">
            <input name="cidrLocation" defaultValue={defaults.cidrLocation ?? locations[0] ?? "*"} />
          </Field>
        </div>
      )}
      {(policy !== "simple" || defaults.healthCheck) && (
        <Field label="Health check" member="HealthCheckId">
          <select name="healthCheck" defaultValue={defaults.healthCheck ?? ""}>
            <option value="">None</option>
            {choices.healthChecks.map((h) => (
              <option key={h.id} value={h.id}>
                {h.label}
              </option>
            ))}
          </select>
        </Field>
      )}
    </>
  );
}
