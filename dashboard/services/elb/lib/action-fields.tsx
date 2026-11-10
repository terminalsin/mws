"use client";

import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import type { Rule } from "@mws-dashboard/ui/validation";
import { useState } from "react";

export type ActionKind = "forward" | "redirect" | "fixed-response";

export interface ActionDefaults {
  type: ActionKind;
  /** Target group ARN → weight (one group is a plain forward). */
  groups?: Record<string, number>;
  stickiness?: number;
  redirect?: { protocol?: string; host?: string; port?: string; path?: string; query?: string; status?: string };
  fixed?: { status?: string; contentType?: string; body?: string };
}

export interface ConditionDefaults {
  host?: string;
  path?: string;
  method?: string;
  sourceIp?: string;
  headerName?: string;
  headerValues?: string;
  query?: string;
}

const STATUS: Rule = { required: true, pattern: "^(2|4|5)\\d\\d$", hint: "2xx, 4xx or 5xx" };
const WEIGHT: Rule = { type: "integer", min: 0, max: 999 };
const BODY: Rule = { maxLength: 1024 };
const REDIRECT_PART: Rule = { maxLength: 128 };

/** A listener's or rule's action: forward to one or more target groups
 * (weighted), redirect, or a fixed response. Network and Gateway Load
 * Balancers only forward. */
export function ActionFields({
  groups,
  defaults,
  kinds,
}: {
  groups: { arn: string; name: string; detail: string }[];
  defaults: ActionDefaults;
  kinds: ActionKind[];
}) {
  const [type, setType] = useState<ActionKind>(kinds.includes(defaults.type) ? defaults.type : kinds[0]);
  const [chosen, setChosen] = useState<Set<string>>(() => new Set(Object.keys(defaults.groups ?? {}).length ? Object.keys(defaults.groups!) : groups.length === 1 ? [groups[0].arn] : []));
  const toggle = (arn: string, on: boolean) =>
    setChosen((s) => {
      const n = new Set(s);
      if (on) n.add(arn);
      else n.delete(arn);
      return n;
    });
  return (
    <>
      {kinds.length > 1 ? (
        <Field label="Action" member="Actions">
          <select name="actionType" value={type} onChange={(e) => setType(e.target.value as ActionKind)}>
            {kinds.includes("forward") && <option value="forward">Forward to target groups</option>}
            {kinds.includes("redirect") && <option value="redirect">Redirect to URL</option>}
            {kinds.includes("fixed-response") && <option value="fixed-response">Return fixed response</option>}
          </select>
        </Field>
      ) : (
        <input type="hidden" name="actionType" value={type} />
      )}
      {type === "forward" && (
        <fieldset className="checks" aria-label="Target groups">
          {groups.length === 0 && <span className="muted">No compatible target groups</span>}
          {groups.map((g) => (
            <span key={g.arn} className="form-row">
              <label className="check">
                <input type="checkbox" name="group" value={g.arn} checked={chosen.has(g.arn)} onChange={(e) => toggle(g.arn, e.target.checked)} /> {g.name}
                <span className="muted">{g.detail}</span>
              </label>
              {chosen.size > 1 && chosen.has(g.arn) && (
                <Field label="Weight" rule={WEIGHT} member="ForwardConfig.TargetGroups.Weight">
                  <input name={`weight:${g.arn}`} type="number" defaultValue={defaults.groups?.[g.arn] ?? 1} />
                </Field>
              )}
            </span>
          ))}
        </fieldset>
      )}
      {type === "forward" && chosen.size > 1 && kinds.length > 1 && (
        <Field label="Group stickiness (seconds, 0 for off)" rule={{ type: "integer", min: 0, max: 604800, unit: "seconds" }}>
          <input name="stickiness" type="number" defaultValue={defaults.stickiness ?? 0} />
        </Field>
      )}
      {type === "redirect" && (
        <>
          <div className="form-row">
            <Field label="Protocol" member="RedirectConfig.Protocol">
              <select name="rProtocol" defaultValue={defaults.redirect?.protocol ?? "HTTPS"}>
                <option value="#{protocol}">Same</option>
                <option>HTTPS</option>
                <option>HTTP</option>
              </select>
            </Field>
            <Field label="Port" rule={{ pattern: "^(#\\{port\\}|\\d{1,5})$", hint: "1-65535 or #{port}" }} member="RedirectConfig.Port">
              <input name="rPort" defaultValue={defaults.redirect?.port ?? "443"} />
            </Field>
            <Field label="Status" member="RedirectConfig.StatusCode">
              <select name="rStatus" defaultValue={defaults.redirect?.status ?? "HTTP_301"}>
                <option value="HTTP_301">301 permanent</option>
                <option value="HTTP_302">302 found</option>
              </select>
            </Field>
          </div>
          <div className="form-row">
            <Field label="Host" rule={REDIRECT_PART} member="RedirectConfig.Host">
              <input name="rHost" defaultValue={defaults.redirect?.host ?? "#{host}"} />
            </Field>
            <Field label="Path" rule={REDIRECT_PART} member="RedirectConfig.Path">
              <input name="rPath" defaultValue={defaults.redirect?.path ?? "/#{path}"} />
            </Field>
            <Field label="Query" rule={REDIRECT_PART} member="RedirectConfig.Query">
              <input name="rQuery" defaultValue={defaults.redirect?.query ?? "#{query}"} />
            </Field>
          </div>
        </>
      )}
      {type === "fixed-response" && (
        <>
          <div className="form-row">
            <Field label="Status code" rule={STATUS} member="FixedResponseConfig.StatusCode">
              <input name="fStatus" defaultValue={defaults.fixed?.status ?? "404"} />
            </Field>
            <Field label="Content type" member="FixedResponseConfig.ContentType">
              <select name="fType" defaultValue={defaults.fixed?.contentType ?? "text/plain"}>
                {["text/plain", "text/css", "text/html", "application/javascript", "application/json"].map((t) => (
                  <option key={t}>{t}</option>
                ))}
              </select>
            </Field>
          </div>
          <Field label="Response body" rule={BODY} member="FixedResponseConfig.MessageBody">
            <textarea name="fBody" rows={2} defaultValue={defaults.fixed?.body ?? "Not found"} />
          </Field>
        </>
      )}
    </>
  );
}

const LIST: Rule = { pattern: "^[^,]+(\\s*,\\s*[^,]+){0,4}$", hint: "Up to 5, comma-separated" };

/** A rule's conditions: any of host, path, method, source IP, one header
 * and query strings; each takes several values, comma-separated. */
export function ConditionFields({ defaults }: { defaults: ConditionDefaults }) {
  return (
    <>
      <div className="form-row">
        <Field label="Host header" rule={LIST} member="HostHeaderConfig">
          <input name="host" defaultValue={defaults.host} placeholder="api.example.com, *.example.org" />
        </Field>
        <Field label="Path" rule={LIST} member="PathPatternConfig">
          <input name="path" defaultValue={defaults.path} placeholder="/api/*" />
        </Field>
      </div>
      <div className="form-row">
        <Field label="HTTP method" rule={{ pattern: "^[A-Za-z_-]+(\\s*,\\s*[A-Za-z_-]+)*$", hint: "Like GET, POST" }} member="HttpRequestMethodConfig">
          <input name="method" defaultValue={defaults.method} placeholder="GET, HEAD" />
        </Field>
        <Field label="Source IP" rule={LIST} member="SourceIpConfig">
          <input name="sourceIp" defaultValue={defaults.sourceIp} placeholder="10.0.0.0/8" />
        </Field>
      </div>
      <div className="form-row">
        <Field label="Header name" rule={{ maxLength: 40, pattern: "^[A-Za-z0-9!#$%&'*+.^_`|~-]+$", hint: "A header name" }} member="HttpHeaderConfig.HttpHeaderName">
          <input name="headerName" defaultValue={defaults.headerName} placeholder="X-Env" />
        </Field>
        <Field label="Header values" rule={LIST} member="HttpHeaderConfig.Values">
          <input name="headerValues" defaultValue={defaults.headerValues} placeholder="beta" />
        </Field>
      </div>
      <Field label="Query string (key=value, comma-separated)" rule={LIST} member="QueryStringConfig">
        <input name="query" defaultValue={defaults.query} placeholder="version=2" />
      </Field>
    </>
  );
}
