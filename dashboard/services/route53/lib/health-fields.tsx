"use client";

import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import { MoreFields, PresetGallery, type PresetItem } from "@mws-dashboard/ui/presets";
import type { Rule, Rules } from "@mws-dashboard/ui/validation";
import { Plug, Sigma } from "lucide-react";
import { useState } from "react";

export type HealthKind = "http" | "TCP" | "CALCULATED" | "CLOUDWATCH_METRIC";

export interface HealthDefaults {
  name?: string;
  kind: HealthKind;
  url?: string;
  host?: string;
  port?: number;
  search?: string;
  interval?: number;
  threshold?: number;
  regions?: string[];
  inverted?: boolean;
  disabled?: boolean;
  children?: string[];
  healthThreshold?: number;
  alarm?: string;
  alarmRegion?: string;
  insufficient?: string;
}

// What a health check watches, as tiles.
const KINDS: (PresetItem & { id: HealthKind })[] = [
  { id: "http", label: "Web endpoint", icon: "resource/Internet", title: "An HTTP or HTTPS URL" },
  { id: "TCP", label: "TCP port", icon: <Plug size={26} aria-hidden />, title: "A host and port that accepts connections" },
  { id: "CALCULATED", label: "Other checks", icon: <Sigma size={26} aria-hidden />, title: "Healthy when enough of other health checks are" },
  { id: "CLOUDWATCH_METRIC", label: "Alarm", icon: "service/AmazonCloudWatch", title: "Follows a CloudWatch alarm's state" },
];

const NAME: Rule = { maxLength: 256 };
const HOST: Rule = { required: true, maxLength: 255 };

/** A health check's settings: what it watches depends on its kind (an
 * endpoint by URL or host and port, other checks, or an alarm). Kind and
 * interval are fixed once created. */
export function HealthFields({
  rules,
  defaults,
  others,
  checkerRegions,
  editing,
}: {
  rules: Rules;
  defaults: HealthDefaults;
  others: { id: string; label: string }[];
  checkerRegions: string[];
  editing?: boolean;
}) {
  const [kind, setKind] = useState<HealthKind>(defaults.kind);
  const [custom, setCustom] = useState(!!defaults.regions?.length);
  const endpoint = kind === "http" || kind === "TCP";
  return (
    <>
      {editing ? (
        <input type="hidden" name="kind" value={kind} />
      ) : (
        <>
          <PresetGallery presets={KINDS} chosen={kind} choose={(k) => setKind(k.id)} label="What to monitor" testId="health-kind" />
          <input type="hidden" name="kind" value={kind} />
        </>
      )}
      <Field label="Name" rule={NAME} member="Tags.Name">
        <input name="checkName" defaultValue={defaults.name} placeholder="api-primary" />
      </Field>
      {kind === "http" && (
        <>
          <Field label="Endpoint URL" format="url" member="FullyQualifiedDomainName">
            <input name="url" required placeholder="https://example.com/health" defaultValue={defaults.url} />
          </Field>
          <Field label="Search string" rule={rules.SearchString} member="SearchString">
            <input name="search" defaultValue={defaults.search} placeholder="OK" />
          </Field>
        </>
      )}
      {kind === "TCP" && (
        <div className="form-row">
          <Field label="Domain name or IP" rule={HOST} member="FullyQualifiedDomainName">
            <input name="host" defaultValue={defaults.host} placeholder="db.example.com" />
          </Field>
          <Field label="Port" rule={rules.Port} format="port" member="Port">
            <input name="port" type="number" required defaultValue={defaults.port ?? 443} />
          </Field>
        </div>
      )}
      {kind === "CALCULATED" && (
        <>
          <fieldset className="checks" aria-label="Health checks to monitor">
            {others.length === 0 && <span className="muted">No other health checks</span>}
            {others.map((o) => (
              <label key={o.id} className="check">
                <input type="checkbox" name="children" value={o.id} defaultChecked={defaults.children?.includes(o.id)} /> {o.label}
              </label>
            ))}
          </fieldset>
          <Field label="Healthy when at least" rule={rules.HealthThreshold} member="HealthThreshold">
            <input name="healthThreshold" type="number" defaultValue={defaults.healthThreshold ?? 1} />
          </Field>
        </>
      )}
      {kind === "CLOUDWATCH_METRIC" && (
        <>
          <div className="form-row">
            <Field label="Alarm name" rule={{ required: true, minLength: 1, maxLength: 256 }} member="AlarmIdentifier.Name">
              <input name="alarm" defaultValue={defaults.alarm} />
            </Field>
            <Field label="Alarm Region" member="AlarmIdentifier.Region">
              <input name="alarmRegion" defaultValue={defaults.alarmRegion ?? "us-east-1"} />
            </Field>
          </div>
          <Field label="When data is insufficient" member="InsufficientDataHealthStatus">
            <select name="insufficient" defaultValue={defaults.insufficient ?? "LastKnownStatus"}>
              <option value="LastKnownStatus">Last known status</option>
              <option value="Healthy">Healthy</option>
              <option value="Unhealthy">Unhealthy</option>
            </select>
          </Field>
        </>
      )}
      <MoreFields open={editing}>
        {endpoint && (
          <>
            <div className="form-row">
              <Field label="Interval" rule={rules.RequestInterval} member="RequestInterval">
                <select name="interval" defaultValue={String(defaults.interval ?? 30)} disabled={editing}>
                  <option value="30">30 seconds</option>
                  <option value="10">10 seconds</option>
                </select>
              </Field>
              <Field label="Failure threshold" rule={rules.FailureThreshold} member="FailureThreshold">
                <input name="threshold" type="number" defaultValue={defaults.threshold ?? 3} />
              </Field>
            </div>
            <label className="check">
              <input type="checkbox" checked={custom} onChange={(e) => setCustom(e.target.checked)} /> Choose checker Regions
            </label>
            {custom && (
              <fieldset className="checks" aria-label="Checker Regions">
                {checkerRegions.map((r) => (
                  <label key={r} className="check">
                    <input type="checkbox" name="regions" value={r} defaultChecked={defaults.regions?.includes(r) ?? true} /> {r}
                  </label>
                ))}
              </fieldset>
            )}
          </>
        )}
        <label className="check">
          <input type="checkbox" name="inverted" defaultChecked={defaults.inverted} /> Invert status
        </label>
        <label className="check">
          <input type="checkbox" name="disabled" defaultChecked={defaults.disabled} /> Disabled (always healthy)
        </label>
      </MoreFields>
    </>
  );
}
