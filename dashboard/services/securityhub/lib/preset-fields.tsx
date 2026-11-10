"use client";

// New insights and automation rules start from a tile: picking one fills
// the name, grouping, severity and workflow, so the common case is one
// click and Create.

import type { Rule } from "@mws-dashboard/ui";
import { FieldShell } from "@mws-dashboard/ui/fields";
import { CreateAutomationRule, CreateInsight } from "@mws-dashboard/ui/model/securityhub";
import { MoreFields, PresetGallery, freeName } from "@mws-dashboard/ui/presets";
import { BellMinus, BellOff, BellRing, Boxes, Layers, Network, Siren, Wrench } from "lucide-react";
import { useState, type ReactNode } from "react";

import { GROUP_BY, INSIGHT_PRESETS, RULE_PRESETS, type InsightPreset, type RulePreset } from "./presets";

const LUCIDE: Record<string, ReactNode> = {
  "lucide:boxes": <Boxes size={24} aria-hidden />,
  "lucide:siren": <Siren size={24} aria-hidden />,
  "lucide:layers": <Layers size={24} aria-hidden />,
  "lucide:network": <Network size={24} aria-hidden />,
  "lucide:bell-off": <BellOff size={24} aria-hidden />,
  "lucide:bell-minus": <BellMinus size={24} aria-hidden />,
  "lucide:bell-ring": <BellRing size={24} aria-hidden />,
};
const icon = (i: string) => LUCIDE[i] ?? i;
const CUSTOM_ICON = <Wrench size={22} aria-hidden />;

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"] as const;
const WORKFLOWS = ["NEW", "NOTIFIED", "RESOLVED", "SUPPRESSED"] as const;
const label = (s: string) => s[0] + s.slice(1).toLowerCase();

function Severity({ any, value = "" }: { any: string; value?: string }) {
  return (
    <FieldShell label="Severity">
      <select name="severity" defaultValue={value}>
        <option value="">{any}</option>
        {SEVERITIES.map((s) => (
          <option key={s} value={s}>
            {label(s)}
          </option>
        ))}
      </select>
    </FieldShell>
  );
}

// The model leaves names unconstrained; these limits are AWS's documented ones.
const INSIGHT_NAME: Rule = { ...CreateInsight.Name, maxLength: 128 };
const GROUP: Rule = { ...CreateInsight.GroupByAttribute, enum: GROUP_BY, hint: "A finding attribute, e.g. ResourceId" };

export function InsightFields({ names }: { names: string[] }) {
  const custom: InsightPreset = { id: "custom", label: "Custom", icon: "", name: "", group: "ResourceId" };
  const [p, setP] = useState<InsightPreset>(INSIGHT_PRESETS[0]);
  return (
    <>
      <PresetGallery
        label="Insight"
        presets={[...INSIGHT_PRESETS.map((x) => ({ ...x, icon: icon(x.icon), added: names.includes(x.name) })), { ...custom, icon: CUSTOM_ICON }]}
        chosen={p.id}
        choose={(x) => setP(INSIGHT_PRESETS.find((y) => y.id === x.id) ?? custom)}
        testId="insight-preset"
      />
      <div key={p.id} className="preset-fields">
        <FieldShell label="Name" rule={INSIGHT_NAME} taken={names} unique>
          <input name="name" required defaultValue={p.name ? freeName(p.name, names) : undefined} />
        </FieldShell>
        <div className="form-row">
          <FieldShell label="Group by" rule={GROUP}>
            <input name="group" required defaultValue={p.group} spellCheck={false} list="securityhub-group-by" autoComplete="off" />
          </FieldShell>
          <datalist id="securityhub-group-by">
            {GROUP_BY.map((g) => (
              <option key={g} value={g} />
            ))}
          </datalist>
          <Severity any="Any severity" value={p.severity} />
        </div>
      </div>
    </>
  );
}

const RULE_NAME: Rule = { ...CreateAutomationRule.RuleName, maxLength: 256 };
const RULE_DESCRIPTION: Rule = { ...CreateAutomationRule.Description, required: false, maxLength: 1024 };

export function RuleFields({ next, names }: { next: number; names: string[] }) {
  const custom: RulePreset = { id: "custom", label: "Custom", icon: "", name: "", severity: "", status: "SUPPRESSED" };
  const [p, setP] = useState<RulePreset>(RULE_PRESETS[0]);
  return (
    <>
      <PresetGallery
        label="Rule"
        presets={[...RULE_PRESETS.map((x) => ({ ...x, icon: icon(x.icon), added: names.includes(x.name) })), { ...custom, icon: CUSTOM_ICON }]}
        chosen={p.id}
        choose={(x) => setP(RULE_PRESETS.find((y) => y.id === x.id) ?? custom)}
        testId="rule-preset"
      />
      <div key={p.id} className="preset-fields">
        <FieldShell label="Name" rule={RULE_NAME} taken={names}>
          <input name="name" required defaultValue={p.name ? freeName(p.name, names) : undefined} />
        </FieldShell>
        <div className="form-row">
          <Severity any="Every finding" value={p.severity} />
          <FieldShell label="Set workflow to">
            <select name="status" defaultValue={p.status}>
              {WORKFLOWS.map((s) => (
                <option key={s} value={s}>
                  {label(s)}
                </option>
              ))}
            </select>
          </FieldShell>
          <FieldShell label="Order" rule={CreateAutomationRule.RuleOrder}>
            <input name="order" type="number" required defaultValue={String(Math.min(next, 1000))} />
          </FieldShell>
        </div>
        <MoreFields>
          <FieldShell label="Description" rule={RULE_DESCRIPTION}>
            <input name="description" />
          </FieldShell>
        </MoreFields>
      </div>
    </>
  );
}

