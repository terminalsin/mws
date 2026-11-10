"use client";

// The new cost category fields: the sheet opens on a template (by
// environment tag, by team tag, by service group), which fills in the
// name, rules and the value for everything else.

import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import { CreateCostCategoryDefinition } from "@mws-dashboard/ui/model/ce";
import { freeName, PresetGallery } from "@mws-dashboard/ui/presets";
import type { Rule } from "@mws-dashboard/ui/validation";
import { Layers, Users, Wrench } from "lucide-react";
import { useState } from "react";

const NAME: Rule = { ...CreateCostCategoryDefinition.Name, generate: "name" };
const RULES: Rule = { required: true, format: "json" };

const tag = (key: string, values: Record<string, string[]>) => Object.entries(values).map(([Value, Values]) => ({ Value, Rule: { Tags: { Key: key, Values } } }));
const services = (values: Record<string, string[]>) => Object.entries(values).map(([Value, Values]) => ({ Value, Rule: { Dimensions: { Key: "SERVICE", Values } } }));

const TEMPLATES = [
  {
    id: "environment",
    label: "Environment",
    icon: <Layers size={24} aria-hidden />,
    name: "Environment",
    fallback: "Untagged",
    rules: tag("env", { Production: ["prod", "production"], Staging: ["staging"], Development: ["dev"] }),
  },
  { id: "team", label: "Team", icon: <Users size={24} aria-hidden />, name: "Team", fallback: "Shared", rules: tag("team", { Payments: ["payments"], Search: ["search"] }) },
  {
    id: "services",
    label: "Service group",
    icon: "service/AWSCostExplorer",
    name: "Service group",
    fallback: "Other",
    rules: services({
      Compute: ["Amazon Elastic Compute Cloud - Compute", "AWS Lambda"],
      Storage: ["Amazon Simple Storage Service", "Amazon Elastic File System"],
      Databases: ["Amazon Relational Database Service", "Amazon DynamoDB"],
    }),
  },
  {
    id: "custom",
    label: "Custom",
    icon: <Wrench size={22} aria-hidden />,
    name: "",
    fallback: "",
    rules: [
      { Value: "Production", Rule: { Tags: { Key: "env", Values: ["prod"] } } },
      { Value: "Storage", Rule: { Dimensions: { Key: "SERVICE", Values: ["Amazon Simple Storage Service"] } } },
    ],
  },
];

export function CategoryFields({ names }: { names: string[] }) {
  const [t, setT] = useState(TEMPLATES[0]);
  return (
    <>
      <PresetGallery label="Template" presets={TEMPLATES} chosen={t.id} choose={(p) => setT(TEMPLATES.find((x) => x.id === p.id)!)} />
      <div key={t.id}>
        <Field label="Name" rule={NAME} taken={names} unique>
          <input name="name" required defaultValue={t.name ? freeName(t.name, names) : undefined} />
        </Field>
        <Field label="Rules" rule={RULES} hint="Each rule maps matching costs to a value">
          <textarea name="rules" rows={10} spellCheck={false} defaultValue={JSON.stringify(t.rules, null, 2)} className="code-editor" />
        </Field>
        <Field label="Uncategorized costs" rule={CreateCostCategoryDefinition.DefaultValue}>
          <input name="default" placeholder="Other" defaultValue={t.fallback || undefined} />
        </Field>
      </div>
    </>
  );
}
