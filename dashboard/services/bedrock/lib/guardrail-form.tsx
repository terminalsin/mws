"use client";

// The guardrail sheet's fields. A new guardrail starts from a template
// (balanced, strict, support bot, ...) that sets every policy; only the
// name, denied topics and words stay in view, the rest wait under More.

import type { GetGuardrailResponse } from "@aws-sdk/client-bedrock";
import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import { CreateGuardrail } from "@mws-dashboard/ui/model/bedrock";
import { freeName, MoreFields, PresetGallery } from "@mws-dashboard/ui/presets";
import { ruleAt } from "@mws-dashboard/ui/validation";
import { Anchor, EyeOff, Headset, Scale, ShieldCheck, Wrench } from "lucide-react";
import { Section, Sections } from "@mws-dashboard/ui/sections";
import { useState, type ReactNode } from "react";

import { FILTERS, GUARDRAIL_TEMPLATES, PII, type GuardrailTemplate } from "./guardrail-presets";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";

const ICON: Record<string, ReactNode> = {
  balanced: <Scale size={24} aria-hidden />,
  strict: <ShieldCheck size={24} aria-hidden />,
  support: <Headset size={24} aria-hidden />,
  privacy: <EyeOff size={24} aria-hidden />,
  grounded: <Anchor size={24} aria-hidden />,
  custom: <Wrench size={22} aria-hidden />,
};
const STRENGTHS = ["NONE", "LOW", "MEDIUM", "HIGH"];

const NAME = { ...CreateGuardrail.name, hint: "Letters, digits, - and _", generate: "name" as const };
// One topic per line, `Name: definition`, each within a topic's limits.
const TOPICS = { pattern: "^([^:\\n]{1,100}(:[^\\n]{1,200})?(\\n|$))*$", hint: "One topic per line: name (100), then : and a definition (200)" };
const WORDS = { pattern: "^[^,]{1,100}(,[^,]{1,100})*,?$", hint: "Comma separated, 100 characters each" };
const REGEXES = { pattern: "^([^:\\n]{1,100}:[^\\n]{1,500}(\\n|$))*$", hint: "One per line: name: pattern" };
const THRESHOLD = { type: "number" as const, min: 0, max: 0.99, required: false, hint: "0 to 0.99; empty turns the check off" };

const label = (s: string) =>
  s
    .toLowerCase()
    .replace(/_/g, " ")
    .replace(/^us /, "US ")
    .replace(/\baws\b/, "AWS")
    .replace(/^ip /, "IP ")
    .replace(/^url$/, "URL");

/** The fields of the create and edit guardrail sheets, filled from `g` when editing. */
export function GuardrailFields({ g, taken = [] }: { g?: GetGuardrailResponse; taken?: string[] }) {
  const [t, setT] = useState<GuardrailTemplate>(GUARDRAIL_TEMPLATES[0]);
  const editing = !!g;
  // Fields remount per template, so each starts from its policies.
  const part = (p: Part) => <Policies key={t.id} part={p} g={g} t={editing ? undefined : t} taken={taken} />;
  return (
    <Sections mode={editing ? "tabs" : "steps"} testId="guardrail">
      {!editing && (
        <Section id="template" label="Template" summary={t.label}>
          <PresetGallery label="Template" presets={GUARDRAIL_TEMPLATES.map((x) => ({ ...x, icon: ICON[x.id] }))} chosen={t.id} choose={(p) => setT(GUARDRAIL_TEMPLATES.find((x) => x.id === p.id)!)} />
        </Section>
      )}
      <Section id="topics" label="Topics">
        {part("topics")}
      </Section>
      <Section id="filters" label="Filters">
        {part("filters")}
      </Section>
      <Section id="data" label="Personal data">
        {part("data")}
      </Section>
      <Section id="grounding" label="Grounding">
        {part("grounding")}
      </Section>
    </Sections>
  );
}

type Part = "topics" | "filters" | "data" | "grounding";

function Policies({ part, g, t, taken }: { part: Part; g?: GetGuardrailResponse; t?: GuardrailTemplate; taken: string[] }) {
  const filter = (type: string) => g?.contentPolicy?.filters?.find((f) => f.type === type);
  const pii = new Map<string, string>(g ? (g.sensitiveInformationPolicy?.piiEntities ?? []).map((p) => [p.type as string, p.action as string]) : Object.entries(t?.pii ?? {}));
  const entities = [...new Set([...PII, ...pii.keys()])];
  const regexes = g?.sensitiveInformationPolicy?.regexes ?? [];
  const grounding = (type: string) => (g ? g.contextualGroundingPolicy?.filters?.find((f) => f.type === type)?.threshold : type === "GROUNDING" ? t?.grounding : t?.relevance);
  const editing = !!g;
  if (part === "topics")
    return (
      <>
        <Field label="Name" rule={NAME} taken={taken} unique={!editing}>
          <input name="name" required defaultValue={g?.name ?? (t && t.id !== "custom" ? freeName(`${t.id}-guardrail`, taken) : undefined)} />
        </Field>
        <Field label="Denied topics" rule={TOPICS}>
          <textarea
            name="topics"
            rows={2}
            placeholder="Investment advice: recommendations about stocks or funds"
            defaultValue={g ? (g.topicPolicy?.topics ?? []).map((tp) => `${tp.name}: ${tp.definition}`).join("\n") : t?.topics}
          />
        </Field>
        <Field label="Blocked words" rule={WORDS}>
          <input name="words" placeholder="comma separated" defaultValue={(g?.wordPolicy?.words ?? []).map((w) => w.text).join(", ")} />
        </Field>
        <label className="check">
          <input type="checkbox" name="profanity" defaultChecked={g ? (g.wordPolicy?.managedWordLists ?? []).some((m) => m.type === "PROFANITY") : !!t?.profanity} /> Profanity
        </label>
        <Field label="Description" rule={{ ...CreateGuardrail.description, required: false }}>
          <input name="description" defaultValue={g?.description} />
        </Field>
      </>
    );
  if (part === "filters")
    return (
      <fieldset className="checks">
        <legend>Content filters (prompt / response)</legend>
        {FILTERS.map((type) => {
          const f = filter(type);
          const fallback = t?.strength ?? "NONE";
          return (
            <div key={type} className="form-row">
              <Field label={label(type)}>
                <select name={`in_${type}`} defaultValue={f?.inputStrength ?? fallback} aria-label={`${label(type)} prompts`}>
                  {STRENGTHS.map((s) => (
                    <option key={s} value={s}>
                      {s.toLowerCase()}
                    </option>
                  ))}
                </select>
              </Field>
              {type !== "PROMPT_ATTACK" && (
                <Field label="Responses">
                  <select name={`out_${type}`} defaultValue={f?.outputStrength ?? fallback} aria-label={`${label(type)} responses`}>
                    {STRENGTHS.map((s) => (
                      <option key={s} value={s}>
                        {s.toLowerCase()}
                      </option>
                    ))}
                  </select>
                </Field>
              )}
            </div>
          );
        })}
      </fieldset>
    );
  if (part === "data")
    return (
      <>
        <fieldset className="checks">
          <legend>Personal data</legend>
          {entities.map((p) => (
            <label key={p} className="check">
              <select name={`pii_${p}`} defaultValue={pii.get(p) ?? ""} aria-label={label(p)}>
                <option value="">off</option>
                <option value="ANONYMIZE">mask</option>
                <option value="BLOCK">block</option>
              </select>{" "}
              {label(p)}
            </label>
          ))}
        </fieldset>
        <div className="form-row">
          <Field label="Regex filters" rule={REGEXES}>
            <textarea name="regexes" rows={2} placeholder="Order id: ORD-[0-9]{6}" defaultValue={regexes.map((r) => `${r.name}: ${r.pattern}`).join("\n")} />
          </Field>
          <Field label="Regex action">
            <select name="regexAction" defaultValue={regexes[0]?.action ?? "ANONYMIZE"}>
              <option value="ANONYMIZE">mask</option>
              <option value="BLOCK">block</option>
            </select>
          </Field>
        </div>
      </>
    );
  return (
    <>
      <div className="form-row">
        <Field label="Grounding threshold" rule={THRESHOLD}>
          <input name="grounding" type="number" step={0.01} min={0} max={0.99} defaultValue={grounding("GROUNDING")} />
        </Field>
        <Field label="Relevance threshold" rule={THRESHOLD}>
          <input name="relevance" type="number" step={0.01} min={0} max={0.99} defaultValue={grounding("RELEVANCE")} />
        </Field>
      </div>
      <div className="form-row">
        <Field label="Blocked prompt message" rule={{ ...CreateGuardrail.blockedInputMessaging, required: false }}>
          <input name="blocked" placeholder="Sorry, I can't help with that." defaultValue={g?.blockedInputMessaging} />
        </Field>
        <Field label="Blocked response message" rule={{ ...CreateGuardrail.blockedOutputsMessaging, required: false }}>
          <input name="blockedOutput" placeholder="Same as the prompt message" defaultValue={g?.blockedOutputsMessaging} />
        </Field>
      </div>
      {!editing && (
        <MoreFields>
          <Field label="KMS key" rule={{ ...ruleAt(CreateGuardrail, "kmsKeyId"), required: false }}>
            <ResourcePicker kind="kms-key" name="kms" exclude="AWS managed" placeholder="alias/my-key" />
          </Field>
          <Field label="Tags" format="tags">
            <textarea name="tags" rows={2} placeholder="team=ml" />
          </Field>
        </MoreFields>
      )}
    </>
  );
}
