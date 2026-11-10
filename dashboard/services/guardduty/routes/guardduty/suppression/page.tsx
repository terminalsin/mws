import { GetFilterCommand, GetFindingsCommand, ListFiltersCommand, ListFindingsCommand } from "@aws-sdk/client-guardduty";
import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, Page, Pill, Sheet, type Rule } from "@mws-dashboard/ui";
import { CreateFilter } from "@mws-dashboard/ui/model/guardduty";
import { EyeOff, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, detectorId, guardduty } from "../../../lib/clients";
import { createSuppressionRule, deleteSuppressionRule, enableGuardDuty } from "../actions";

export const metadata: Metadata = { title: "Suppression rules · GuardDuty" };

// The model only bounds the length; GuardDuty's own check allows these.
const NAME: Rule = { ...CreateFilter.Name, pattern: "^[A-Za-z0-9._-]+$", hint: "Letters, digits, ., - and _", generate: "name" };
// ThreatPurpose:ResourceType/ThreatFamily.Mechanism!Artifact
const TYPE: Rule = { required: true, maxLength: 100, pattern: "^[A-Za-z]+:[A-Za-z0-9]+/[A-Za-z0-9.!&_-]+$", hint: "Like Recon:EC2/PortProbeUnprotectedPort" };

interface Suppression {
  name: string;
  description?: string;
  types: string[];
}

export default async function SuppressionRules() {
  const data = await load(async () => {
    const detector = await detectorId();
    if (!detector) return undefined;
    const client = await guardduty();
    const [names, findingIds] = await Promise.all([
      client.send(new ListFiltersCommand({ DetectorId: detector })).then((r) => r.FilterNames ?? []),
      client.send(new ListFindingsCommand({ DetectorId: detector, MaxResults: 50 })).then((r) => r.FindingIds ?? []),
    ]);
    const [filters, findings] = await Promise.all([
      Promise.all(names.map((n) => client.send(new GetFilterCommand({ DetectorId: detector, FilterName: n })))),
      findingIds.length ? client.send(new GetFindingsCommand({ DetectorId: detector, FindingIds: findingIds })).then((r) => r.Findings ?? []) : [],
    ]);
    const rules: Suppression[] = filters
      .filter((f) => f.Action === "ARCHIVE")
      .sort((a, b) => (a.Rank ?? 0) - (b.Rank ?? 0))
      .map((f) => ({ name: f.Name!, description: f.Description, types: f.FindingCriteria?.Criterion?.type?.Equals ?? f.FindingCriteria?.Criterion?.type?.Eq ?? [] }));
    const types = [...new Set(findings.map((f) => f.Type!).filter(Boolean))].sort();
    return { detector, names, rules, types };
  });
  if (!data.ok) {
    return (
      <Page title="Suppression rules">
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  if (!data.value) {
    return (
      <Page title="Suppression rules">
        <Empty icon={ICONS.guardduty} action={<ActionForm action={enableGuardDuty} submit="Enable GuardDuty" testId="enable-guardduty" />} />
      </Page>
    );
  }
  const { detector, names, rules, types } = data.value;
  return (
    <Page
      title="Suppression rules"
      actions={
        <Sheet title="Suppression rule" label="Create suppression rule" icon={<EyeOff size={16} />} testId="create-suppression-rule">
          <ActionForm action={createSuppressionRule.bind(null, detector)} submit="Create" testId="create-suppression-rule">
            <Field label="Name" rule={NAME} taken={names} unique>
              <input name="name" required autoFocus />
            </Field>
            <Field label="Finding type" rule={TYPE} known={types}>
              <input name="type" list="guardduty-finding-types" required autoComplete="off" />
            </Field>
            <datalist id="guardduty-finding-types">
              {types.map((t) => (
                <option key={t} value={t} />
              ))}
            </datalist>
            <Field label="Description" rule={CreateFilter.Description}>
              <input name="description" />
            </Field>
          </ActionForm>
        </Sheet>
      }
    >
      <Curated
        label="Suppression rules"
        sections={[{ id: "rules", title: "Suppression rules", items: rules }]}
        empty={<Empty icon={ICONS.guardduty} />}
        row={(r) => ({
          key: r.name,
          icon: <AwsIcon icon="resource/AWSWAFFilteringRule" size={22} />,
          title: r.name,
          subtitle: r.description,
          meta: (
            <>
              {r.types.map((t) => (
                <Pill key={t}>{t}</Pill>
              ))}
            </>
          ),
          actions: <ActionForm action={deleteSuppressionRule.bind(null, detector, r.name)} submit="Delete rule" icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${r.name}?`} />,
        })}
      />
    </Page>
  );
}
