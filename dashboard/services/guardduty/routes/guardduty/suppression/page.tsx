import { GetFilterCommand, GetFindingsStatisticsCommand, ListFiltersCommand, type GetFilterResponse } from "@aws-sdk/client-guardduty";
import { all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, Page, Pill, Sheet, type Rule } from "@mws-dashboard/ui";
import { CreateFilter } from "@mws-dashboard/ui/model/guardduty";
import { EyeOff, Filter, Pencil, Trash2 } from "lucide-react";
import Link from "next/link";
import type { Metadata } from "next";

import { ICONS, detectorId, guardduty } from "../../../lib/clients";
import { describe } from "../../../lib/criteria";
import { GuardDutyNav } from "../../../lib/nav";
import { createSuppressionRule, deleteSuppressionRule, enableGuardDuty, updateSuppressionRule } from "../actions";

export const metadata: Metadata = { title: "Suppression rules · GuardDuty" };

// The model only bounds the length; GuardDuty's own check allows these.
const NAME: Rule = { ...CreateFilter.Name, pattern: "^[A-Za-z0-9._-]+$", hint: "Letters, digits, ., - and _", generate: "name" };
// ThreatPurpose:ResourceType/ThreatFamily.Mechanism!Artifact
const ONE = "[A-Za-z]+:[A-Za-z0-9]+/[A-Za-z0-9.!&_-]+";
const TYPE: Rule = { required: true, pattern: `^${ONE}(\\s*,\\s*${ONE})*$`, hint: "Like Recon:EC2/PortProbeUnprotectedPort (comma-separate several)" };
const RESOURCES = ["Instance", "AccessKey", "S3Bucket", "S3Object", "EKSCluster", "ECSCluster", "Container", "Lambda", "RDSDBInstance", "EBSVolume"];

interface Saved {
  name: string;
  description?: string;
  action: string;
  rank?: number;
  criteria: string[];
  types: string[];
  severity?: number;
  resource?: string;
}

function saved(f: GetFilterResponse): Saved {
  const c = f.FindingCriteria?.Criterion ?? {};
  return {
    name: f.Name!,
    description: f.Description,
    action: f.Action ?? "NOOP",
    rank: f.Rank,
    criteria: describe(f.FindingCriteria),
    types: c.type?.Equals ?? c.type?.Eq ?? [],
    severity: c.severity?.GreaterThanOrEqual ?? c.severity?.Gte,
    resource: (c["resource.resourceType"]?.Equals ?? [])[0],
  };
}

/** The fields a filter is made of (create and edit share them). */
function FilterFields({ types, f, names }: { types: string[]; f?: Saved; names?: string[] }) {
  return (
    <>
      {!f && (
        <Field label="Name" rule={NAME} taken={names} unique>
          <input name="name" required autoFocus />
        </Field>
      )}
      <Field label="Finding type" rule={TYPE} known={types}>
        <input name="type" list="guardduty-finding-types" required autoComplete="off" defaultValue={f?.types.join(", ")} />
      </Field>
      <datalist id="guardduty-finding-types">
        {types.map((t) => (
          <option key={t} value={t} />
        ))}
      </datalist>
      <div className="form-row">
        <Field label="Minimum severity">
          <select name="severity" defaultValue={f?.severity === undefined ? "" : String(f.severity)}>
            <option value="">Any</option>
            <option value="9">Critical</option>
            <option value="7">High</option>
            <option value="4">Medium</option>
            <option value="1">Low</option>
          </select>
        </Field>
        <Field label="Resource type">
          <select name="resource" defaultValue={f?.resource ?? ""}>
            <option value="">Any</option>
            {RESOURCES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </Field>
      </div>
      <div className="form-row">
        <Field label="Action">
          <select name="action" defaultValue={f?.action ?? "ARCHIVE"}>
            <option value="ARCHIVE">Suppress (archive)</option>
            <option value="NOOP">Saved filter only</option>
          </select>
        </Field>
        <Field label="Rank" rule={CreateFilter.Rank}>
          <input name="rank" type="number" min={1} max={100} defaultValue={f?.rank} />
        </Field>
      </div>
      <Field label="Description" rule={CreateFilter.Description}>
        <input name="description" defaultValue={f?.description} />
      </Field>
    </>
  );
}

export default async function SuppressionRules() {
  const data = await load(async () => {
    const detector = await detectorId();
    if (!detector) return undefined;
    const client = await guardduty();
    const [names, stats] = await Promise.all([
      all(
        (NextToken) => client.send(new ListFiltersCommand({ DetectorId: detector, NextToken })),
        (r) => r.FilterNames,
        (r) => r.NextToken,
      ),
      client.send(new GetFindingsStatisticsCommand({ DetectorId: detector, GroupBy: "FINDING_TYPE", MaxResults: 100 })).catch(() => undefined),
    ]);
    const filters = (await Promise.all(names.map((n) => client.send(new GetFilterCommand({ DetectorId: detector, FilterName: n }))))).map(saved).sort((a, b) => (a.rank ?? 0) - (b.rank ?? 0));
    const types = (stats?.FindingStatistics?.GroupedByFindingType ?? []).map((t) => t.FindingType!).filter(Boolean).sort();
    return { detector, names, rules: filters, types };
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
            <FilterFields types={types} names={names} />
          </ActionForm>
        </Sheet>
      }
    >
      <GuardDutyNav active="suppression" />
      <Curated
        label="Suppression rules"
        sections={[
          { id: "rules", title: "Suppression rules", items: rules.filter((r) => r.action === "ARCHIVE") },
          { id: "saved", title: "Saved filters", items: rules.filter((r) => r.action !== "ARCHIVE") },
        ]}
        empty={<Empty icon={ICONS.guardduty} />}
        row={(r) => ({
          key: r.name,
          icon: r.action === "ARCHIVE" ? <AwsIcon icon="resource/AWSWAFFilteringRule" size={22} /> : <Filter size={20} aria-hidden />,
          title: r.name,
          subtitle: [r.description, r.criteria.filter((c) => !c.startsWith("type ")).join(" · ")].filter(Boolean).join(" · "),
          meta: (
            <>
              {r.types.map((t) => (
                <Pill key={t}>{t}</Pill>
              ))}
              {r.rank !== undefined && <Pill>#{r.rank}</Pill>}
              <Link href={`/guardduty?filter=${encodeURIComponent(r.name)}${r.action === "ARCHIVE" ? "&view=archived" : ""}`}>findings</Link>
            </>
          ),
          actions: (
            <>
              <Sheet title={r.name} label={`Edit ${r.name}`} icon={<Pencil size={15} />} testId="edit-filter">
                <ActionForm action={updateSuppressionRule.bind(null, detector, r.name)} submit="Save" testId="edit-filter">
                  <FilterFields types={types} f={r} />
                </ActionForm>
              </Sheet>
              <ActionForm action={deleteSuppressionRule.bind(null, detector, r.name)} submit="Delete rule" icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${r.name}?`} />
            </>
          ),
        })}
      />
    </Page>
  );
}
