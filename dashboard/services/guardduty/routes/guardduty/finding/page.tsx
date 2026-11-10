import { GetFindingsCommand, ListFiltersCommand } from "@aws-sdk/client-guardduty";
import { ago, all, load, when } from "@mws-dashboard/aws";
import { ActionForm, CopyValue, AwsIcon, CodeBlock, ErrorNotice, Facts, Field, List, Page, Pill, Section, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { Archive, ArchiveRestore, Clock, EyeOff, FlaskConical, Hash, ThumbsDown, ThumbsUp } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, RESOURCE_ICON, detectorId, guardduty, severity } from "../../../lib/clients";
import { FilterFields } from "../../../lib/filter-fields";
import { actor, affected } from "../../../lib/resources";
import { archive, createSuppressionRule, feedback, unarchive } from "../actions";

export const metadata: Metadata = { title: "Finding · GuardDuty" };

type Props = { searchParams: Promise<{ id?: string }> };

export default async function Finding({ searchParams }: Props) {
  const { id = "" } = await searchParams;
  const back = { href: "/guardduty", label: "Findings" };
  const data = await load(async () => {
    const detector = await detectorId();
    if (!detector) throw new Error("GuardDuty is not enabled in this Region");
    const client = await guardduty();
    const [found, filters] = await Promise.all([
      client.send(new GetFindingsCommand({ DetectorId: detector, FindingIds: [id] })),
      all(
        (NextToken) => client.send(new ListFiltersCommand({ DetectorId: detector, NextToken })),
        (r) => r.FilterNames,
        (r) => r.NextToken,
      ).catch(() => [] as string[]),
    ]);
    const f = found.Findings?.[0];
    if (!f) throw new Error(`Finding ${id} not found`);
    return { detector, f, filters };
  });
  if (!data.ok) {
    return (
      <Page title="Finding" back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { detector, f, filters } = data.value;
  const icon = RESOURCE_ICON[f.Resource?.ResourceType ?? ""] ?? ICONS.guardduty;
  const sev = severity(f.Severity);
  const s = f.Service;
  const archived = !!s?.Archived;
  const resources = affected(f);
  const sample = (s?.AdditionalInfo?.Value ?? "").includes('"sample":true') || f.Title?.startsWith("[SAMPLE]");
  const fb = (value: "USEFUL" | "NOT_USEFUL") => (
    <Sheet title={value === "USEFUL" ? "Useful finding" : "Not useful"} label={value === "USEFUL" ? "Mark useful" : "Mark not useful"} icon={value === "USEFUL" ? <ThumbsUp size={16} /> : <ThumbsDown size={16} />} testId={`feedback-${value.toLowerCase()}`}>
      <ActionForm action={feedback.bind(null, detector, f.Id!, value)} submit="Send feedback" testId={`feedback-${value.toLowerCase()}`}>
        <Field label="Comments">
          <textarea name="comments" rows={3} />
        </Field>
      </ActionForm>
    </Sheet>
  );
  return (
    <Page
      title={f.Title}
      icon={icon}
      back={back}
      subtitle={f.Arn}
      actions={
        <>
          {f.Type && (
            <Sheet title="Suppress findings like this" label="Suppress findings like this" icon={<EyeOff size={16} />} testId="suppress-similar">
              <ActionForm action={createSuppressionRule.bind(null, detector)} submit="Create" testId="suppress-similar">
                <FilterFields types={[f.Type]} names={filters} like={{ type: f.Type, resource: f.Resource?.ResourceType, icon }} />
              </ActionForm>
            </Sheet>
          )}
          {fb("USEFUL")}
          {fb("NOT_USEFUL")}
          {archived ? (
            <ActionForm action={unarchive.bind(null, detector, f.Id!)} submit="Unarchive finding" icon={<ArchiveRestore size={16} />} testId="unarchive-finding" />
          ) : (
            <ActionForm action={archive.bind(null, detector, f.Id!)} submit="Archive finding" icon={<Archive size={16} />} testId="archive-finding" />
          )}
        </>
      }
    >
      <Specs
        items={[
          { label: "Severity", icon: <AwsIcon icon={ICONS.guardduty} size={16} />, value: <Status tone={sev.tone}>{`${sev.label} ${f.Severity?.toFixed(1)}`}</Status> },
          (s?.Count ?? 0) > 1 && { label: "Count", icon: <Hash size={15} />, value: `×${s!.Count}` },
          archived && { label: "Archived", icon: <Archive size={15} />, value: "Archived" },
          sample && { label: "Sample", icon: <FlaskConical size={15} />, value: "Sample finding" },
          s?.UserFeedback && { label: "Feedback", icon: s.UserFeedback === "USEFUL" ? <ThumbsUp size={15} /> : <ThumbsDown size={15} />, value: s.UserFeedback === "USEFUL" ? "Useful" : "Not useful" },
          { label: "Updated", icon: <Clock size={15} />, value: <span title={when(f.UpdatedAt)}>{ago(f.UpdatedAt)}</span> },
        ]}
      />
      {f.Description && <p>{f.Description}</p>}
      <Section title="Resources affected" count={resources.length} plain>
        <List
          label="Resources affected"
          rows={resources.map((r, i) => ({
            key: `${r.kind}-${r.name}-${i}`,
            icon: <AwsIcon icon={r.icon} size={22} />,
            title: r.name,
            subtitle: r.detail,
            href: r.href,
            meta: <Pill>{r.kind}</Pill>,
          }))}
        />
      </Section>
      <Section title="Overview">
        <Facts
          items={[
            ["Finding type", <code key="type">{f.Type}</code>],
            ["Finding ID", <CopyValue key="id" value={f.Id} label="Copy finding ID" />],
            ["Account", f.AccountId],
            ["Region", f.Region],
            ["Resource type", f.Resource?.ResourceType],
            s?.ResourceRole && ["Resource role", s.ResourceRole],
            s?.FeatureName && ["Protection plan", s.FeatureName],
            ["Created", when(f.CreatedAt)],
            ["Updated", when(f.UpdatedAt)],
            s?.EventFirstSeen && ["First seen", when(s.EventFirstSeen)],
            s?.EventLastSeen && ["Last seen", when(s.EventLastSeen)],
            ...actor(f),
          ]}
        />
      </Section>
      {(s?.Evidence?.ThreatIntelligenceDetails ?? []).length > 0 && (
        <Section title="Threat intelligence">
          <Facts items={s!.Evidence!.ThreatIntelligenceDetails!.map((t) => [t.ThreatListName, (t.ThreatNames ?? []).join(", ")])} />
        </Section>
      )}
      <Section title="JSON">
        <CodeBlock value={JSON.stringify(f, null, 2)} label="Finding JSON" />
      </Section>
    </Page>
  );
}
