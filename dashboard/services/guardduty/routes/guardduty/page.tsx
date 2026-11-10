import { GetDetectorCommand, GetFilterCommand, GetFindingsCommand, GetFindingsStatisticsCommand, ListDetectorsCommand, ListFiltersCommand, ListFindingsCommand, type FindingCriteria } from "@aws-sdk/client-guardduty";
import { ago, all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Metric, Metrics, More, Page, Pill, Segments, Status } from "@mws-dashboard/ui";
import { Archive, ArchiveRestore, FlaskConical, Pause, Play, Search } from "lucide-react";
import type { Metadata } from "next";

import { BANDS, ICONS, RESOURCE_ICON, guardduty, severity } from "../../lib/clients";
import { criteria, type FindingFilters } from "../../lib/criteria";
import { GuardDutyNav } from "../../lib/nav";
import { affected } from "../../lib/resources";
import { archive, enableGuardDuty, sampleFindings, setDetector, unarchive } from "./actions";

export const metadata: Metadata = { title: "GuardDuty" };

type Props = { searchParams: Promise<FindingFilters & { token?: string; filter?: string }> };

const RESOURCE_TYPES = ["Instance", "AccessKey", "S3Bucket", "S3Object", "EKSCluster", "ECSCluster", "Container", "Lambda", "RDSDBInstance", "EBSVolume"];

export default async function GuardDuty({ searchParams }: Props) {
  const params = await searchParams;
  const { view = "current", severity: band, type, resource, token, filter } = params;
  const data = await load(async () => {
    const client = await guardduty();
    const detector = (await client.send(new ListDetectorsCommand({}))).DetectorIds?.[0];
    if (!detector) return undefined;
    const saved = filter ? await client.send(new GetFilterCommand({ DetectorId: detector, FilterName: filter })) : undefined;
    const base: FindingCriteria = saved?.FindingCriteria ?? {};
    const FindingCriteria = criteria(params, base);
    const [d, page, bySeverity, byType, filters] = await Promise.all([
      client.send(new GetDetectorCommand({ DetectorId: detector })),
      client.send(new ListFindingsCommand({ DetectorId: detector, FindingCriteria, SortCriteria: { AttributeName: "severity", OrderBy: "DESC" }, MaxResults: 50, NextToken: token })),
      // Counts for the tiles cover every finding in view, not one page.
      client.send(new GetFindingsStatisticsCommand({ DetectorId: detector, FindingCriteria: criteria(params, base, false), FindingStatisticTypes: ["COUNT_BY_SEVERITY"] })),
      client.send(new GetFindingsStatisticsCommand({ DetectorId: detector, FindingCriteria: criteria({ view }), GroupBy: "FINDING_TYPE", MaxResults: 100 })).catch(() => undefined),
      all(
        (NextToken) => client.send(new ListFiltersCommand({ DetectorId: detector, NextToken })),
        (r) => r.FilterNames,
        (r) => r.NextToken,
      ),
    ]);
    const ids = page.FindingIds ?? [];
    const findings = ids.length ? ((await client.send(new GetFindingsCommand({ DetectorId: detector, FindingIds: ids, SortCriteria: { AttributeName: "severity", OrderBy: "DESC" } }))).Findings ?? []) : [];
    const counts = BANDS.map((b) =>
      Object.entries(bySeverity.FindingStatistics?.CountBySeverity ?? {})
        .filter(([s]) => Number(s) >= b.gte && Number(s) < b.lt)
        .reduce((n, [, c]) => n + c, 0),
    );
    const types = (byType?.FindingStatistics?.GroupedByFindingType ?? []).map((t) => t.FindingType!).filter(Boolean).sort();
    return { detector, d, findings, next: page.NextToken, counts, types, filters };
  });
  if (!data.ok) {
    return (
      <Page title="Findings">
        <GuardDutyNav active="findings" />
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  if (!data.value) {
    return (
      <Page title="GuardDuty">
        <Empty icon={ICONS.guardduty} action={<ActionForm action={enableGuardDuty} submit="Enable GuardDuty" testId="enable-guardduty" />} />
      </Page>
    );
  }
  const { detector, d, findings, next, counts, types, filters } = data.value;
  const archived = view === "archived";
  const href = (over: Record<string, string | undefined>) => {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries({ view, severity: band, type, resource, filter, ...over })) if (v && !(k === "view" && v === "current")) q.set(k, v);
    const s = q.toString();
    return `/guardduty${s ? `?${s}` : ""}`;
  };
  const sorted = findings.sort((a, b) => (b.Severity ?? 0) - (a.Severity ?? 0));
  const total = counts.reduce((a, b) => a + b, 0);
  return (
    <Page
      title="Findings"
      actions={
        <>
          <ActionForm action={sampleFindings.bind(null, detector)} submit="Generate sample findings" icon={<FlaskConical size={16} />} testId="sample-findings" />
          <ActionForm action={setDetector.bind(null, detector, d.Status !== "ENABLED")} submit={d.Status === "ENABLED" ? "Suspend GuardDuty" : "Enable GuardDuty"} icon={d.Status === "ENABLED" ? <Pause size={16} /> : <Play size={16} />} />
        </>
      }
    >
      <GuardDutyNav active="findings" />
      {d.Status !== "ENABLED" && <div className="banner">GuardDuty is suspended: it generates no new findings until enabled again.</div>}
      <Metrics>
        {BANDS.map((b, i) => (
          <Metric key={b.id} label={b.label} value={counts[i]} tone={counts[i] && b.tone !== "neutral" ? b.tone : undefined} href={href({ severity: band === b.id ? undefined : b.id, token: undefined })} />
        ))}
      </Metrics>
      <Segments
        items={[
          { label: "Current", href: href({ view: "current" }), active: !archived },
          { label: "Archived", href: href({ view: "archived" }), active: archived },
        ]}
      />
      <form method="get" action="/guardduty" className="filter-bar" data-testid="finding-filters">
        {archived && <input type="hidden" name="view" value="archived" />}
        <select name="severity" defaultValue={band ?? ""} aria-label="Severity">
          <option value="">Any severity</option>
          {BANDS.map((b) => (
            <option key={b.id} value={b.id}>
              {b.label}
            </option>
          ))}
        </select>
        <select name="type" defaultValue={type ?? ""} aria-label="Finding type">
          <option value="">Any finding type</option>
          {[...new Set([...(type ? [type] : []), ...types])].map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <select name="resource" defaultValue={resource ?? ""} aria-label="Resource type">
          <option value="">Any resource</option>
          {RESOURCE_TYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        {filters.length > 0 && (
          <select name="filter" defaultValue={filter ?? ""} aria-label="Saved filter">
            <option value="">No saved filter</option>
            {filters.map((f) => (
              <option key={f} value={f}>
                {f}
              </option>
            ))}
          </select>
        )}
        <button type="submit" className="icon-button primary" aria-label="Apply filters" title="Apply filters">
          <Search size={16} aria-hidden />
        </button>
      </form>
      <Curated
        label="Findings"
        sections={BANDS.map((b) => ({ id: b.id, title: b.label, items: sorted.filter((f) => severity(f.Severity).label === b.label) }))}
        empty={<Empty icon={ICONS.guardduty} />}
        row={(f) => {
          const sev = severity(f.Severity);
          const target = affected(f)[0];
          return {
            key: f.Id!,
            icon: <AwsIcon icon={RESOURCE_ICON[f.Resource?.ResourceType ?? ""] ?? ICONS.guardduty} size={22} />,
            title: f.Title,
            subtitle: [f.Type, target ? `${target.kind} ${target.name}` : ""].filter(Boolean).join(" · "),
            href: `/guardduty/finding?id=${encodeURIComponent(f.Id!)}`,
            meta: (
              <>
                <Status tone={sev.tone}>{sev.label}</Status>
                {(f.Service?.Count ?? 0) > 1 && <Pill>×{f.Service!.Count}</Pill>}
                {f.Service?.UserFeedback && <Pill tone={f.Service.UserFeedback === "USEFUL" ? "good" : "neutral"}>{f.Service.UserFeedback === "USEFUL" ? "useful" : "not useful"}</Pill>}
                <span>{ago(f.UpdatedAt)}</span>
              </>
            ),
            actions: archived ? (
              <ActionForm action={unarchive.bind(null, detector, f.Id!)} submit="Unarchive finding" icon={<ArchiveRestore size={15} />} />
            ) : (
              <ActionForm action={archive.bind(null, detector, f.Id!)} submit="Archive finding" icon={<Archive size={15} />} />
            ),
          };
        }}
      />
      <More shown={findings.length} noun={`of ${total.toLocaleString()} findings`} href={next ? href({ token: next }) : undefined} />
    </Page>
  );
}
