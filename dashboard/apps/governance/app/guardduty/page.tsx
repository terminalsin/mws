import { GetDetectorCommand, GetFindingsCommand, ListDetectorsCommand, ListFindingsCommand } from "@aws-sdk/client-guardduty";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Metric, Metrics, Page, Pill, Status } from "@mws-dashboard/ui";
import { Archive, FlaskConical, Pause, Play } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, guardduty, severity } from "../../lib/clients";
import { archive, enableGuardDuty, sampleFindings, setDetector } from "./actions";

export const metadata: Metadata = { title: "GuardDuty" };

const RESOURCE_ICON: Record<string, string> = {
  Instance: "resource/AmazonEC2Instance",
  AccessKey: "resource/AWSIdentityAccessManagementLongTermSecurityCredential",
  S3Bucket: "resource/AmazonSimpleStorageServiceBucket",
  EKSCluster: "service/AmazonElasticKubernetesService",
  Lambda: "resource/AWSLambdaLambdaFunction",
  RDSDBInstance: "service/AmazonRDS",
  Container: "resource/AmazonElasticContainerServiceContainer1",
};

export default async function GuardDuty() {
  const data = await load(async () => {
    const client = await guardduty();
    const detector = (await client.send(new ListDetectorsCommand({}))).DetectorIds?.[0];
    if (!detector) return undefined;
    const [d, ids] = await Promise.all([
      client.send(new GetDetectorCommand({ DetectorId: detector })),
      client.send(new ListFindingsCommand({ DetectorId: detector, FindingCriteria: { Criterion: { "service.archived": { Equals: ["false"] } } }, MaxResults: 50 })).then((r) => r.FindingIds ?? []),
    ]);
    const findings = ids.length ? ((await client.send(new GetFindingsCommand({ DetectorId: detector, FindingIds: ids }))).Findings ?? []) : [];
    return { detector, d, findings };
  });
  if (!data.ok) {
    return (
      <Page title="Findings">
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
  const { detector, d, findings } = data.value;
  const all = findings.sort((a, b) => (b.Severity ?? 0) - (a.Severity ?? 0));
  const count = (rank: number) => all.filter((f) => severity(f.Severity).rank === rank).length;
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
      <Metrics>
        <Metric label="Critical" value={count(4)} tone={count(4) ? "bad" : undefined} />
        <Metric label="High" value={count(3)} tone={count(3) ? "bad" : undefined} />
        <Metric label="Medium" value={count(2)} tone={count(2) ? "warn" : undefined} />
        <Metric label="Low" value={count(1)} />
      </Metrics>
      <Curated
        label="Findings"
        sections={[4, 3, 2, 1, 0].map((rank) => ({ id: String(rank), title: ["Informational", "Low", "Medium", "High", "Critical"][rank], items: all.filter((f) => severity(f.Severity).rank === rank) }))}
        empty={<Empty icon={ICONS.guardduty} />}
        row={(f) => {
          const sev = severity(f.Severity);
          return {
            key: f.Id!,
            icon: <AwsIcon icon={RESOURCE_ICON[f.Resource?.ResourceType ?? ""] ?? ICONS.guardduty} size={22} />,
            title: f.Title,
            subtitle: f.Type,
            meta: (
              <>
                <Status tone={sev.tone}>{sev.label}</Status>
                {(f.Service?.Count ?? 0) > 1 && <Pill>×{f.Service!.Count}</Pill>}
                <span>{ago(f.UpdatedAt)}</span>
              </>
            ),
            actions: <ActionForm action={archive.bind(null, detector, f.Id!)} submit="Archive finding" icon={<Archive size={15} />} />,
          };
        }}
      />
    </Page>
  );
}
