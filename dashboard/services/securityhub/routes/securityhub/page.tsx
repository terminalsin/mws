import { DescribeHubCommand, DescribeStandardsCommand, GetEnabledStandardsCommand, GetFindingsCommand } from "@aws-sdk/client-securityhub";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, List, Metric, Metrics, Page, Pill, Status } from "@mws-dashboard/ui";
import { BellOff, CheckCircle2, Plus } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, securityhub, severity } from "../../lib/clients";
import { enableHub, enableStandard, setWorkflow } from "./actions";

export const metadata: Metadata = { title: "Security Hub" };

type Props = { searchParams: Promise<{ tab?: string }> };

export default async function SecurityHub({ searchParams }: Props) {
  const { tab = "findings" } = await searchParams;
  const client = await securityhub();
  const hub = await load(() => client.send(new DescribeHubCommand({})));
  if (!hub.ok) {
    return (
      <Page title="Security Hub">
        {/not subscribed|InvalidAccess|not enabled/i.test(hub.error) ? <Empty icon={ICONS.securityhub} action={<ActionForm action={enableHub} submit="Enable Security Hub" testId="enable-security-hub" />} /> : <ErrorNotice error={hub.error} />}
      </Page>
    );
  }
  if (tab === "standards") {
    const standards = await load(async () => {
      const [all, enabled] = await Promise.all([client.send(new DescribeStandardsCommand({})).then((r) => r.Standards ?? []), client.send(new GetEnabledStandardsCommand({})).then((r) => r.StandardsSubscriptions ?? [])]);
      return all.map((s) => ({ s, sub: enabled.find((e) => e.StandardsArn === s.StandardsArn) }));
    });
    return (
      <Page title="Security standards">
        {standards.ok ? (
          <List
            label="Standards"
            rows={standards.value.map(({ s, sub }) => ({
              key: s.StandardsArn!,
              icon: <AwsIcon icon={ICONS.securityhub} size={22} />,
              title: s.Name,
              subtitle: s.Description,
              meta: sub ? <Status tone={sub.StandardsStatus === "READY" ? "good" : "warn"}>{sub.StandardsStatus?.toLowerCase()}</Status> : undefined,
              actions: sub ? undefined : <ActionForm action={enableStandard.bind(null, s.StandardsArn!)} submit={`Enable ${s.Name}`} icon={<Plus size={15} />} />,
            }))}
          />
        ) : (
          <ErrorNotice error={standards.error} />
        )}
      </Page>
    );
  }
  const findings = await load(async () => (await client.send(new GetFindingsCommand({ Filters: { RecordState: [{ Value: "ACTIVE", Comparison: "EQUALS" }], WorkflowStatus: [{ Value: "NEW", Comparison: "EQUALS" }, { Value: "NOTIFIED", Comparison: "EQUALS" }] }, MaxResults: 100 }))).Findings ?? []);
  if (!findings.ok) {
    return (
      <Page title="Findings">
        <ErrorNotice error={findings.error} />
      </Page>
    );
  }
  const all = findings.value.sort((a, b) => severity(b.Severity?.Label).rank - severity(a.Severity?.Label).rank);
  const count = (l: string) => all.filter((f) => f.Severity?.Label === l).length;
  return (
    <Page title="Findings">
      <Metrics>
        <Metric label="Critical" value={count("CRITICAL")} tone={count("CRITICAL") ? "bad" : undefined} />
        <Metric label="High" value={count("HIGH")} tone={count("HIGH") ? "bad" : undefined} />
        <Metric label="Medium" value={count("MEDIUM")} tone={count("MEDIUM") ? "warn" : undefined} />
        <Metric label="Low" value={count("LOW")} />
      </Metrics>
      <Curated
        label="Findings"
        sections={["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"].map((l) => ({ id: l, title: severity(l).label, items: all.filter((f) => (f.Severity?.Label ?? "INFORMATIONAL") === l) }))}
        empty={<Empty icon={ICONS.finding} />}
        row={(f) => {
          const sev = severity(f.Severity?.Label);
          return {
            key: f.Id!,
            icon: <AwsIcon icon={ICONS.finding} size={22} />,
            title: f.Title,
            subtitle: `${f.ProductName ?? f.ProductArn?.split("/").pop()} · ${f.Resources?.[0]?.Id?.split(/[:/]/).pop() ?? ""}`,
            meta: (
              <>
                <Status tone={sev.tone}>{sev.label}</Status>
                {f.Compliance?.Status && <Pill tone={f.Compliance.Status === "PASSED" ? "good" : "bad"}>{f.Compliance.Status.toLowerCase()}</Pill>}
                <span>{ago(f.UpdatedAt)}</span>
              </>
            ),
            actions: (
              <>
                <ActionForm action={setWorkflow.bind(null, f.Id!, f.ProductArn!, "RESOLVED")} submit="Resolve finding" icon={<CheckCircle2 size={15} />} />
                <ActionForm action={setWorkflow.bind(null, f.Id!, f.ProductArn!, "SUPPRESSED")} submit="Suppress finding" icon={<BellOff size={15} />} />
              </>
            ),
          };
        }}
      />
    </Page>
  );
}
