import {
  DescribeActionTargetsCommand,
  DescribeHubCommand,
  DescribeStandardsCommand,
  GetEnabledStandardsCommand,
  GetFindingsCommand,
  GetInsightsCommand,
  ListAutomationRulesCommand,
  type SecurityHubClient,
} from "@aws-sdk/client-securityhub";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, List, Metric, Metrics, Page, Pill, Status, type FormAction } from "@mws-dashboard/ui";
import { BellOff, CheckCircle2, Plus, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, securityhub, severity } from "../../lib/clients";
import { deleteActionTarget, deleteAutomationRule, deleteInsight, enableHub, enableStandard, setWorkflow } from "./actions";
import { NewActionTarget, NewAutomationRule, NewInsight } from "./forms";

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
  if (tab === "insights") return <Insights client={client} />;
  if (tab === "rules") return <AutomationRules client={client} />;
  if (tab === "actions") return <CustomActions client={client} />;
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

const ICON_INSIGHT = "resource/AmazonCloudWatchMetricsInsights";
const ICON_RULE = "resource/AmazonEventBridgeRule";
const ICON_ACTION = "resource/AmazonEventBridgeCustomEventBus";

function Delete({ action, what }: { action: FormAction; what: string }) {
  return <ActionForm action={action} submit={`Delete ${what}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${what}?`} />;
}

async function Insights({ client }: { client: SecurityHubClient }) {
  const insights = await load(async () => (await client.send(new GetInsightsCommand({}))).Insights ?? []);
  if (!insights.ok) {
    return (
      <Page title="Insights">
        <ErrorNotice error={insights.error} />
      </Page>
    );
  }
  const names = insights.value.map((i) => i.Name!);
  return (
    <Page title="Insights" actions={<NewInsight names={names} />}>
      <List
        label="Insights"
        empty={<Empty icon={ICON_INSIGHT} action={<NewInsight names={names} />} />}
        rows={insights.value.map((i) => {
          const sev = i.Filters?.SeverityLabel?.[0]?.Value;
          return {
            key: i.InsightArn!,
            icon: <AwsIcon icon={ICON_INSIGHT} size={22} />,
            title: i.Name,
            subtitle: i.GroupByAttribute,
            meta: sev ? <Status tone={severity(sev).tone}>{severity(sev).label}</Status> : undefined,
            actions: <Delete action={deleteInsight.bind(null, i.InsightArn!)} what={`insight ${i.Name}`} />,
          };
        })}
      />
    </Page>
  );
}

async function AutomationRules({ client }: { client: SecurityHubClient }) {
  const rules = await load(async () => (await client.send(new ListAutomationRulesCommand({}))).AutomationRulesMetadata ?? []);
  if (!rules.ok) {
    return (
      <Page title="Automation rules">
        <ErrorNotice error={rules.error} />
      </Page>
    );
  }
  const all = rules.value.sort((a, b) => (a.RuleOrder ?? 0) - (b.RuleOrder ?? 0));
  const next = Math.max(0, ...all.map((r) => r.RuleOrder ?? 0)) + 1;
  const create = <NewAutomationRule next={next} names={all.map((r) => r.RuleName!)} />;
  return (
    <Page title="Automation rules" actions={create}>
      <List
        label="Automation rules"
        empty={<Empty icon={ICON_RULE} action={create} />}
        rows={all.map((r) => ({
          key: r.RuleArn!,
          icon: <AwsIcon icon={ICON_RULE} size={22} />,
          title: r.RuleName,
          subtitle: r.Description !== r.RuleName ? r.Description : undefined,
          meta: (
            <>
              <Pill title="Order">#{r.RuleOrder}</Pill>
              <Status tone={r.RuleStatus === "ENABLED" ? "good" : "neutral"}>{r.RuleStatus?.toLowerCase()}</Status>
            </>
          ),
          actions: <Delete action={deleteAutomationRule.bind(null, r.RuleArn!)} what={`rule ${r.RuleName}`} />,
        }))}
      />
    </Page>
  );
}

async function CustomActions({ client }: { client: SecurityHubClient }) {
  const targets = await load(async () => (await client.send(new DescribeActionTargetsCommand({}))).ActionTargets ?? []);
  if (!targets.ok) {
    return (
      <Page title="Custom actions">
        <ErrorNotice error={targets.error} />
      </Page>
    );
  }
  const ids = targets.value.map((t) => t.ActionTargetArn!.split("/").pop()!);
  return (
    <Page title="Custom actions" actions={<NewActionTarget ids={ids} />}>
      <List
        label="Custom actions"
        empty={<Empty icon={ICON_ACTION} action={<NewActionTarget ids={ids} />} />}
        rows={targets.value.map((t) => ({
          key: t.ActionTargetArn!,
          icon: <AwsIcon icon={ICON_ACTION} size={22} />,
          title: t.Name,
          subtitle: t.Description !== t.Name ? t.Description : undefined,
          meta: <code>{t.ActionTargetArn!.split("/").pop()}</code>,
          actions: <Delete action={deleteActionTarget.bind(null, t.ActionTargetArn!)} what={`custom action ${t.Name}`} />,
        }))}
      />
    </Page>
  );
}
