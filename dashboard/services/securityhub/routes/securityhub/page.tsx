import {
  DescribeActionTargetsCommand,
  DescribeHubCommand,
  DescribeStandardsCommand,
  GetEnabledStandardsCommand,
  GetFindingsCommand,
  GetInsightsCommand,
  ListAutomationRulesCommand,
  ListSecurityControlDefinitionsCommand,
  BatchGetSecurityControlsCommand,
  type DescribeHubCommandOutput,
  type SecurityHubClient,
} from "@aws-sdk/client-securityhub";
import { ago, all, load, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Facts, Field, List, Metric, Metrics, More, Page, Pill, Section, Segments, Status, type FormAction } from "@mws-dashboard/ui";
import { BellOff, CheckCircle2, Minus, Pause, Play, Plus, RotateCcw, Search, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import type { ReactNode } from "react";

import { ICONS, SEVERITY_LABELS, isManagedInsight, securityhub, severity, word, workflowTone } from "../../lib/clients";
import { filters, type FindingView } from "../../lib/findings";
import { deleteActionTarget, deleteAutomationRule, deleteInsight, disableHub, disableStandard, enableHub, enableStandard, setRuleStatus, setWorkflow, updateHubSettings } from "./actions";
import { ImportFindings, NewActionTarget, NewAutomationRule, NewInsight } from "./forms";

export const metadata: Metadata = { title: "Security Hub" };

type Props = { searchParams: Promise<FindingView & { tab?: string; page?: string }> };

const TABS: [string, string][] = [
  ["findings", "Findings"],
  ["insights", "Insights"],
  ["standards", "Security standards"],
  ["controls", "Controls"],
  ["rules", "Automation rules"],
  ["actions", "Custom actions"],
  ["settings", "Settings"],
];

function Nav({ tab }: { tab: string }) {
  return <Segments label="Security Hub" items={TABS.map(([id, label]) => ({ label, href: id === "findings" ? "/securityhub" : `/securityhub?tab=${id}`, active: id === tab }))} />;
}

const PAGE = 50;

export default async function SecurityHub({ searchParams }: Props) {
  const params = await searchParams;
  const { tab = "findings" } = params;
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
  if (tab === "standards") return <Standards client={client} />;
  if (tab === "controls") return <Controls client={client} />;
  if (tab === "settings") return <Settings hub={hub.value} />;
  return <Findings client={client} view={params} hubArn={hub.value.HubArn ?? ""} />;
}

async function Findings({ client, view, hubArn }: { client: SecurityHubClient; view: FindingView & { page?: string }; hubArn: string }) {
  const [, , , region, account] = hubArn.split(":");
  const offset = Math.max(0, Number(view.page ?? 0) || 0);
  const data = await load(async () => {
    // Every matching finding, most severe first: the tiles count all of
    // them and the list pages through them.
    const list = await all(
      (NextToken) => client.send(new GetFindingsCommand({ Filters: filters(view, false), SortCriteria: [{ Field: "SeverityNormalized", SortOrder: "desc" }], MaxResults: 100, NextToken })),
      (r) => r.Findings,
      (r) => r.NextToken,
    );
    return list;
  });
  const href = (over: Record<string, string | undefined>) => {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries({ workflow: view.workflow, record: view.record, severity: view.severity, product: view.product, resource: view.resource, compliance: view.compliance, ...over })) if (v) q.set(k, v);
    const s = q.toString();
    return `/securityhub${s ? `?${s}` : ""}`;
  };
  if (!data.ok) {
    return (
      <Page title="Findings">
        <Nav tab="findings" />
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const everything = data.value;
  const count = (l: string) => everything.filter((f) => (f.Severity?.Label ?? "INFORMATIONAL") === l).length;
  const shown = view.severity ? everything.filter((f) => (f.Severity?.Label ?? "INFORMATIONAL") === view.severity) : everything;
  const products = [...new Set(everything.map((f) => f.ProductName!).filter(Boolean))].sort();
  const types = [...new Set(everything.flatMap((f) => (f.Resources ?? []).map((r) => r.Type!)).filter(Boolean))].sort();
  const pageItems = shown.slice(offset, offset + PAGE);
  return (
    <Page title="Findings" actions={<ImportFindings account={account} region={region} />}>
      <Nav tab="findings" />
      <Metrics>
        {SEVERITY_LABELS.map((l) => {
          const n = count(l);
          const s = severity(l);
          return <Metric key={l} label={s.label} value={n} tone={n && s.tone !== "neutral" ? s.tone : undefined} href={href({ severity: view.severity === l ? undefined : l })} />;
        })}
      </Metrics>
      <form method="get" action="/securityhub" className="filter-bar" data-testid="finding-filters">
        <select name="workflow" defaultValue={view.workflow ?? "open"} aria-label="Workflow status">
          <option value="open">New or notified</option>
          <option value="NEW">New</option>
          <option value="NOTIFIED">Notified</option>
          <option value="RESOLVED">Resolved</option>
          <option value="SUPPRESSED">Suppressed</option>
          <option value="any">Any workflow</option>
        </select>
        <select name="record" defaultValue={view.record ?? "ACTIVE"} aria-label="Record state">
          <option value="ACTIVE">Active</option>
          <option value="ARCHIVED">Archived</option>
          <option value="any">Any record state</option>
        </select>
        <select name="severity" defaultValue={view.severity ?? ""} aria-label="Severity">
          <option value="">Any severity</option>
          {SEVERITY_LABELS.map((l) => (
            <option key={l} value={l}>
              {severity(l).label}
            </option>
          ))}
        </select>
        <select name="product" defaultValue={view.product ?? ""} aria-label="Product">
          <option value="">Any product</option>
          {[...new Set([...(view.product ? [view.product] : []), ...products])].map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
        <select name="resource" defaultValue={view.resource ?? ""} aria-label="Resource type">
          <option value="">Any resource</option>
          {[...new Set([...(view.resource ? [view.resource] : []), ...types])].map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <button type="submit" className="icon-button primary" aria-label="Apply filters" title="Apply filters">
          <Search size={16} aria-hidden />
        </button>
      </form>
      <Curated
        label="Findings"
        sections={SEVERITY_LABELS.map((l) => ({ id: l, title: severity(l).label, items: pageItems.filter((f) => (f.Severity?.Label ?? "INFORMATIONAL") === l) }))}
        empty={<Empty icon={ICONS.finding} />}
        row={(f) => {
          const sev = severity(f.Severity?.Label);
          const r = f.Resources?.[0];
          const status = f.Workflow?.Status ?? "NEW";
          const act = (to: "NEW" | "RESOLVED" | "SUPPRESSED" | "NOTIFIED", label: string, icon: ReactNode) =>
            status !== to && <ActionForm key={to} action={setWorkflow.bind(null, f.Id!, f.ProductArn!, to)} submit={`${label} finding`} icon={icon} />;
          return {
            key: `${f.ProductArn}|${f.Id}`,
            icon: <AwsIcon icon={ICONS.finding} size={22} />,
            title: f.Title,
            subtitle: [f.ProductName ?? f.ProductArn?.split("/").pop(), r ? `${r.Type} ${r.Id}` : "", f.AwsAccountId, f.Region].filter(Boolean).join(" · "),
            href: `/securityhub/finding?id=${encodeURIComponent(f.Id!)}&product=${encodeURIComponent(f.ProductArn!)}`,
            meta: (
              <>
                <Status tone={sev.tone}>{sev.label}</Status>
                {status !== "NEW" && <Pill tone={workflowTone(status)}>{word(status)}</Pill>}
                {f.RecordState === "ARCHIVED" && <Pill>archived</Pill>}
                {f.Compliance?.Status && <Pill tone={f.Compliance.Status === "PASSED" ? "good" : f.Compliance.Status === "FAILED" ? "bad" : "neutral"}>{word(f.Compliance.Status)}</Pill>}
                <span>{ago(f.UpdatedAt)}</span>
              </>
            ),
            actions: (
              <>
                {status === "RESOLVED" || status === "SUPPRESSED" ? act("NEW", "Reopen", <RotateCcw size={15} />) : null}
                {act("RESOLVED", "Resolve", <CheckCircle2 size={15} />)}
                {act("SUPPRESSED", "Suppress", <BellOff size={15} />)}
              </>
            ),
          };
        }}
      />
      <More shown={offset + pageItems.length} noun={`of ${shown.length.toLocaleString()} findings`} href={offset + PAGE < shown.length ? href({ page: String(offset + PAGE) }) : undefined} />
    </Page>
  );
}

const ICON_INSIGHT = "resource/AmazonCloudWatchMetricsInsights";
const ICON_RULE = "resource/AmazonEventBridgeRule";
const ICON_ACTION = "resource/AmazonEventBridgeCustomEventBus";

function Delete({ action, what }: { action: FormAction; what: string }) {
  return <ActionForm action={action} submit={`Delete ${what}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${what}?`} />;
}

async function Standards({ client }: { client: SecurityHubClient }) {
  const standards = await load(async () => {
    const [list, enabled] = await Promise.all([
      all(
        (NextToken) => client.send(new DescribeStandardsCommand({ NextToken })),
        (r) => r.Standards,
        (r) => r.NextToken,
      ),
      all(
        (NextToken) => client.send(new GetEnabledStandardsCommand({ NextToken })),
        (r) => r.StandardsSubscriptions,
        (r) => r.NextToken,
      ),
    ]);
    return list.map((s) => ({ s, sub: enabled.find((e) => e.StandardsArn === s.StandardsArn) }));
  });
  return (
    <Page title="Security standards">
      <Nav tab="standards" />
      {standards.ok ? (
        <List
          label="Standards"
          rows={standards.value.map(({ s, sub }) => {
            const st = sub?.StandardsStatus;
            return {
              key: s.StandardsArn!,
              icon: <AwsIcon icon={ICONS.securityhub} size={22} />,
              title: s.Name,
              subtitle: sub?.StandardsStatusReason?.StatusReasonCode ? word(sub.StandardsStatusReason.StatusReasonCode) : s.Description,
              href: sub && st !== "DELETING" ? `/securityhub/standard?arn=${encodeURIComponent(sub.StandardsSubscriptionArn!)}` : undefined,
              meta: sub ? <Status tone={st === "READY" ? "good" : st === "FAILED" || st === "INCOMPLETE" ? "bad" : "warn"}>{word(st)}</Status> : undefined,
              actions: sub ? (
                st !== "DELETING" && <ActionForm action={disableStandard.bind(null, sub.StandardsSubscriptionArn!)} submit={`Disable ${s.Name}`} icon={<Minus size={15} />} tone="danger" confirm={`Disable ${s.Name}? Its control findings are archived.`} />
              ) : (
                <ActionForm action={enableStandard.bind(null, s.StandardsArn!)} submit={`Enable ${s.Name}`} icon={<Plus size={15} />} />
              ),
            };
          })}
        />
      ) : (
        <ErrorNotice error={standards.error} />
      )}
    </Page>
  );
}

async function Controls({ client }: { client: SecurityHubClient }) {
  const data = await load(async () => {
    const defs = await all(
      (NextToken) => client.send(new ListSecurityControlDefinitionsCommand({ NextToken })),
      (r) => r.SecurityControlDefinitions,
      (r) => r.NextToken,
    );
    const status = new Map<string, string>();
    for (let i = 0; i < defs.length; i += 100) {
      const r = await client.send(new BatchGetSecurityControlsCommand({ SecurityControlIds: defs.slice(i, i + 100).map((d) => d.SecurityControlId!) }));
      for (const c of r.SecurityControls ?? []) status.set(c.SecurityControlId!, c.SecurityControlStatus ?? "");
    }
    return defs.map((d) => ({ ...d, status: status.get(d.SecurityControlId!) }));
  });
  return (
    <Page title="Controls">
      <Nav tab="controls" />
      {data.ok ? (
        <List
          label="Controls"
          empty={<Empty icon={ICONS.securityhub} />}
          rows={data.value.map((c) => {
            const sev = severity(c.SeverityRating);
            return {
              key: c.SecurityControlId!,
              icon: <AwsIcon icon={ICONS.securityhub} size={22} />,
              title: `${c.SecurityControlId} ${c.Title ?? ""}`,
              subtitle: c.RemediationUrl ? (
                <a href={c.RemediationUrl} target="_blank" rel="noreferrer">
                  Remediation
                </a>
              ) : undefined,
              meta: (
                <>
                  <Status tone={sev.tone}>{sev.label}</Status>
                  {c.status && <Status tone={c.status === "ENABLED" ? "good" : "neutral"}>{word(c.status)}</Status>}
                </>
              ),
            };
          })}
        />
      ) : (
        <ErrorNotice error={data.error} />
      )}
    </Page>
  );
}

function Settings({ hub }: { hub: DescribeHubCommandOutput }) {
  return (
    <Page title="Settings" actions={<ActionForm action={disableHub} submit="Disable Security Hub" icon={<Trash2 size={16} />} tone="danger" confirm="Disable Security Hub? Its findings, insights and standards subscriptions are removed." testId="disable-hub" />}>
      <Nav tab="settings" />
      <Facts
        items={[
          ["Hub ARN", <code key="arn">{hub.HubArn}</code>],
          hub.SubscribedAt && ["Enabled", when(hub.SubscribedAt)],
        ]}
      />
      <Section title="General">
        <ActionForm action={updateHubSettings} submit="Save" testId="hub-settings">
          <label className="check">
            <input type="checkbox" name="autoEnable" defaultChecked={hub.AutoEnableControls ?? true} /> Enable new controls automatically
          </label>
          <Field label="Control findings">
            <select name="generator" defaultValue={hub.ControlFindingGenerator ?? "SECURITY_CONTROL"}>
              <option value="SECURITY_CONTROL">Consolidated (one finding per control)</option>
              <option value="STANDARD_CONTROL">One finding per standard</option>
            </select>
          </Field>
        </ActionForm>
      </Section>
    </Page>
  );
}

async function Insights({ client }: { client: SecurityHubClient }) {
  const insights = await load(() =>
    all(
      (NextToken) => client.send(new GetInsightsCommand({ NextToken })),
      (r) => r.Insights,
      (r) => r.NextToken,
    ),
  );
  if (!insights.ok) {
    return (
      <Page title="Insights">
        <Nav tab="insights" />
        <ErrorNotice error={insights.error} />
      </Page>
    );
  }
  const names = insights.value.map((i) => i.Name!);
  return (
    <Page title="Insights" actions={<NewInsight names={names} />}>
      <Nav tab="insights" />
      <Curated
        label="Insights"
        sections={[
          { id: "custom", title: "Custom insights", items: insights.value.filter((i) => !isManagedInsight(i.InsightArn)) },
          { id: "managed", title: "Managed insights", items: insights.value.filter((i) => isManagedInsight(i.InsightArn)) },
        ]}
        empty={<Empty icon={ICON_INSIGHT} action={<NewInsight names={names} />} />}
        row={(i) => {
          const sev = i.Filters?.SeverityLabel?.[0]?.Value;
          return {
            key: i.InsightArn!,
            icon: <AwsIcon icon={ICON_INSIGHT} size={22} />,
            title: i.Name,
            subtitle: `Grouped by ${i.GroupByAttribute}`,
            href: `/securityhub/insight?arn=${encodeURIComponent(i.InsightArn!)}`,
            meta: (
              <>
                {isManagedInsight(i.InsightArn) && <Pill>managed</Pill>}
                {sev && <Status tone={severity(sev).tone}>{severity(sev).label}</Status>}
              </>
            ),
            actions: isManagedInsight(i.InsightArn) ? undefined : <Delete action={deleteInsight.bind(null, i.InsightArn!)} what={`insight ${i.Name}`} />,
          };
        }}
      />
    </Page>
  );
}

async function AutomationRules({ client }: { client: SecurityHubClient }) {
  const rules = await load(() =>
    all(
      (NextToken) => client.send(new ListAutomationRulesCommand({ NextToken })),
      (r) => r.AutomationRulesMetadata,
      (r) => r.NextToken,
    ),
  );
  if (!rules.ok) {
    return (
      <Page title="Automation rules">
        <Nav tab="rules" />
        <ErrorNotice error={rules.error} />
      </Page>
    );
  }
  const list = rules.value.sort((a, b) => (a.RuleOrder ?? 0) - (b.RuleOrder ?? 0));
  const next = Math.max(0, ...list.map((r) => r.RuleOrder ?? 0)) + 1;
  const create = <NewAutomationRule next={next} names={list.map((r) => r.RuleName!)} />;
  return (
    <Page title="Automation rules" actions={create}>
      <Nav tab="rules" />
      <List
        label="Automation rules"
        empty={<Empty icon={ICON_RULE} action={create} />}
        rows={list.map((r) => {
          const on = r.RuleStatus === "ENABLED";
          return {
            key: r.RuleArn!,
            icon: <AwsIcon icon={ICON_RULE} size={22} />,
            title: r.RuleName,
            subtitle: r.Description !== r.RuleName ? r.Description : undefined,
            href: `/securityhub/rule?arn=${encodeURIComponent(r.RuleArn!)}`,
            meta: (
              <>
                <Pill title="Order">#{r.RuleOrder}</Pill>
                {r.IsTerminal && <Pill>terminal</Pill>}
                <Status tone={on ? "good" : "neutral"}>{word(r.RuleStatus)}</Status>
              </>
            ),
            actions: (
              <>
                <ActionForm action={setRuleStatus.bind(null, r.RuleArn!, !on)} submit={`${on ? "Disable" : "Enable"} rule ${r.RuleName}`} icon={on ? <Pause size={15} /> : <Play size={15} />} />
                <Delete action={deleteAutomationRule.bind(null, r.RuleArn!)} what={`rule ${r.RuleName}`} />
              </>
            ),
          };
        })}
      />
    </Page>
  );
}

async function CustomActions({ client }: { client: SecurityHubClient }) {
  const targets = await load(() =>
    all(
      (NextToken) => client.send(new DescribeActionTargetsCommand({ NextToken })),
      (r) => r.ActionTargets,
      (r) => r.NextToken,
    ),
  );
  if (!targets.ok) {
    return (
      <Page title="Custom actions">
        <Nav tab="actions" />
        <ErrorNotice error={targets.error} />
      </Page>
    );
  }
  const ids = targets.value.map((t) => t.ActionTargetArn!.split("/").pop()!);
  return (
    <Page title="Custom actions" actions={<NewActionTarget ids={ids} />}>
      <Nav tab="actions" />
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

