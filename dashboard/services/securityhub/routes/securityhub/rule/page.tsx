import { BatchGetAutomationRulesCommand } from "@aws-sdk/client-securityhub";
import { load, when } from "@mws-dashboard/aws";
import { ActionForm, CodeBlock, ErrorNotice, Facts, Page, Section, Specs, Status } from "@mws-dashboard/ui";
import { Hash, Pause, Play, Trash2, Zap } from "lucide-react";
import type { Metadata } from "next";

import { securityhub, word } from "../../../lib/clients";
import { describeFilters } from "../../../lib/findings";
import { deleteAutomationRule, setRuleStatus } from "../actions";
import { EditAutomationRule } from "../forms";

export const metadata: Metadata = { title: "Automation rule · Security Hub" };

type Props = { searchParams: Promise<{ arn?: string }> };

export default async function Rule({ searchParams }: Props) {
  const { arn = "" } = await searchParams;
  const back = { href: "/securityhub?tab=rules", label: "Automation rules" };
  const data = await load(async () => {
    const r = await (await securityhub()).send(new BatchGetAutomationRulesCommand({ AutomationRulesArns: [arn] }));
    const rule = r.Rules?.[0];
    if (!rule) throw new Error(r.UnprocessedAutomationRules?.[0]?.ErrorMessage ?? `Rule ${arn} not found`);
    return rule;
  });
  if (!data.ok) {
    return (
      <Page title="Automation rule" back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const r = data.value;
  const on = r.RuleStatus === "ENABLED";
  const update = r.Actions?.[0]?.FindingFieldsUpdate;
  const changes = [
    update?.Workflow?.Status && `workflow → ${word(update.Workflow.Status)}`,
    update?.Severity?.Label && `severity → ${word(update.Severity.Label)}`,
    update?.Note?.Text && `note “${update.Note.Text}”`,
    update?.Confidence !== undefined && `confidence → ${update.Confidence}`,
    update?.Criticality !== undefined && `criticality → ${update.Criticality}`,
    (update?.Types ?? []).length > 0 && `types → ${update!.Types!.join(", ")}`,
    update?.VerificationState && `verification → ${word(update.VerificationState)}`,
    Object.keys(update?.UserDefinedFields ?? {}).length > 0 && `fields ${Object.entries(update!.UserDefinedFields!).map(([k, v]) => `${k}=${v}`).join(", ")}`,
  ].filter(Boolean) as string[];
  return (
    <Page
      title={r.RuleName}
      icon="resource/AmazonEventBridgeRule"
      back={back}
      subtitle={arn}
      actions={
        <>
          <ActionForm action={setRuleStatus.bind(null, arn, !on)} submit={on ? "Disable rule" : "Enable rule"} icon={on ? <Pause size={16} /> : <Play size={16} />} testId="toggle-rule" />
          <EditAutomationRule arn={arn} name={r.RuleName!} description={r.Description} order={r.RuleOrder ?? 1} severity={r.Criteria?.SeverityLabel?.[0]?.Value} status={update?.Workflow?.Status} />
          <ActionForm action={deleteAutomationRule.bind(null, arn)} submit="Delete rule" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete rule ${r.RuleName}?`} testId="delete-rule" />
        </>
      }
    >
      <Specs
        items={[
          { label: "Status", icon: <Zap size={15} />, value: <Status tone={on ? "good" : "neutral"}>{word(r.RuleStatus)}</Status> },
          { label: "Order", icon: <Hash size={15} />, value: `#${r.RuleOrder}` },
          r.IsTerminal && { label: "Terminal", icon: <Hash size={15} />, value: "Stops later rules" },
        ]}
      />
      {r.Description && r.Description !== r.RuleName && <p>{r.Description}</p>}
      <Section title="Criteria">
        <Facts items={(describeFilters(r.Criteria as Record<string, unknown>).length ? describeFilters(r.Criteria as Record<string, unknown>) : ["Every finding"]).map((c, i) => [i === 0 ? "Matches" : "", c])} />
      </Section>
      <Section title="Actions">
        <Facts items={(changes.length ? changes : [word(r.Actions?.[0]?.Type)]).map((c, i) => [i === 0 ? "Updates" : "", c])} />
      </Section>
      <Section title="JSON">
        <CodeBlock value={JSON.stringify({ Criteria: r.Criteria, Actions: r.Actions }, null, 2)} label="Rule JSON" />
      </Section>
      <Facts
        items={[
          r.CreatedBy && ["Created by", r.CreatedBy],
          ["Created", when(r.CreatedAt)],
          r.UpdatedAt && ["Updated", when(r.UpdatedAt)],
        ]}
      />
    </Page>
  );
}
