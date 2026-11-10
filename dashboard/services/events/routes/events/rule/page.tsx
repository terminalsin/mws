import { DescribeRuleCommand, ListTargetsByRuleCommand } from "@aws-sdk/client-eventbridge";
import { all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Sheet, Status } from "@mws-dashboard/ui";
import { FlaskConical, Pause, Play, Settings2, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { enabled, events, ICONS, managed } from "../../../lib/clients";
import { arnHref, arnName } from "../../../lib/links";
import { DLQ, EVENT_AGE, GROUP_ID, INPUT, INPUT_PATH, INPUT_PATHS, INPUT_TEMPLATE, PATTERN, RETRIES, ROLE, RULE_DESCRIPTION, SCHEDULE, TARGET_ARN, TARGET_ID } from "../../../lib/rules";
import { TargetFields } from "../../../lib/target-form";
import { targetArns } from "../../../lib/targets";
import { targetIcon } from "../../../lib/targets-view";
import { deleteRule, removeTarget, saveTarget, setRuleState, testPattern, updateRule } from "../actions";

type Props = { searchParams: Promise<{ bus?: string; name?: string }> };

export async function generateMetadata({ searchParams }: Props): Promise<Metadata> {
  return { title: (await searchParams).name ?? "Rule" };
}

const TARGET_RULES = { id: TARGET_ID, arn: TARGET_ARN, input: INPUT, inputPath: INPUT_PATH, inputPaths: INPUT_PATHS, inputTemplate: INPUT_TEMPLATE, retries: RETRIES, age: EVENT_AGE, dlq: DLQ, role: ROLE, group: GROUP_ID };

const link = (arn?: string) => {
  if (!arn) return null;
  const href = arnHref(arn);
  return href ? <Link href={href}>{arnName(arn)}</Link> : <code>{arn}</code>;
};

const SAMPLE = (source: string, detailType: string) =>
  JSON.stringify({ version: "0", id: "00000000-0000-0000-0000-000000000000", "detail-type": detailType, source, account: "000000000000", time: new Date().toISOString(), region: "us-east-1", resources: [], detail: {} }, null, 2);

export default async function EventRule({ searchParams }: Props) {
  const { bus = "default", name = "" } = await searchParams;
  const back = { href: bus === "default" ? "/events" : `/events?bus=${encodeURIComponent(bus)}`, label: bus === "default" ? "Rules" : bus };
  const data = await load(async () => {
    const client = await events();
    const [rule, targets] = await Promise.all([
      client.send(new DescribeRuleCommand({ Name: name, EventBusName: bus })),
      all((NextToken) => client.send(new ListTargetsByRuleCommand({ Rule: name, EventBusName: bus, NextToken })), (r) => r.Targets, (r) => r.NextToken),
    ]);
    return { rule, targets };
  });
  if (!data.ok) {
    return (
      <Page title={name} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { rule, targets } = data.value;
  const known = await targetArns().catch(() => [] as string[]);
  const on = enabled(rule.State);
  const own = managed(rule);
  let source = "my.app";
  let detailType = "Test event";
  try {
    const p = JSON.parse(rule.EventPattern ?? "{}");
    source = p.source?.find?.((s: unknown) => typeof s === "string") ?? source;
    detailType = p["detail-type"]?.find?.((s: unknown) => typeof s === "string") ?? detailType;
  } catch {
    // no pattern
  }
  return (
    <Page
      title={name}
      icon={ICONS.rule}
      back={back}
      subtitle={rule.Arn}
      actions={
        <>
          <Link
            className="icon-button plain"
            href={`/metrics?ns=AWS%2FEvents&metric=Invocations&dims=${encodeURIComponent(JSON.stringify([{ Name: "RuleName", Value: name }]))}`}
            aria-label="Metrics"
            title="Metrics"
          >
            <AwsIcon icon="service/AmazonCloudWatch" size={18} />
          </Link>
          {!own && (
          <>
            <Sheet title={`Rule ${name}`} label="Edit rule" icon={<Settings2 size={15} aria-hidden />} testId="edit-rule">
              <ActionForm action={updateRule.bind(null, bus, name)} submit="Save" testId="edit-rule">
                <Field label="Description" rule={RULE_DESCRIPTION}>
                  <input name="description" defaultValue={rule.Description} />
                </Field>
                <Field label="Event pattern" rule={{ ...PATTERN, required: false }} member="EventPattern" format="eventPattern">
                  <textarea name="pattern" rows={8} spellCheck={false} defaultValue={rule.EventPattern ? JSON.stringify(JSON.parse(rule.EventPattern), null, 2) : ""} />
                </Field>
                {bus === "default" && (
                  <Field label="Or schedule" rule={SCHEDULE} member="ScheduleExpression" format="schedule">
                    <input name="schedule" defaultValue={rule.ScheduleExpression} />
                  </Field>
                )}
                <Field label="Role" rule={{ ...ROLE, required: false }} member="RoleArn">
                  <input name="role" defaultValue={rule.RoleArn} spellCheck={false} />
                </Field>
              </ActionForm>
            </Sheet>
            <ActionForm action={setRuleState.bind(null, bus, name, !on)} submit={on ? "Disable rule" : "Enable rule"} icon={on ? <Pause size={16} aria-hidden /> : <Play size={16} aria-hidden />} />
            <ActionForm action={deleteRule.bind(null, bus, name, true)} submit="Delete rule" icon={<Trash2 size={16} aria-hidden />} tone="danger" confirm={`Delete rule ${name}?`} />
          </>
          )}
        </>
      }
    >
      <Section>
        <Facts
          items={[
            ["State", <Status key="s" tone={on ? "good" : "neutral"}>{on ? "Enabled" : "Disabled"}</Status>],
            rule.Description && ["Description", rule.Description],
            ["Event bus", <Link key="b" href={back.href}>{bus}</Link>],
            rule.ScheduleExpression && ["Schedule", <code key="c">{rule.ScheduleExpression}</code>],
            rule.RoleArn && ["Role", link(rule.RoleArn)],
            own && ["Managed by", <Pill key="m">{rule.ManagedBy}</Pill>],
            rule.CreatedBy && ["Created by", rule.CreatedBy],
          ]}
        />
      </Section>
      {rule.EventPattern && (
        <Section
          title="Event pattern"
          actions={
            <Sheet title="Test event pattern" label="Test pattern" icon={<FlaskConical size={15} aria-hidden />} testId="test-pattern">
              <ActionForm action={testPattern} submit="Test" testId="test-pattern">
                <Field label="Event pattern" rule={PATTERN} format="eventPattern" member="EventPattern">
                  <textarea name="pattern" rows={6} spellCheck={false} defaultValue={JSON.stringify(JSON.parse(rule.EventPattern), null, 2)} />
                </Field>
                <Field label="Event" format="json" member="Event">
                  <textarea name="event" rows={10} spellCheck={false} defaultValue={SAMPLE(source, detailType)} />
                </Field>
              </ActionForm>
            </Sheet>
          }
        >
          <CodeBlock value={rule.EventPattern} label="Event pattern" />
        </Section>
      )}
      <Section
        title="Targets"
        count={targets.length}
        plain
        actions={
          own ? undefined : (
            <Sheet title="Add target" label="Add target" testId="add-target">
              <ActionForm action={saveTarget.bind(null, bus, name)} submit="Add" testId="add-target">
                <TargetFields rules={TARGET_RULES} known={known} ids={targets.map((t) => t.Id!)} />
              </ActionForm>
            </Sheet>
          )
        }
      >
        <List
          label="Targets"
          empty={<Empty icon={ICONS.rule} />}
          rows={targets.map((t) => ({
            key: t.Id!,
            icon: <AwsIcon icon={targetIcon(t.Arn)} size={24} />,
            title: link(t.Arn),
            subtitle: (
              <>
                <code>{t.Id}</code>
                {t.Input && <> · constant</>}
                {t.InputPath && <> · {t.InputPath}</>}
                {t.InputTransformer && (
                  <details>
                    <summary>input transformer</summary>
                    <CodeBlock value={JSON.stringify(t.InputTransformer)} />
                  </details>
                )}
                {t.DeadLetterConfig?.Arn && <> · DLQ {link(t.DeadLetterConfig.Arn)}</>}
              </>
            ),
            meta: (
              <>
                {t.RetryPolicy?.MaximumRetryAttempts !== undefined && <Pill title="Retry attempts">{t.RetryPolicy.MaximumRetryAttempts} retries</Pill>}
                {t.RetryPolicy?.MaximumEventAgeInSeconds !== undefined && <Pill title="Maximum event age">{t.RetryPolicy.MaximumEventAgeInSeconds}s</Pill>}
                {t.SqsParameters?.MessageGroupId && <Pill title="Message group">{t.SqsParameters.MessageGroupId}</Pill>}
                {t.RoleArn && <Pill title={t.RoleArn}>role</Pill>}
              </>
            ),
            actions: own ? undefined : (
              <>
                <Sheet title={`Target ${t.Id}`} label={`Edit ${t.Id}`} icon={<Settings2 size={15} aria-hidden />} testId="edit-target">
                  <ActionForm action={saveTarget.bind(null, bus, name)} submit="Save" testId="edit-target">
                    <TargetFields
                      rules={TARGET_RULES}
                      known={known}
                      ids={targets.map((x) => x.Id!)}
                      values={{
                        id: t.Id,
                        arn: t.Arn,
                        input: t.Input,
                        inputPath: t.InputPath,
                        inputPaths: t.InputTransformer?.InputPathsMap ? JSON.stringify(t.InputTransformer.InputPathsMap, null, 2) : undefined,
                        inputTemplate: t.InputTransformer?.InputTemplate,
                        retries: t.RetryPolicy?.MaximumRetryAttempts,
                        age: t.RetryPolicy?.MaximumEventAgeInSeconds,
                        dlq: t.DeadLetterConfig?.Arn,
                        role: t.RoleArn,
                        group: t.SqsParameters?.MessageGroupId,
                        partitionKey: t.KinesisParameters?.PartitionKeyPath,
                      }}
                    />
                  </ActionForm>
                </Sheet>
                <ActionForm action={removeTarget.bind(null, bus, name, t.Id!)} submit={`Remove ${t.Id}`} icon={<Trash2 size={15} aria-hidden />} tone="danger" confirm={`Remove target ${t.Id}?`} />
              </>
            ),
          }))}
        />
      </Section>
    </Page>
  );
}
