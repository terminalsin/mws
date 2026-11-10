import { DescribeEventBusCommand, ListRulesCommand, ListTargetsByRuleCommand, type Target } from "@aws-sdk/client-eventbridge";
import { all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, CopyValue, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Segments, Sheet } from "@mws-dashboard/ui";
import { Pause, Play, Send, Settings2, Trash2 } from "lucide-react";
import { MoreFields } from "@mws-dashboard/ui/presets";
import type { Metadata } from "next";
import Link from "next/link";

import { enabled, events, ICONS, managed } from "../../lib/clients";
import { arnHref, arnName } from "../../lib/links";
import { CreateRuleFields } from "../../lib/create-rule";
import { BUS_DESCRIPTION, BUS_NAME, DLQ, ENTRY, SOURCE } from "../../lib/rules";
import { buses as listBuses, targetArns } from "../../lib/targets";
import { ruleHref, TargetIcons } from "../../lib/targets-view";
import { EventsTabs } from "../../lib/tabs";
import { createBus, createRule, deleteBus, deleteRule, putEvent, setRuleState, updateBus } from "./actions";

export const metadata: Metadata = { title: "EventBridge" };

type Props = { searchParams: Promise<{ bus?: string }> };

/** The exact strings a rule's pattern matches at a top-level field. */
function patternValues(pattern: string | undefined, field: string): string[] {
  try {
    const values = (JSON.parse(pattern ?? "{}") as Record<string, unknown>)[field];
    return Array.isArray(values) ? values.filter((v): v is string => typeof v === "string") : [];
  } catch {
    return [];
  }
}

export default async function EventBridge({ searchParams }: Props) {
  const bus = (await searchParams).bus ?? "default";
  const client = await events();
  const [buses, rules, info, known] = await Promise.all([
    load(listBuses),
    load(async () => {
      const list = await all(
        (NextToken) => client.send(new ListRulesCommand({ EventBusName: bus, NextToken })),
        (r) => r.Rules,
        (r) => r.NextToken,
      );
      return Promise.all(
        list.map(async (rule) => ({
          rule,
          targets: (await all((NextToken) => client.send(new ListTargetsByRuleCommand({ Rule: rule.Name!, EventBusName: bus, NextToken })), (r) => r.Targets, (r) => r.NextToken)) as Target[],
        })),
      );
    }),
    load(() => client.send(new DescribeEventBusCommand({ Name: bus }))),
    targetArns().catch(() => [] as string[]),
  ]);
  const listed = rules.ok ? rules.value : [];
  const sources = [...new Set(listed.flatMap(({ rule }) => patternValues(rule.EventPattern, "source")))].filter((v) => !v.startsWith("aws."));
  const detailTypes = [...new Set(listed.flatMap(({ rule }) => patternValues(rule.EventPattern, "detail-type")))];
  const targetArnList = [...new Set([...listed.flatMap(({ targets }) => targets.map((t) => t.Arn!)), ...known])];
  const b = info.ok ? info.value : undefined;
  const partner = bus.startsWith("aws.partner/");
  return (
    <Page
      title="Rules"
      actions={
        <>
          <Sheet title={`Send event to ${bus}`} label="Send event" icon={<Send size={15} aria-hidden />} testId="put-event">
            <ActionForm action={putEvent.bind(null, bus)} submit="Send" testId="put-event">
              <div className="form-row">
                <Field label="Source" rule={SOURCE} member="Source" known={sources}>
                  <input name="source" required defaultValue={sources[0] ?? "mws.console"} />
                </Field>
                <Field label="Detail type" rule={ENTRY.DetailType} member="DetailType" known={detailTypes}>
                  <input name="detailType" required defaultValue={detailTypes[0] ?? "Test event"} />
                </Field>
              </div>
              <Field label="Detail" rule={ENTRY.Detail} member="Detail" format="json">
                <textarea name="detail" required defaultValue="{}" />
              </Field>
            </ActionForm>
          </Sheet>
          <Sheet title="New event bus" label="Create event bus" icon={<AwsIcon icon={ICONS.bus} size={18} />}>
            <ActionForm action={createBus} submit="Create">
              <Field label="Name" rule={BUS_NAME} taken={buses.ok ? buses.value.map((x) => x.Name!) : undefined} unique>
                <input name="name" required autoFocus />
              </Field>
              <Field label="Description" rule={BUS_DESCRIPTION}>
                <input name="description" />
              </Field>
            </ActionForm>
          </Sheet>
        </>
      }
    >
      <EventsTabs active="rules" />
      {buses.ok ? (
        buses.value.length > 1 && (
          <Segments
            label="Event buses"
            items={buses.value.map((x) => ({
              label: x.Name!,
              href: x.Name === "default" ? "/events" : `/events?bus=${encodeURIComponent(x.Name!)}`,
              active: x.Name === bus,
            }))}
          />
        )
      ) : (
        <ErrorNotice error={buses.error} />
      )}
      {b && (
        <Section
          title={bus}
          icon={<AwsIcon icon={bus === "default" ? ICONS.defaultBus : partner ? ICONS.partner : ICONS.bus} size={20} />}
          actions={
            <>
              <Sheet title={`Event bus ${bus}`} label="Edit event bus" icon={<Settings2 size={15} aria-hidden />} testId="edit-bus">
                <ActionForm action={updateBus.bind(null, bus)} submit="Save" testId="edit-bus">
                  <Field label="Description" rule={BUS_DESCRIPTION}>
                    <input name="description" defaultValue={b.Description} />
                  </Field>
                  <Field label="Dead-letter queue" rule={{ ...DLQ, required: false }} known={known.filter((a) => a.split(":")[2] === "sqs")}>
                    <input name="dlq" defaultValue={b.DeadLetterConfig?.Arn} spellCheck={false} />
                  </Field>
                  <MoreFields label="Resource-based policy" expanded={!!b.Policy}>
                    <Field label="Resource-based policy" format="policy">
                      <textarea name="policy" rows={8} spellCheck={false} defaultValue={b.Policy ? JSON.stringify(JSON.parse(b.Policy), null, 2) : ""} />
                    </Field>
                  </MoreFields>
                  {b.Policy && <input type="hidden" name="hadPolicy" value="1" />}
                </ActionForm>
              </Sheet>
              {bus !== "default" && (
                <ActionForm action={deleteBus.bind(null, bus)} submit={`Delete ${bus}`} icon={<Trash2 size={16} aria-hidden />} tone="danger" confirm={`Delete event bus ${bus}?`} />
              )}
            </>
          }
        >
          <Facts
            items={[
              ["ARN", <CopyValue key="a" value={b.Arn} label="Copy ARN" />],
              b.Description && ["Description", b.Description],
              partner && ["Type", <Pill key="p" tone="info">partner</Pill>],
              b.DeadLetterConfig?.Arn && ["Dead-letter queue", arnHref(b.DeadLetterConfig.Arn) ? <Link key="d" href={arnHref(b.DeadLetterConfig.Arn)!}>{arnName(b.DeadLetterConfig.Arn)}</Link> : b.DeadLetterConfig.Arn],
              b.KmsKeyIdentifier && ["Encryption", b.KmsKeyIdentifier],
              b.Policy && [
                "Policy",
                <details key="p">
                  <summary>{(JSON.parse(b.Policy).Statement ?? []).length} statements</summary>
                  <CodeBlock value={b.Policy} />
                </details>,
              ],
            ]}
          />
        </Section>
      )}
      <Section
        title="Rules"
        count={rules.ok ? rules.value.length : undefined}
        plain
        actions={
          <Sheet title={`New rule on ${bus}`} label="Create rule" testId="create-rule">
            <ActionForm action={createRule.bind(null, bus)} submit="Create" testId="create-rule">
              <CreateRuleFields bus={bus} taken={listed.map(({ rule }) => rule.Name!)} targets={targetArnList.map((a) => ({ arn: a, name: arnName(a) }))} />
            </ActionForm>
          </Sheet>
        }
      >
        {rules.ok ? (
          <List
            label="Rules"
            empty={<Empty icon={ICONS.rule} />}
            rows={rules.value.map(({ rule, targets }) => {
              const on = enabled(rule.State);
              const own = managed(rule);
              return {
                key: rule.Name!,
                icon: <AwsIcon icon={rule.ScheduleExpression ? "resource/AmazonEventBridgeScheduler" : ICONS.rule} size={24} />,
                title: rule.Name,
                href: ruleHref(bus, rule.Name!),
                subtitle: rule.Description ?? rule.ScheduleExpression,
                meta: (
                  <>
                    <TargetIcons targets={targets} />
                    {own && <Pill title={`Managed by ${rule.ManagedBy}`}>managed</Pill>}
                    {!on && <Pill>disabled</Pill>}
                  </>
                ),
                actions: own ? undefined : (
                  <>
                    <ActionForm
                      action={setRuleState.bind(null, bus, rule.Name!, !on)}
                      submit={on ? `Disable ${rule.Name}` : `Enable ${rule.Name}`}
                      icon={on ? <Pause size={16} aria-hidden /> : <Play size={16} aria-hidden />}
                    />
                    <ActionForm
                      action={deleteRule.bind(null, bus, rule.Name!, false)}
                      submit={`Delete ${rule.Name}`}
                      icon={<Trash2 size={16} aria-hidden />}
                      tone="danger"
                      confirm={`Delete rule ${rule.Name}?`}
                    />
                  </>
                ),
              };
            })}
          />
        ) : (
          <ErrorNotice error={rules.error} />
        )}
      </Section>
    </Page>
  );
}
