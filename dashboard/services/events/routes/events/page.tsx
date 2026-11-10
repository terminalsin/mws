import { ListEventBusesCommand, ListRulesCommand, ListTargetsByRuleCommand, type Target } from "@aws-sdk/client-eventbridge";
import { collect, load, shortName } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Field, List, Page, Pill, Section, Segments, SERVICES, Sheet, type Rule } from "@mws-dashboard/ui";
import { CreateEventBus, PutEvents, PutRule, PutTargets } from "@mws-dashboard/ui/model/eventbridge";
import { Clock, Pause, Play, Send, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { events, ICONS } from "../../lib/clients";
import { createBus, createRule, deleteBus, deleteRule, putEvent, setRuleState } from "./actions";

export const metadata: Metadata = { title: "EventBridge" };

type Props = { searchParams: Promise<{ bus?: string }> };

const ENTRY = PutEvents.Entries.item!.fields!;
// A target is optional here: the rule can get one later.
const TARGET: Rule = { ...PutTargets.Targets.item!.fields!.Arn, required: false };
// Sources under aws. belong to AWS services; PutEvents refuses them.
const SOURCE: Rule = { ...ENTRY.Source, reserved: ["aws."] };
// The model allows "/" for partner buses only; custom buses can't use aws.
const BUS_NAME: Rule = {
  ...CreateEventBus.Name,
  pattern: "^[.\\-_A-Za-z0-9]+$",
  reserved: ["aws."],
  hint: "Letters, digits, . - and _",
  generate: "name",
};
const RULE_NAME: Rule = { ...PutRule.Name, hint: "Letters, digits, . - and _", generate: "name" };

/** The exact strings a rule's pattern matches at a top-level field. */
function patternValues(pattern: string | undefined, field: string): string[] {
  try {
    const values = (JSON.parse(pattern ?? "{}") as Record<string, unknown>)[field];
    return Array.isArray(values) ? values.filter((v): v is string => typeof v === "string") : [];
  } catch {
    return [];
  }
}

/** The catalog service an ARN belongs to, for its icon. */
function targetIcon(arn?: string) {
  const service = arn?.split(":")[2];
  const map: Record<string, string> = { sqs: "sqs", sns: "sns", lambda: "lambda", logs: "cloudwatch", events: "events", kinesis: "kinesis", firehose: "firehose", states: "events" };
  const s = SERVICES.find((x) => x.id === map[service ?? ""]);
  return s?.icon ?? "service/AmazonEventBridge";
}

export default async function EventBridge({ searchParams }: Props) {
  const bus = (await searchParams).bus ?? "default";
  const client = await events();
  const [buses, rules] = await Promise.all([
    load(() =>
      collect(
        (NextToken) => client.send(new ListEventBusesCommand({ NextToken })),
        (r) => r.EventBuses,
        (r) => r.NextToken,
      ),
    ),
    load(async () => {
      const list = await collect(
        (NextToken) => client.send(new ListRulesCommand({ EventBusName: bus, NextToken })),
        (r) => r.Rules,
        (r) => r.NextToken,
      );
      return Promise.all(
        list.map(async (rule) => ({
          rule,
          targets: ((await client.send(new ListTargetsByRuleCommand({ Rule: rule.Name!, EventBusName: bus }))).Targets ?? []) as Target[],
        })),
      );
    }),
  ]);
  const listed = rules.ok ? rules.value : [];
  const sources = [...new Set(listed.flatMap(({ rule }) => patternValues(rule.EventPattern, "source")))].filter((v) => !v.startsWith("aws."));
  const detailTypes = [...new Set(listed.flatMap(({ rule }) => patternValues(rule.EventPattern, "detail-type")))];
  const targetArns = [...new Set(listed.flatMap(({ targets }) => targets.map((t) => t.Arn!)))];
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
              <Field label="Name" rule={BUS_NAME} taken={buses.ok ? buses.value.map((b) => b.Name!) : undefined} unique>
                <input name="name" required autoFocus />
              </Field>
            </ActionForm>
          </Sheet>
        </>
      }
    >
      {buses.ok ? (
        buses.value.length > 1 && (
          <Segments
            label="Event buses"
            items={buses.value.map((b) => ({
              label: b.Name!,
              href: b.Name === "default" ? "/events" : `/events?bus=${encodeURIComponent(b.Name!)}`,
              active: b.Name === bus,
            }))}
          />
        )
      ) : (
        <ErrorNotice error={buses.error} />
      )}
      <Section
        title="Rules"
        count={rules.ok ? rules.value.length : undefined}
        plain
        actions={
          <>
            {bus !== "default" && (
              <ActionForm
                action={deleteBus.bind(null, bus)}
                submit={`Delete ${bus}`}
                icon={<Trash2 size={16} aria-hidden />}
                tone="danger"
                confirm={`Delete event bus ${bus}?`}
              />
            )}
            <Sheet title={`New rule on ${bus}`} label="Create rule" testId="create-rule">
              <ActionForm action={createRule.bind(null, bus)} submit="Create" testId="create-rule">
                <Field label="Name" rule={RULE_NAME} taken={listed.map(({ rule }) => rule.Name!)} unique>
                  <input name="name" required autoFocus />
                </Field>
                <Field label="Event pattern" rule={PutRule.EventPattern} member="EventPattern" format="eventPattern">
                  <textarea name="pattern" placeholder='{"source": ["my.app"]}' />
                </Field>
                {/* Schedules run on the default bus only. */}
                {bus === "default" && (
                  <Field label="Or schedule" rule={PutRule.ScheduleExpression} member="ScheduleExpression" format="schedule">
                    <input name="schedule" placeholder="rate(5 minutes)" />
                  </Field>
                )}
                <Field label="Target ARN" rule={TARGET} member="Arn" format="arn" known={targetArns}>
                  <input name="target" placeholder="arn:aws:sqs:…" />
                </Field>
              </ActionForm>
            </Sheet>
          </>
        }
      >
        {rules.ok ? (
          <List
            label="Rules"
            empty={<Empty icon={ICONS.rule} />}
            rows={rules.value.map(({ rule, targets }) => {
              const enabled = rule.State === "ENABLED";
              return {
                key: rule.Name!,
                icon: rule.ScheduleExpression ? <Clock size={18} aria-hidden /> : <AwsIcon icon={ICONS.rule} size={24} />,
                title: rule.Name,
                subtitle: rule.ScheduleExpression ? (
                  rule.ScheduleExpression
                ) : (
                  <details>
                    <summary>pattern</summary>
                    <CodeBlock value={rule.EventPattern} />
                  </details>
                ),
                meta: (
                  <>
                    <span className="icon-stack" title={targets.map((t) => t.Arn).join("\n")}>
                      {targets.map((t) => (
                        <AwsIcon key={t.Id} icon={targetIcon(t.Arn)} size={22} label={shortName(t.Arn)} />
                      ))}
                    </span>
                    {!enabled && <Pill>disabled</Pill>}
                  </>
                ),
                actions: (
                  <>
                    <ActionForm
                      action={setRuleState.bind(null, bus, rule.Name!, !enabled)}
                      submit={enabled ? `Disable ${rule.Name}` : `Enable ${rule.Name}`}
                      icon={enabled ? <Pause size={16} aria-hidden /> : <Play size={16} aria-hidden />}
                    />
                    <ActionForm
                      action={deleteRule.bind(null, bus, rule.Name!)}
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
