import { ListEventBusesCommand, ListRulesCommand, ListTargetsByRuleCommand, type Target } from "@aws-sdk/client-eventbridge";
import { collect, load, shortName } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Field, List, Page, Pill, Section, Segments, SERVICES, Sheet } from "@mws-dashboard/ui";
import { Clock, Pause, Play, Send, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { events, ICONS } from "../../lib/clients";
import { createBus, createRule, deleteBus, deleteRule, putEvent, setRuleState } from "./actions";

export const metadata: Metadata = { title: "EventBridge" };

type Props = { searchParams: Promise<{ bus?: string }> };

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
  return (
    <Page
      title="Rules"
      actions={
        <>
          <Sheet title={`Send event to ${bus}`} label="Send event" icon={<Send size={15} aria-hidden />} testId="put-event">
            <ActionForm action={putEvent.bind(null, bus)} submit="Send" testId="put-event">
              <div className="form-row">
                <Field label="Source">
                  <input name="source" required defaultValue="mws.console" />
                </Field>
                <Field label="Detail type">
                  <input name="detailType" required defaultValue="Test event" />
                </Field>
              </div>
              <Field label="Detail">
                <textarea name="detail" defaultValue="{}" />
              </Field>
            </ActionForm>
          </Sheet>
          <Sheet title="New event bus" label="Create event bus" icon={<AwsIcon icon={ICONS.bus} size={18} />}>
            <ActionForm action={createBus} submit="Create">
              <Field label="Name">
                <input name="name" required pattern="[A-Za-z0-9._\-/]+" />
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
                <Field label="Name">
                  <input name="name" required pattern="[A-Za-z0-9._\-]+" />
                </Field>
                <Field label="Event pattern">
                  <textarea name="pattern" placeholder='{"source": ["my.app"]}' />
                </Field>
                <Field label="Or schedule">
                  <input name="schedule" placeholder="rate(5 minutes)" />
                </Field>
                <Field label="Target ARN">
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
