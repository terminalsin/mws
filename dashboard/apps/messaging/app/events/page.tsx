import { ListEventBusesCommand, ListRulesCommand, ListTargetsByRuleCommand } from "@aws-sdk/client-eventbridge";
import { collect, load } from "@mws-dashboard/aws";
import { ActionForm, Badge, CodeBlock, ErrorNotice, Field, PageHeader, Section, Table, Tabs } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { events } from "../../lib/clients";
import { createBus, putEvent, setRuleState } from "./actions";

export const metadata: Metadata = { title: "EventBridge" };

type Props = { searchParams: Promise<{ bus?: string }> };

export default async function EventBuses({ searchParams }: Props) {
  const bus = (await searchParams).bus ?? "default";
  const client = await events();
  const [buses, rules] = await Promise.all([
    load(async () =>
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
          targets: (await client.send(new ListTargetsByRuleCommand({ Rule: rule.Name!, EventBusName: bus }))).Targets ?? [],
        })),
      );
    }),
  ]);
  return (
    <>
      <PageHeader title="EventBridge" description="Event buses, their rules and targets. Put a test event to see rules fire." />
      {buses.ok ? (
        <Tabs
          items={buses.value.map((b) => ({
            label: b.Name!,
            href: b.Name === "default" ? "/events" : `/events?bus=${encodeURIComponent(b.Name!)}`,
            active: b.Name === bus,
          }))}
        />
      ) : (
        <ErrorNotice error={buses.error} />
      )}
      <Section title={rules.ok ? `Rules on ${bus} (${rules.value.length})` : `Rules on ${bus}`}>
        {rules.ok ? (
          <Table
            label="Rules"
            rows={rules.value}
            rowKey={(r) => r.rule.Name!}
            empty="No rules on this bus."
            columns={[
              { header: "Name", cell: (r) => <strong>{r.rule.Name}</strong> },
              {
                header: "State",
                cell: (r) => <Badge tone={r.rule.State === "ENABLED" ? "good" : "neutral"}>{r.rule.State?.toLowerCase()}</Badge>,
              },
              {
                header: "Pattern / schedule",
                className: "wrap",
                cell: (r) =>
                  r.rule.ScheduleExpression ? <code>{r.rule.ScheduleExpression}</code> : <CodeBlock value={r.rule.EventPattern} />,
              },
              {
                header: "Targets",
                className: "wrap",
                cell: (r) =>
                  r.targets.length === 0 ? (
                    <span className="muted">none</span>
                  ) : (
                    r.targets.map((t) => (
                      <div key={t.Id}>
                        <code>{t.Arn}</code>
                      </div>
                    ))
                  ),
              },
              {
                header: "",
                cell: (r) => (
                  <ActionForm
                    action={setRuleState.bind(null, bus, r.rule.Name!, r.rule.State !== "ENABLED")}
                    submit={r.rule.State === "ENABLED" ? "Disable" : "Enable"}
                    tone={r.rule.State === "ENABLED" ? "danger" : "primary"}
                    inline
                  />
                ),
              },
            ]}
          />
        ) : (
          <ErrorNotice error={rules.error} />
        )}
      </Section>
      <Section title={`Put an event on ${bus}`}>
        <ActionForm action={putEvent.bind(null, bus)} submit="Put event" testId="put-event">
          <div className="form-row">
            <Field label="Source">
              <input name="source" required defaultValue="mws.console" />
            </Field>
            <Field label="Detail type">
              <input name="detailType" required defaultValue="Test event" />
            </Field>
          </div>
          <Field label="Detail (JSON)">
            <textarea name="detail" defaultValue="{}" />
          </Field>
        </ActionForm>
      </Section>
      <Section title="Create event bus">
        <ActionForm action={createBus} submit="Create bus" inline>
          <Field label="Name">
            <input name="name" required pattern="[A-Za-z0-9._\-/]+" />
          </Field>
        </ActionForm>
      </Section>
    </>
  );
}
