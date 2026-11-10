import {
  DescribeInsightRulesCommand,
  GetInsightRuleReportCommand,
} from "@aws-sdk/client-cloudwatch";
import { all, load, mws } from "@mws-dashboard/aws";
import {
  ActionForm,
  Empty,
  ErrorNotice,
  Field,
  List,
  Page,
  Pill,
  Section,
  Sheet,
  Status,
  Table,
} from "@mws-dashboard/ui";
import { PutInsightRule } from "@mws-dashboard/ui/model/cloudwatch";
import { Pause, Play, Trash2, Users } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, cloudwatch, listGroups } from "../../../lib/clients";
import { deleteInsightRule, putInsightRule, setInsightRule } from "../actions";

export const metadata: Metadata = { title: "Contributor Insights" };

type Props = { searchParams: Promise<{ rule?: string }> };

/** A rule over JSON logs: the top values of one key, counted. */
const template = (group: string) =>
  JSON.stringify(
    {
      Schema: { Name: "CloudWatchLogRule", Version: 1 },
      LogGroupNames: [group],
      LogFormat: "JSON",
      Contribution: { Keys: ["$.user"], Filters: [] },
      AggregateOn: "Count",
    },
    null,
    2,
  );

async function Report({ name }: { name: string }) {
  const report = await load(async () => {
    const now = new Date((await mws<{ now: string }>("/_mws/clock")).now);
    return (await cloudwatch()).send(
      new GetInsightRuleReportCommand({
        RuleName: name,
        StartTime: new Date(now.getTime() - 3600_000),
        EndTime: new Date(now.getTime() + 60_000),
        Period: 60,
        MaxContributorCount: 10,
      }),
    );
  });
  if (!report.ok) return <ErrorNotice error={report.error} />;
  const keys = report.value.KeyLabels ?? [];
  const rows = report.value.Contributors ?? [];
  return (
    <Section
      title={`${name} · last hour`}
      count={report.value.ApproximateUniqueCount}
      plain
    >
      <Table
        label="Top contributors"
        rows={rows}
        rowKey={(r) => (r.Keys ?? []).join("|")}
        empty={<Empty icon={ICONS.metrics} />}
        columns={[
          ...keys.map((k, i) => ({
            header: k,
            cell: (r: (typeof rows)[number]) => r.Keys?.[i] ?? "",
          })),
          {
            header: "Value",
            className: "num",
            cell: (r) => r.ApproximateAggregateValue ?? 0,
          },
        ]}
      />
    </Section>
  );
}

export default async function Contributors({ searchParams }: Props) {
  const { rule } = await searchParams;
  const [rules, groups] = await Promise.all([
    load(async () => {
      const c = await cloudwatch();
      return all(
        (NextToken) => c.send(new DescribeInsightRulesCommand({ NextToken })),
        (r) => r.InsightRules,
        (r) => r.NextToken,
      );
    }),
    load(() => listGroups()),
  ]);
  const firstGroup = groups.ok
    ? (groups.value[0]?.logGroupName ?? "/app/api")
    : "/app/api";
  const create = (
    <Sheet title="Create rule" label="Create rule" testId="create-insight-rule">
      <ActionForm
        action={putInsightRule}
        submit="Create"
        testId="create-insight-rule"
      >
        <Field
          label="Name"
          rule={PutInsightRule.RuleName}
          taken={rules.ok ? rules.value.map((r) => r.Name!) : []}
          generate="name"
          unique
        >
          <input name="name" autoFocus />
        </Field>
        <Field
          label="Rule"
          rule={{ ...PutInsightRule.RuleDefinition, format: "json" }}
        >
          <textarea
            name="definition"
            rows={12}
            className="code-editor"
            defaultValue={template(firstGroup)}
          />
        </Field>
      </ActionForm>
    </Sheet>
  );
  return (
    <Page
      title="Contributor Insights"
      icon={ICONS.metrics}
      back={{ href: "/metrics", label: "Metrics" }}
      actions={create}
    >
      {rules.ok ? (
        <List
          label="Insight rules"
          empty={<Empty icon={ICONS.metrics} action={create} />}
          rows={rules.value.map((r) => {
            const enabled = r.State === "ENABLED";
            let groupsOf: string[] = [];
            try {
              groupsOf =
                (
                  JSON.parse(r.Definition ?? "{}") as {
                    LogGroupNames?: string[];
                  }
                ).LogGroupNames ?? [];
            } catch {
              // a managed rule's definition
            }
            return {
              key: r.Name!,
              icon: <Users size={18} />,
              title: r.Name,
              subtitle: groupsOf.length ? groupsOf.join(", ") : undefined,
              href: `/metrics/contributors?${new URLSearchParams({ rule: r.Name! })}`,
              meta: (
                <>
                  {r.ManagedRule && <Pill>Managed</Pill>}
                  <Status tone={enabled ? "good" : "neutral"}>
                    {r.State?.toLowerCase() ?? ""}
                  </Status>
                </>
              ),
              actions: (
                <>
                  <ActionForm
                    action={setInsightRule.bind(null, r.Name!, !enabled)}
                    submit={enabled ? `Disable ${r.Name}` : `Enable ${r.Name}`}
                    icon={enabled ? <Pause size={15} /> : <Play size={15} />}
                  />
                  {!r.ManagedRule && (
                    <ActionForm
                      action={deleteInsightRule.bind(null, r.Name!)}
                      submit={`Delete ${r.Name}`}
                      icon={<Trash2 size={15} />}
                      tone="danger"
                      confirm={`Delete ${r.Name}?`}
                    />
                  )}
                </>
              ),
            };
          })}
        />
      ) : (
        <ErrorNotice error={rules.error} />
      )}
      {rule && <Report name={rule} />}
    </Page>
  );
}
