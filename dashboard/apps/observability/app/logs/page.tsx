import { DescribeLogGroupsCommand } from "@aws-sdk/client-cloudwatch-logs";
import { bytes, collect, load, when } from "@mws-dashboard/aws";
import { ActionForm, ErrorNotice, Field, PageHeader, Section, Table } from "@mws-dashboard/ui";
import type { Metadata } from "next";
import Link from "next/link";

import { groupHref, logs } from "../../lib/clients";
import { createGroup } from "./actions";

export const metadata: Metadata = { title: "Log groups" };

type Props = { searchParams: Promise<{ prefix?: string }> };

export default async function LogGroups({ searchParams }: Props) {
  const prefix = (await searchParams).prefix ?? "";
  const groups = await load(async () => {
    const client = await logs();
    return collect(
      (nextToken) => client.send(new DescribeLogGroupsCommand({ nextToken, ...(prefix ? { logGroupNamePrefix: prefix } : {}) })),
      (r) => r.logGroups,
      (r) => r.nextToken,
    );
  });
  return (
    <>
      <PageHeader title="Log groups" description="CloudWatch Logs groups in the selected region. Lambda functions log to /aws/lambda/<name>." />
      <Section
        title={groups.ok ? `Log groups (${groups.value.length})` : "Log groups"}
        actions={
          <form className="form-row" action="/observability/logs">
            <input name="prefix" defaultValue={prefix} placeholder="Name prefix" aria-label="Name prefix" />
            <button className="button primary" type="submit">
              Filter
            </button>
          </form>
        }
      >
        {groups.ok ? (
          <Table
            label="Log groups"
            rows={groups.value}
            rowKey={(g) => g.logGroupName!}
            empty="No log groups."
            columns={[
              { header: "Name", className: "wrap", cell: (g) => <Link href={groupHref(g.logGroupName!)}>{g.logGroupName}</Link> },
              { header: "Retention", cell: (g) => (g.retentionInDays ? `${g.retentionInDays} days` : "never expire") },
              { header: "Stored", className: "num", cell: (g) => bytes(g.storedBytes) },
              { header: "Metric filters", className: "num", cell: (g) => g.metricFilterCount ?? 0 },
              { header: "Created", cell: (g) => when(g.creationTime) },
            ]}
          />
        ) : (
          <ErrorNotice error={groups.error} />
        )}
      </Section>
      <Section title="Create log group">
        <ActionForm action={createGroup} submit="Create" inline testId="create-log-group">
          <Field label="Name">
            <input name="name" required size={40} />
          </Field>
        </ActionForm>
      </Section>
    </>
  );
}
