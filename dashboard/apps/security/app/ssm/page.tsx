import { GetParametersCommand, DescribeParametersCommand } from "@aws-sdk/client-ssm";
import { collect, load, when } from "@mws-dashboard/aws";
import { ActionForm, Badge, ErrorNotice, Field, PageHeader, Section, Table } from "@mws-dashboard/ui";
import type { Metadata } from "next";
import Link from "next/link";

import { ssm } from "../../lib/clients";
import { deleteParameter, putParameter } from "./actions";

export const metadata: Metadata = { title: "Parameter Store" };

type Props = { searchParams: Promise<{ path?: string; reveal?: string }> };

export default async function Parameters({ searchParams }: Props) {
  const { path = "", reveal } = await searchParams;
  const client = await ssm();
  const params = await load(async () => {
    const list = await collect(
      (NextToken) =>
        client.send(
          new DescribeParametersCommand({
            NextToken,
            MaxResults: 50,
            ...(path ? { ParameterFilters: [{ Key: "Name", Option: "BeginsWith", Values: [path] }] } : {}),
          }),
        ),
      (r) => r.Parameters,
      (r) => r.NextToken,
    );
    const values = new Map<string, string>();
    for (let i = 0; i < list.length; i += 10) {
      const out = await client.send(new GetParametersCommand({ Names: list.slice(i, i + 10).map((p) => p.Name!), WithDecryption: !!reveal }));
      for (const p of out.Parameters ?? []) values.set(p.Name!, p.Value ?? "");
    }
    return list.map((p) => ({ meta: p, value: values.get(p.Name!) }));
  });
  const query = (extra: Record<string, string>) => {
    const q = new URLSearchParams({ ...(path ? { path } : {}), ...extra });
    return `/ssm${q.size ? `?${q}` : ""}`;
  };
  return (
    <>
      <PageHeader
        title="Parameter Store"
        description="SSM parameters in the selected region."
        actions={
          reveal ? (
            <Link className="button primary" href={query({})}>
              Hide SecureStrings
            </Link>
          ) : (
            <Link className="button primary" href={query({ reveal: "1" })}>
              Decrypt SecureStrings
            </Link>
          )
        }
      />
      <Section title="Put parameter">
        <ActionForm action={putParameter} submit="Put parameter" testId="put-parameter">
          <div className="form-row">
            <Field label="Name">
              <input name="name" required placeholder="/app/prod/db/host" size={32} />
            </Field>
            <Field label="Type">
              <select name="type" defaultValue="String">
                <option>String</option>
                <option>StringList</option>
                <option>SecureString</option>
              </select>
            </Field>
            <Field label="Value">
              <input name="value" required size={32} />
            </Field>
            <label className="check">
              <input type="checkbox" name="overwrite" /> Overwrite
            </label>
          </div>
        </ActionForm>
      </Section>
      <Section
        title={params.ok ? `Parameters (${params.value.length})` : "Parameters"}
        actions={
          <form className="form-row" action="/security/ssm">
            <input name="path" defaultValue={path} placeholder="Filter by prefix, e.g. /app/" aria-label="Name prefix" />
            {reveal && <input type="hidden" name="reveal" value="1" />}
            <button className="button primary" type="submit">
              Filter
            </button>
          </form>
        }
      >
        {params.ok ? (
          <Table
            label="Parameters"
            rows={params.value}
            rowKey={(p) => p.meta.Name!}
            empty="No parameters."
            columns={[
              { header: "Name", className: "wrap", cell: (p) => <code>{p.meta.Name}</code> },
              { header: "Type", cell: (p) => <Badge tone={p.meta.Type === "SecureString" ? "warn" : "neutral"}>{p.meta.Type}</Badge> },
              {
                header: "Value",
                className: "wrap",
                cell: (p) => (p.meta.Type === "SecureString" && !reveal ? <span className="muted">encrypted</span> : <code>{p.value}</code>),
              },
              { header: "Version", className: "num", cell: (p) => p.meta.Version },
              { header: "Modified", cell: (p) => when(p.meta.LastModifiedDate) },
              {
                header: "",
                cell: (p) => (
                  <ActionForm action={deleteParameter.bind(null, p.meta.Name!)} submit="Delete" tone="danger" confirm={`Delete ${p.meta.Name}?`} inline />
                ),
              },
            ]}
          />
        ) : (
          <ErrorNotice error={params.error} />
        )}
      </Section>
    </>
  );
}
