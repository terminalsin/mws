import { GetFunctionCommand, ListEventSourceMappingsCommand } from "@aws-sdk/client-lambda";
import { bytes, load, when } from "@mws-dashboard/aws";
import { ActionForm, Badge, ErrorNotice, Field, KeyValue, PageHeader, Section, Table, type Tone, zoneHref } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { lambda } from "../../../lib/clients";
import { invoke } from "../actions";

type Props = { params: Promise<{ name: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  return { title: decodeURIComponent((await params).name) };
}

const STATE_TONE: Record<string, Tone> = { Active: "good", Pending: "warn", Inactive: "neutral", Failed: "bad" };

export default async function LambdaFunction({ params }: Props) {
  const name = decodeURIComponent((await params).name);
  const client = await lambda();
  const data = await load(async () => {
    const [fn, mappings] = await Promise.all([
      client.send(new GetFunctionCommand({ FunctionName: name })),
      client.send(new ListEventSourceMappingsCommand({ FunctionName: name })),
    ]);
    return { fn, mappings: mappings.EventSourceMappings ?? [] };
  });
  const crumbs = [{ label: "Lambda functions", href: "/lambda" }];
  if (!data.ok) {
    return (
      <>
        <PageHeader title={name} crumbs={crumbs} />
        <ErrorNotice error={data.error} />
      </>
    );
  }
  const c = data.value.fn.Configuration!;
  const logGroup = c.LoggingConfig?.LogGroup ?? `/aws/lambda/${c.FunctionName}`;
  const env = Object.entries(c.Environment?.Variables ?? {});
  return (
    <>
      <PageHeader
        title={name}
        crumbs={crumbs}
        description={<code>{c.FunctionArn}</code>}
        actions={
          <a className="button primary" href={`${zoneHref("observability", "/logs/group")}?name=${encodeURIComponent(logGroup)}`}>
            View logs
          </a>
        }
      />
      <Section title="Invoke">
        <ActionForm action={invoke.bind(null, name)} submit="Invoke" testId="invoke">
          <Field label="Event (JSON)">
            <textarea name="payload" defaultValue={'{\n  "hello": "world"\n}'} />
          </Field>
        </ActionForm>
      </Section>
      <Section title="Configuration">
        <KeyValue
          items={[
            ["State", <Badge tone={STATE_TONE[c.State ?? ""] ?? "neutral"}>{c.State ?? "Active"}</Badge>],
            ["Runtime", c.Runtime ?? c.PackageType],
            ["Handler", <code>{c.Handler}</code>],
            ["Architecture", c.Architectures?.join(", ")],
            ["Memory", `${c.MemorySize} MB`],
            ["Timeout", `${c.Timeout}s`],
            ["Code size", bytes(c.CodeSize)],
            ["Execution role", <code>{c.Role}</code>],
            ["Last modified", when(c.LastModified)],
            ["Version", c.Version],
            ["Log group", <code>{logGroup}</code>],
            ["Layers", c.Layers?.map((l) => l.Arn).join(", ") || "none"],
          ]}
        />
      </Section>
      <Section title="Environment variables">
        <Table
          label="Environment"
          rows={env}
          rowKey={([k]) => k}
          empty="No environment variables."
          columns={[
            { header: "Name", cell: ([k]) => <code>{k}</code> },
            { header: "Value", className: "wrap", cell: ([, v]) => <code>{v}</code> },
          ]}
        />
      </Section>
      <Section title="Event source mappings">
        <Table
          label="Event source mappings"
          rows={data.value.mappings}
          rowKey={(m) => m.UUID!}
          empty="No event source mappings."
          columns={[
            { header: "Source", className: "wrap", cell: (m) => <code>{m.EventSourceArn}</code> },
            { header: "State", cell: (m) => <Badge tone={m.State === "Enabled" ? "good" : "neutral"}>{m.State}</Badge> },
            { header: "Batch size", className: "num", cell: (m) => m.BatchSize },
          ]}
        />
      </Section>
    </>
  );
}
