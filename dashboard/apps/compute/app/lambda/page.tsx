import { ListFunctionsCommand } from "@aws-sdk/client-lambda";
import { bytes, collect, load, when } from "@mws-dashboard/aws";
import { Badge, ErrorNotice, PageHeader, Section, Table } from "@mws-dashboard/ui";
import type { Metadata } from "next";
import Link from "next/link";

import { lambda } from "../../lib/clients";

export const metadata: Metadata = { title: "Lambda functions" };

export default async function Functions() {
  const functions = await load(async () => {
    const client = await lambda();
    return collect(
      (Marker) => client.send(new ListFunctionsCommand({ Marker })),
      (r) => r.Functions,
      (r) => r.NextMarker,
    );
  });
  return (
    <>
      <PageHeader
        title="Lambda functions"
        description="Functions in the selected region. MWS runs them for real on your machine; open one to invoke it."
      />
      <Section title={functions.ok ? `Functions (${functions.value.length})` : "Functions"}>
        {functions.ok ? (
          <Table
            label="Functions"
            rows={functions.value}
            rowKey={(f) => f.FunctionArn!}
            empty="No functions in this region. Deploy one with the SDK, the CLI or your IaC tool."
            columns={[
              { header: "Name", cell: (f) => <Link href={`/lambda/${encodeURIComponent(f.FunctionName!)}`}>{f.FunctionName}</Link> },
              { header: "Runtime", cell: (f) => <Badge>{f.Runtime ?? f.PackageType}</Badge> },
              { header: "Handler", cell: (f) => <code>{f.Handler}</code> },
              { header: "Memory", className: "num", cell: (f) => `${f.MemorySize} MB` },
              { header: "Code size", className: "num", cell: (f) => bytes(f.CodeSize) },
              { header: "Last modified", cell: (f) => when(f.LastModified) },
            ]}
          />
        ) : (
          <ErrorNotice error={functions.error} />
        )}
      </Section>
    </>
  );
}
