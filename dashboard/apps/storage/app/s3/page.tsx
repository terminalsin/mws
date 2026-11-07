import { ListBucketsCommand } from "@aws-sdk/client-s3";
import { load, when } from "@mws-dashboard/aws";
import { ActionForm, ErrorNotice, Field, PageHeader, Section, Table } from "@mws-dashboard/ui";
import type { Metadata } from "next";
import Link from "next/link";

import { folderHref, s3 } from "../../lib/s3";
import { createBucket } from "./actions";

export const metadata: Metadata = { title: "S3 buckets" };

export default async function Buckets() {
  const buckets = await load(async () => {
    const out = await (await s3()).send(new ListBucketsCommand({}));
    return out.Buckets ?? [];
  });
  return (
    <>
      <PageHeader title="S3 buckets" description="Every bucket the current account owns, in all regions." />
      <Section title="Create bucket">
        <ActionForm action={createBucket} submit="Create bucket" inline testId="create-bucket">
          <Field label="Bucket name" hint="Created in the region picked in the top bar.">
            <input name="name" required minLength={3} maxLength={63} pattern="[a-z0-9][a-z0-9.\-]*[a-z0-9]" />
          </Field>
        </ActionForm>
      </Section>
      <Section title={buckets.ok ? `Buckets (${buckets.value.length})` : "Buckets"}>
        {buckets.ok ? (
          <Table
            label="Buckets"
            rows={buckets.value}
            rowKey={(b) => b.Name!}
            empty="No buckets yet."
            columns={[
              { header: "Name", cell: (b) => <Link href={folderHref(b.Name!, "")}>{b.Name}</Link> },
              { header: "Region", cell: (b) => b.BucketRegion ?? "—" },
              { header: "Created", cell: (b) => when(b.CreationDate) },
            ]}
          />
        ) : (
          <ErrorNotice error={buckets.error} />
        )}
      </Section>
    </>
  );
}
