import { ListBucketsCommand } from "@aws-sdk/client-s3";
import { stage, sections } from "@mws-dashboard/ai";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, Page, Pill, Sheet } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { BUCKET_ICON, BUCKET_PURPOSES, ICON, bucketHref, s3 } from "../../lib/s3";
import { createBucket } from "./actions";

export const metadata: Metadata = { title: "S3" };

function CreateBucket() {
  return (
    <Sheet title="New bucket" label="Create bucket" testId="create-bucket">
      <ActionForm action={createBucket} submit="Create" testId="create-bucket">
        <Field label="Name">
          <input name="name" required minLength={3} maxLength={63} pattern="[a-z0-9][a-z0-9.\-]*[a-z0-9]" autoFocus />
        </Field>
        <label className="check">
          <input type="checkbox" name="versioning" /> Versioning
        </label>
      </ActionForm>
    </Sheet>
  );
}

export default async function Buckets() {
  const buckets = await load(async () => {
    const list = (await (await s3()).send(new ListBucketsCommand({}))).Buckets ?? [];
    return sections(
      list.map((b) => ({ ...b, text: b.Name! })),
      BUCKET_PURPOSES,
    );
  });
  return (
    <Page title="Buckets" actions={<CreateBucket />}>
      {buckets.ok ? (
        <Curated
          label="Buckets"
          sections={buckets.value}
          empty={<Empty icon={BUCKET_ICON} action={<CreateBucket />} />}
          row={(b) => {
            const env = stage(b.Name!);
            return {
              key: b.Name!,
              icon: <AwsIcon icon={BUCKET_ICON} size={24} />,
              title: b.Name,
              subtitle: b.BucketRegion,
              href: bucketHref(b.Name!),
              meta: (
                <>
                  {env && <Pill tone={env === "production" ? "warn" : "neutral"}>{env}</Pill>}
                  <span title={b.CreationDate?.toISOString()}>{ago(b.CreationDate)}</span>
                </>
              ),
            };
          }}
        />
      ) : (
        <ErrorNotice error={buckets.error} />
      )}
    </Page>
  );
}
