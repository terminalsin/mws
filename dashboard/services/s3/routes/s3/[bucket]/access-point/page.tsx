import { GetAccessPointCommand, GetAccessPointPolicyCommand, GetAccessPointPolicyStatusCommand, ListTagsForResourceCommand } from "@aws-sdk/client-s3-control";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, CodeBlock, ErrorNotice, Facts, Field, Page, Pill, Section, Sheet, Tags } from "@mws-dashboard/ui";
import { Globe, Pencil, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import type { ReactNode } from "react";

import { CONTROL_ICONS, accessPointHref, account, bucketHref, control, links, optional } from "../../../../lib/s3";
import { deleteAccessPoint, saveAccessPointPolicy, saveControlTags } from "../../control-actions";
import { BPA_SETTINGS, bpaSummary } from "../permissions";
import { PolicyEditor } from "@mws-dashboard/ui/policy";

type Props = { params: Promise<{ bucket: string }>; searchParams: Promise<{ name?: string }> };

export async function generateMetadata({ searchParams }: Props): Promise<Metadata> {
  return { title: (await searchParams).name ?? "Access point" };
}

export default async function AccessPoint({ params, searchParams }: Props) {
  const bucket = decodeURIComponent((await params).bucket);
  const name = (await searchParams).name ?? "";
  const back = { href: bucketHref(bucket, { tab: "access-points" }), label: bucket };
  const data = await load(async () => {
    const AccountId = await account();
    const client = await control();
    const [ap, policy, status] = await Promise.all([
      client.send(new GetAccessPointCommand({ AccountId, Name: name })),
      load(() => optional(() => client.send(new GetAccessPointPolicyCommand({ AccountId, Name: name })))),
      load(() => optional(() => client.send(new GetAccessPointPolicyStatusCommand({ AccountId, Name: name })))),
    ]);
    const tags = ap.AccessPointArn ? await load(async () => (await client.send(new ListTagsForResourceCommand({ AccountId, ResourceArn: ap.AccessPointArn! }))).Tags ?? []) : null;
    return { ap, policy, status, tags };
  });
  if (!data.ok) {
    return (
      <Page title={name} icon={CONTROL_ICONS.accessPoint} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { ap, policy, status, tags } = data.value;
  const doc = policy.ok ? policy.value?.Policy : undefined;
  const block = ap.PublicAccessBlockConfiguration;
  const path = accessPointHref(bucket, name).split("?")[0];
  const arn = ap.AccessPointArn ?? "";
  const template = JSON.stringify(
    {
      Version: "2012-10-17",
      Statement: [{ Effect: "Allow", Principal: { AWS: `arn:aws:iam::${arn.split(":")[4] ?? ""}:root` }, Action: ["s3:GetObject", "s3:PutObject"], Resource: `${arn}/object/*` }],
    },
    null,
    2,
  );
  return (
    <Page
      title={name}
      icon={ap.NetworkOrigin === "VPC" ? CONTROL_ICONS.vpcAccessPoint : CONTROL_ICONS.accessPoint}
      back={back}
      subtitle={arn}
      actions={
        <ActionForm
          action={deleteAccessPoint.bind(null, name, back.href)}
          submit="Delete access point"
          icon={<Trash2 size={16} aria-hidden />}
          tone="danger"
          confirm={`Delete access point ${name}?`}
          testId="delete-access-point"
        />
      }
    >
      <Section title="Properties">
        <Facts
          items={[
            ["Bucket", <Link href={bucketHref(ap.Bucket ?? bucket)}>{ap.Bucket}</Link>],
            ["Alias", <code>{ap.Alias}</code>],
            ["Network origin", ap.NetworkOrigin === "VPC" ? <>VPC <Link href={links.vpc(ap.VpcConfiguration?.VpcId ?? "")}>{ap.VpcConfiguration?.VpcId}</Link></> : "Internet"],
            ap.BucketAccountId && ["Bucket owner", ap.BucketAccountId],
            ["Created", ago(ap.CreationDate)],
            ...Object.entries(ap.Endpoints ?? {}).map(([k, v]) => [`Endpoint (${k})`, <code>{v}</code>] as [string, ReactNode]),
          ]}
        />
      </Section>
      <Section title="Block Public Access">
        <Facts items={[["Block all public access", bpaSummary(block)], ...BPA_SETTINGS.filter(([k]) => block && !block[k]).map(([, label]) => [label, "Off"] as [string, string])]} />
      </Section>
      <Section
        title="Access point policy"
        actions={
          <Sheet title="Access point policy" label="Edit access point policy" icon={<Pencil size={15} aria-hidden />} testId="edit-ap-policy">
            <ActionForm action={saveAccessPointPolicy.bind(null, name, bucket)} submit="Save" testId="edit-ap-policy">
              <PolicyEditor label="Policy JSON" hint="Empty removes the policy" format="policy" kind="resource" name="policy" rows={14} defaultValue={doc ? JSON.stringify(JSON.parse(doc), null, 2) : template} />
            </ActionForm>
          </Sheet>
        }
      >
        {status.ok && status.value?.PolicyStatus?.IsPublic && (
          <p>
            <Pill tone="bad" icon={<Globe size={12} aria-hidden />}>
              Public
            </Pill>
          </p>
        )}
        {!policy.ok ? <ErrorNotice error={policy.error} /> : doc ? <CodeBlock value={doc} label="Access point policy" /> : <span className="muted">None</span>}
      </Section>
      {tags && (
        <Section
          title="Tags"
          actions={
            <Sheet title="Tags" label="Edit tags" icon={<Pencil size={15} aria-hidden />} testId="edit-ap-tags">
              <ActionForm action={saveControlTags.bind(null, arn, tags.ok ? tags.value.map((t) => t.Key!) : [], path)} submit="Save" testId="edit-ap-tags">
                <Field label="One Key=Value per line" format="tags">
                  <textarea name="tags" defaultValue={(tags.ok ? tags.value : []).map((t) => `${t.Key}=${t.Value}`).join("\n")} />
                </Field>
              </ActionForm>
            </Sheet>
          }
        >
          {!tags.ok ? <ErrorNotice error={tags.error} /> : tags.value.length ? <Tags tags={tags.value} /> : <span className="muted">None</span>}
        </Section>
      )}
    </Page>
  );
}
