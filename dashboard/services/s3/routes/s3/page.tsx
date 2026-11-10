import { ListBucketsCommand } from "@aws-sdk/client-s3";
import { GetPublicAccessBlockCommand } from "@aws-sdk/client-s3-control";
import { stage, sections } from "@mws-dashboard/ai";
import { ago, load, region } from "@mws-dashboard/aws";
import { AwsIcon, Curated, Empty, ErrorNotice, Facts, Page, Pill, Section, Segments, Sheet } from "@mws-dashboard/ui";
import { Pencil, ShieldCheck } from "lucide-react";
import type { Metadata } from "next";
import type { ReactNode } from "react";

import { BUCKET_ICON, BUCKET_PURPOSES, account, bucketHref, control, controlHref, optional, s3 } from "../../lib/s3";
import { AccessPointList, CreateAccessPointSheet, accessPoints } from "./access-points";
import { CreateBucketForm } from "./create-bucket.tsx";
import { ControlTab, CONTROL_TABS } from "./control";
import { saveAccountBpa } from "./control-actions";
import { BPA_SETTINGS, BpaForm, bpaSummary } from "./[bucket]/permissions";

export const metadata: Metadata = { title: "S3" };

type Props = { searchParams: Promise<{ tab?: string; id?: string }> };

function CreateBucket({ names = [] }: { names?: string[] }) {
  return (
    <Sheet title="New bucket" label="Create bucket" testId="create-bucket">
      <CreateBucketForm names={names} />
    </Sheet>
  );
}

const TABS: [string, string][] = [
  ["buckets", "Buckets"],
  ["access-points", "Access Points"],
  ...CONTROL_TABS,
  ["block-public-access", "Block Public Access"],
];

async function Buckets() {
  const buckets = await load(async () => {
    const list = (await (await s3()).send(new ListBucketsCommand({}))).Buckets ?? [];
    return sections(
      list.map((b) => ({ ...b, text: b.Name! })),
      BUCKET_PURPOSES,
    );
  });
  const names = buckets.ok ? buckets.value.flatMap((s) => s.items.map((b) => b.Name!)) : [];
  const here = await region();
  return {
    actions: <CreateBucket names={names} />,
    body: buckets.ok ? (
      <Curated
        label="Buckets"
        sections={buckets.value}
        empty={<Empty icon={BUCKET_ICON} action={<CreateBucket names={names} />} />}
        row={(b) => {
          const env = stage(b.Name!);
          return {
            key: b.Name!,
            icon: <AwsIcon icon={BUCKET_ICON} size={24} />,
            title: b.Name,
            // The Region only says something when it is not this one.
            subtitle: b.BucketRegion && b.BucketRegion !== here ? b.BucketRegion : undefined,
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
    ),
  };
}

async function AccountBpa() {
  const bpa = await load(async () => optional(async () => (await (await control()).send(new GetPublicAccessBlockCommand({ AccountId: await account() }))).PublicAccessBlockConfiguration));
  const current = bpa.ok ? (bpa.value ?? {}) : undefined;
  return {
    actions: undefined,
    body: (
      <Section
        title="Block Public Access settings for this account"
        icon={<ShieldCheck size={16} aria-hidden />}
        actions={
          <Sheet title="Block Public Access (account)" label="Edit account Block Public Access" icon={<Pencil size={15} aria-hidden />} testId="edit-account-bpa">
            <BpaForm action={saveAccountBpa} current={current} testId="edit-account-bpa" />
          </Sheet>
        }
      >
        {!bpa.ok ? (
          <ErrorNotice error={bpa.error} />
        ) : (
          <Facts
            items={[
              ["Block all public access", bpaSummary(current)],
              ...BPA_SETTINGS.map(([k, label]) => [label, current?.[k] ? "On" : "Off"] as [string, string]),
            ]}
          />
        )}
      </Section>
    ),
  };
}

async function AccessPoints() {
  const [points, buckets] = await Promise.all([load(() => accessPoints()), load(async () => ((await (await s3()).send(new ListBucketsCommand({}))).Buckets ?? []).map((b) => b.Name!))]);
  return {
    actions: <CreateAccessPointSheet buckets={buckets.ok ? buckets.value : []} taken={points.ok ? points.value.map((p) => p.Name!) : []} />,
    body: <AccessPointList />,
  };
}

export default async function S3({ searchParams }: Props) {
  const { tab = "buckets", id } = await searchParams;
  const view: { actions?: ReactNode; body: ReactNode; title?: string } =
    tab === "access-points" ? await AccessPoints() : tab === "block-public-access" ? await AccountBpa() : tab === "buckets" ? await Buckets() : await ControlTab({ tab, id });
  return (
    <Page title={view.title ?? TABS.find(([t]) => t === tab)?.[1] ?? "Buckets"} actions={view.actions}>
      <Segments items={TABS.map(([t, label]) => ({ label, href: t === "buckets" ? "/s3" : controlHref(t), active: t === tab }))} />
      {view.body}
    </Page>
  );
}
