import type { KeyMetadata } from "@aws-sdk/client-kms";
import { ago, load } from "@mws-dashboard/aws";
import { AwsIcon, Curated, Empty, ErrorNotice, Metric, Metrics, Page, Pill, Sheet, Status } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { ICONS } from "../../lib/clients";
import { STATE_TONE, USAGE, listAliases, listKeys } from "../../lib/kms";
import { takenAliases } from "../../lib/rules";
import { CreateKeyForm } from "./create-key.tsx";

export const metadata: Metadata = { title: "KMS" };

type Props = { searchParams: Promise<{ tab?: string }> };

export default async function Keys({ searchParams }: Props) {
  const { tab = "customer" } = await searchParams;
  const [keys, aliases] = await Promise.all([load(listKeys), load(listAliases)]);
  const taken = takenAliases(aliases.ok ? aliases.value.map((a) => a.AliasName!) : []);
  const create = (
    <Sheet title="New key" label="Create key" testId="create-key">
      <CreateKeyForm taken={taken} />
    </Sheet>
  );
  if (!keys.ok) {
    return (
      <Page title={tab === "aws" ? "AWS managed keys" : "Customer managed keys"} actions={create}>
        <ErrorNotice error={keys.error} />
      </Page>
    );
  }
  const customer = keys.value.filter((k) => k.meta.KeyManager === "CUSTOMER");
  const aws = keys.value.filter((k) => k.meta.KeyManager !== "CUSTOMER");
  const pending = customer.filter((k) => k.meta.KeyState === "PendingDeletion").length;
  const shown = tab === "aws" ? aws : customer;
  const row = ({ meta, aliases }: { meta: KeyMetadata; aliases: string[] }) => ({
    key: meta.KeyId!,
    icon: <AwsIcon icon={ICONS.key} size={24} />,
    title: aliases[0]?.replace(/^alias\//, "") ?? <code>{meta.KeyId}</code>,
    subtitle: [
      aliases.length > 1 ? `+${aliases.length - 1}` : null,
      meta.KeySpec !== "SYMMETRIC_DEFAULT" ? meta.KeySpec : null,
      meta.Origin === "EXTERNAL" ? "imported" : meta.Origin === "EXTERNAL_KEY_STORE" ? "external key store" : null,
      meta.MultiRegion ? `multi-Region ${meta.MultiRegionConfiguration?.MultiRegionKeyType?.toLowerCase() ?? ""}`.trim() : null,
    ]
      .filter(Boolean)
      .join(" · "),
    href: `/kms/key?id=${meta.KeyId}`,
    meta:
      meta.KeyState === "PendingDeletion" ? (
        <Pill tone="bad">{ago(meta.DeletionDate)}</Pill>
      ) : meta.KeyState !== "Enabled" ? (
        <Status tone={STATE_TONE[meta.KeyState!] ?? "neutral"}>{meta.KeyState}</Status>
      ) : (
        <span>{ago(meta.CreationDate)}</span>
      ),
  });
  return (
    <Page title={tab === "aws" ? "AWS managed keys" : "Customer managed keys"} actions={create}>
      {(customer.length > 0 || pending > 0) && (
        <Metrics>
          <Metric label="Customer keys" value={customer.length} />
          <Metric label="Disabled" value={customer.filter((k) => k.meta.KeyState === "Disabled").length} />
          {pending > 0 && <Metric label="Pending deletion" value={pending} tone="bad" />}
        </Metrics>
      )}
      <Curated
        label="Keys"
        sections={[
          ...USAGE.map((u) => ({ id: u.id, title: u.title, items: shown.filter((k) => k.meta.KeyUsage === u.id) })),
          // A usage KMS adds later still shows, under its own name.
          { id: "other", title: "Other", items: shown.filter((k) => !USAGE.some((u) => u.id === k.meta.KeyUsage)) },
        ]}
        row={row}
        empty={<Empty icon={ICONS.key} action={tab === "aws" ? undefined : create} />}
      />
    </Page>
  );
}
