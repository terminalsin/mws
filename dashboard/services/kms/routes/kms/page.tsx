import type { KeyMetadata } from "@aws-sdk/client-kms";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, Metric, Metrics, Page, Pill, Sheet, Status } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { ICONS } from "../../lib/clients";
import { STATE_TONE, listKeys } from "../../lib/kms";
import { createKey } from "./actions";

export const metadata: Metadata = { title: "KMS" };


const USAGE = [
  { id: "ENCRYPT_DECRYPT", title: "Encryption" },
  { id: "SIGN_VERIFY", title: "Signing" },
  { id: "GENERATE_VERIFY_MAC", title: "MAC" },
  { id: "KEY_AGREEMENT", title: "Key agreement" },
];

type Props = { searchParams: Promise<{ tab?: string }> };

export default async function Keys({ searchParams }: Props) {
  const { tab = "customer" } = await searchParams;
  const keys = await load(listKeys);
  const create = (
    <Sheet title="New key" label="Create key" testId="create-key">
      <ActionForm action={createKey} submit="Create" testId="create-key">
        <Field label="Alias">
          <input name="alias" placeholder="alias/app-data" autoFocus />
        </Field>
        <Field label="Key spec">
          <select name="spec" defaultValue="SYMMETRIC_DEFAULT">
            {["SYMMETRIC_DEFAULT", "RSA_2048", "RSA_3072", "RSA_4096", "ECC_NIST_P256", "ECC_NIST_P384", "ECC_NIST_P521", "ECC_SECG_P256K1", "HMAC_224", "HMAC_256", "HMAC_384", "HMAC_512"].map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </Field>
        <Field label="RSA usage">
          <select name="usage" defaultValue="encrypt">
            <option value="encrypt">Encrypt and decrypt</option>
            <option value="sign">Sign and verify</option>
          </select>
        </Field>
        <label className="check">
          <input type="checkbox" name="rotation" defaultChecked /> Automatic rotation
        </label>
        <label className="check">
          <input type="checkbox" name="multiRegion" /> Multi-Region
        </label>
      </ActionForm>
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
    subtitle: [aliases.length > 1 ? `+${aliases.length - 1}` : null, meta.KeySpec !== "SYMMETRIC_DEFAULT" ? meta.KeySpec : null, meta.MultiRegion ? "multi-Region" : null]
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
        sections={USAGE.map((u) => ({ ...u, items: shown.filter((k) => k.meta.KeyUsage === u.id) }))}
        row={row}
        empty={<Empty icon={ICONS.key} />}
      />
    </Page>
  );
}
