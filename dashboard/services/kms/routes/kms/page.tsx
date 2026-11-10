import type { KeyMetadata } from "@aws-sdk/client-kms";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, Metric, Metrics, Page, Pill, Sheet, Status } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { ICONS } from "../../lib/clients";
import { ALL_SPECS, STATE_TONE, USAGE, listAliases, listKeys } from "../../lib/kms";
import { ALIAS, DESCRIPTION, KEY_POLICY, ROTATION_DAYS, TAGS, takenAliases } from "../../lib/rules";
import { createKey } from "./actions";

export const metadata: Metadata = { title: "KMS" };



type Props = { searchParams: Promise<{ tab?: string }> };

export default async function Keys({ searchParams }: Props) {
  const { tab = "customer" } = await searchParams;
  const [keys, aliases] = await Promise.all([load(listKeys), load(listAliases)]);
  const taken = takenAliases(aliases.ok ? aliases.value.map((a) => a.AliasName!) : []);
  const create = (
    <Sheet title="New key" label="Create key" testId="create-key">
      <ActionForm action={createKey} submit="Create" testId="create-key">
        <Field label="Alias" rule={ALIAS} taken={taken} unique>
          <input name="alias" placeholder="alias/app-data" autoFocus />
        </Field>
        <Field label="Description" rule={DESCRIPTION}>
          <input name="description" />
        </Field>
        <div className="form-row">
          <Field label="Key usage" member="KeyUsage">
            <select name="usage" defaultValue="">
              <option value="">By key spec</option>
              {USAGE.map((u) => (
                <option key={u.id} value={u.id}>
                  {u.title}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Key spec" member="KeySpec">
            <select name="spec" defaultValue="SYMMETRIC_DEFAULT">
              {ALL_SPECS.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </Field>
        </div>
        <Field label="Key material origin" member="Origin">
          <select name="origin" defaultValue="AWS_KMS">
            <option value="AWS_KMS">KMS</option>
            <option value="EXTERNAL">External (import key material)</option>
          </select>
        </Field>
        <div className="form-row">
          <label className="check">
            <input type="checkbox" name="rotation" defaultChecked /> Automatic rotation
          </label>
          <Field label="Rotation period (days)" rule={ROTATION_DAYS} member="RotationPeriodInDays">
            <input name="rotationDays" type="number" placeholder="365" />
          </Field>
        </div>
        <label className="check">
          <input type="checkbox" name="multiRegion" /> Multi-Region
        </label>
        <Field label="Tags" rule={TAGS}>
          <textarea name="tags" rows={2} placeholder="team=payments" />
        </Field>
        <details>
          <summary>Key policy</summary>
          <Field label="Key policy" rule={KEY_POLICY}>
            <textarea name="policy" rows={8} placeholder="Default: the account root may use and manage the key" className="code-editor" spellCheck={false} />
          </Field>
        </details>
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
        empty={<Empty icon={ICONS.key} />}
      />
    </Page>
  );
}
