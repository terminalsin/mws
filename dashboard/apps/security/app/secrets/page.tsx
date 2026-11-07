import { sections } from "@mws-dashboard/ai";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, Page, Pill, Sheet } from "@mws-dashboard/ui";
import { RotateCw } from "lucide-react";
import type { Metadata } from "next";

import { ICONS } from "../../lib/clients";
import { SECRET_KINDS, listSecrets } from "../../lib/secrets";
import { createSecret } from "./actions";

export const metadata: Metadata = { title: "Secrets Manager" };

export default async function Secrets() {
  const list = await load(listSecrets);
  const create = (
    <Sheet title="New secret" label="Create secret" testId="create-secret">
      <ActionForm action={createSecret} submit="Create" testId="create-secret">
        <Field label="Name">
          <input name="name" required placeholder="prod/app/db" autoFocus />
        </Field>
        <textarea name="value" rows={6} aria-label="Secret value" placeholder='{"username": "app", "password": "…"}' />
        <Field label="KMS key">
          <input name="kmsKeyId" placeholder="aws/secretsmanager" />
        </Field>
      </ActionForm>
    </Sheet>
  );
  if (!list.ok) {
    return (
      <Page title="Secrets Manager" icon={ICONS.secrets} actions={create}>
        <ErrorNotice error={list.error} />
      </Page>
    );
  }
  const items = list.value.map((s) => ({ ...s, name: s.Name!, text: `${s.Name} ${s.Description ?? ""} ${(s.Tags ?? []).map((t) => `${t.Key} ${t.Value}`).join(" ")}` }));
  const grouped = await sections(items, SECRET_KINDS, "Other");
  return (
    <Page title="Secrets Manager" icon={ICONS.secrets} actions={create}>
      <Curated
        label="Secrets"
        sections={grouped}
        empty={<Empty icon={ICONS.secrets} />}
        row={(s) => ({
          key: s.ARN!,
          icon: <AwsIcon icon={ICONS.secrets} size={24} />,
          title: s.Name,
          subtitle: s.Description,
          href: `/secrets/secret?id=${encodeURIComponent(s.ARN!)}`,
          meta: s.DeletedDate ? (
            <Pill tone="bad">deleted {ago(s.DeletedDate)}</Pill>
          ) : (
            <>
              {s.RotationEnabled && <RotateCw size={14} aria-label="Rotates" />}
              <span>{ago(s.LastChangedDate ?? s.CreatedDate)}</span>
            </>
          ),
        })}
      />
    </Page>
  );
}
