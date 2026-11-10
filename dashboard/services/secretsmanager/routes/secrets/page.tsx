import { sections } from "@mws-dashboard/ai";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, Page, Pill, Sheet, type Rule } from "@mws-dashboard/ui";
import { CreateSecret } from "@mws-dashboard/ui/model/secretsmanager";
import { RotateCw } from "lucide-react";
import type { Metadata } from "next";

import { ICONS } from "../../lib/clients";
import { kmsKeys } from "../../lib/known";
import { SECRET_KINDS, listSecrets } from "../../lib/secrets";
import { createSecret } from "./actions";

export const metadata: Metadata = { title: "Secrets Manager" };

// The model leaves names unconstrained; the characters are in AWS's docs.
const NAME: Rule = { ...CreateSecret.Name, pattern: "^[A-Za-z0-9/_+=.@-]+$", hint: "Letters, digits and /_+=.@-", generate: "name" };
// The console asks for a value; an empty one gets a generated password.
const VALUE: Rule = { ...CreateSecret.SecretString, required: true, format: "jsonish", generate: "password" };

function Create({ names, keys }: { names: string[]; keys: string[] }) {
  return (
    <Sheet title="New secret" label="Create secret" testId="create-secret">
      <ActionForm action={createSecret} submit="Create" testId="create-secret">
        <Field label="Name" rule={NAME} taken={names} unique>
          <input name="name" placeholder="prod/app/db" autoFocus />
        </Field>
        <Field label="Value" rule={VALUE} member="SecretString">
          <textarea name="value" rows={6} placeholder='{"username": "app", "password": "…"}' />
        </Field>
        <Field label="Description" rule={CreateSecret.Description}>
          <input name="description" />
        </Field>
        <Field label="KMS key" rule={CreateSecret.KmsKeyId} known={keys}>
          <input name="kmsKeyId" placeholder="alias/aws/secretsmanager" />
        </Field>
      </ActionForm>
    </Sheet>
  );
}

export default async function Secrets() {
  const [list, keys] = await Promise.all([load(listSecrets), kmsKeys()]);
  // Secrets scheduled for deletion still hold their names.
  const create = <Create names={list.ok ? list.value.map((s) => s.Name!) : []} keys={keys} />;
  if (!list.ok) {
    return (
      <Page title="Secrets" actions={create}>
        <ErrorNotice error={list.error} />
      </Page>
    );
  }
  const items = list.value.map((s) => ({ ...s, name: s.Name!, text: `${s.Name} ${s.Description ?? ""} ${(s.Tags ?? []).map((t) => `${t.Key} ${t.Value}`).join(" ")}` }));
  const grouped = await sections(items, SECRET_KINDS, "Other");
  return (
    <Page title="Secrets" actions={create}>
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
