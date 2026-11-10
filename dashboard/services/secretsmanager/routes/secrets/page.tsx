import { sections } from "@mws-dashboard/ai";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Page, Pill, Sheet } from "@mws-dashboard/ui";
import { RotateCw } from "lucide-react";
import type { Metadata } from "next";

import { ICONS } from "../../lib/clients";
import { kmsKeys } from "../../lib/known";
import { secretLogo } from "../../lib/presets";
import { SecretFields } from "../../lib/secret-fields";
import { SECRET_KINDS, listSecrets } from "../../lib/secrets";
import { createSecret } from "./actions";

export const metadata: Metadata = { title: "Secrets Manager" };

function Create({ names, keys }: { names: string[]; keys: string[] }) {
  return (
    <Sheet title="New secret" label="Create secret" testId="create-secret">
      <ActionForm action={createSecret} submit="Create" testId="create-secret">
        <SecretFields names={names} keys={keys} />
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
          icon: <AwsIcon icon={secretLogo(s.Name!) ?? ICONS.secrets} size={24} />,
          title: s.Name,
          subtitle: s.Description,
          href: `/secrets/secret?id=${encodeURIComponent(s.ARN!)}`,
          meta: s.DeletedDate ? (
            <Pill tone="bad">deletes {ago(s.DeletedDate)}</Pill>
          ) : (
            <>
              {s.RotationEnabled && <RotateCw size={14} aria-label="Rotates" />}
              {s.PrimaryRegion && s.ARN?.split(":")[3] !== s.PrimaryRegion && <Pill>replica</Pill>}
              <span>{ago(s.LastChangedDate ?? s.CreatedDate)}</span>
            </>
          ),
        })}
      />
    </Page>
  );
}
