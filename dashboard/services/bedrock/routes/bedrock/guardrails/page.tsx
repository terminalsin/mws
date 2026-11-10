import { ListGuardrailsCommand } from "@aws-sdk/client-bedrock";
import { ago, all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, List, Page, Sheet, Status } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { bedrock, ICONS, tone } from "../../../lib/clients";
import { GuardrailFields } from "../../../lib/guardrail-form";
import { createGuardrail } from "../actions";

export const metadata: Metadata = { title: "Guardrails" };

export default async function Guardrails() {
  const guardrails = await load(async () => {
    const client = await bedrock();
    return all((nextToken) => client.send(new ListGuardrailsCommand({ nextToken })), (r) => r.guardrails, (r) => r.nextToken);
  });
  const names = guardrails.ok ? guardrails.value.map((g) => g.name!) : [];
  const create = (
    <Sheet title="Create guardrail" label="Create guardrail" testId="create-guardrail">
      <ActionForm action={createGuardrail} submit="Create guardrail" testId="create-guardrail">
        <GuardrailFields taken={names} />
      </ActionForm>
    </Sheet>
  );
  return (
    <Page title="Guardrails" actions={create}>
      {guardrails.ok ? (
        <List
          label="Guardrails"
          empty={<Empty icon={ICONS.bedrock} action={create} />}
          rows={guardrails.value.map((g) => ({
            key: g.id!,
            icon: <AwsIcon icon={ICONS.guardrail} size={22} />,
            title: g.name,
            subtitle: g.description,
            href: `/bedrock/guardrail?id=${g.id}`,
            meta: (
              <>
                {g.status !== "READY" && <Status tone={tone(g.status)}>{g.status?.toLowerCase()}</Status>}
                <span>{ago(g.updatedAt)}</span>
              </>
            ),
          }))}
        />
      ) : (
        <ErrorNotice error={guardrails.error} />
      )}
    </Page>
  );
}
