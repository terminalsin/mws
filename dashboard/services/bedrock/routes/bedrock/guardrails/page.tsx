import { ListGuardrailsCommand } from "@aws-sdk/client-bedrock";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Sheet, Status } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { bedrock, ICONS, tone } from "../../../lib/clients";
import { createGuardrail } from "../actions";

export const metadata: Metadata = { title: "Guardrails" };

const PII = ["EMAIL", "PHONE", "NAME", "ADDRESS", "US_SOCIAL_SECURITY_NUMBER", "CREDIT_DEBIT_CARD_NUMBER", "AWS_ACCESS_KEY", "IP_ADDRESS"];

export default async function Guardrails() {
  const guardrails = await load(async () => ((await (await bedrock()).send(new ListGuardrailsCommand({}))).guardrails ?? []));
  const create = (
    <Sheet title="Create guardrail" label="Create guardrail" testId="create-guardrail">
      <ActionForm action={createGuardrail} submit="Create guardrail" testId="create-guardrail">
        <Field label="Name">
          <input name="name" required autoFocus pattern="[0-9a-zA-Z_-]+" />
        </Field>
        <Field label="Content filters">
          <select name="strength" defaultValue="MEDIUM">
            <option value="NONE">Off</option>
            <option value="LOW">Low</option>
            <option value="MEDIUM">Medium</option>
            <option value="HIGH">High</option>
          </select>
        </Field>
        <Field label="Denied topics">
          <textarea name="topics" rows={2} placeholder="Investment advice: recommendations about stocks or funds" />
        </Field>
        <Field label="Blocked words">
          <input name="words" placeholder="comma separated" />
        </Field>
        <label className="check">
          <input type="checkbox" name="profanity" /> Profanity
        </label>
        <fieldset className="checks">
          <legend>Mask personal data</legend>
          {PII.map((p) => (
            <label key={p} className="check">
              <input type="checkbox" name="pii" value={p} /> {p.toLowerCase().replace(/_/g, " ").replace("us ", "US ").replace("aws", "AWS").replace("ip ", "IP ")}
            </label>
          ))}
        </fieldset>
        <Field label="Blocked message">
          <input name="blocked" placeholder="Sorry, I can't help with that." />
        </Field>
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
                {g.version && g.version !== "DRAFT" && <Pill>v{g.version}</Pill>}
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
