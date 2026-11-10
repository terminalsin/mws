import { ListCustomModelsCommand, ListFoundationModelsCommand, ListProvisionedModelThroughputsCommand } from "@aws-sdk/client-bedrock";
import { ago, all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Section, Sheet, Status } from "@mws-dashboard/ui";
import { CreateProvisionedModelThroughput } from "@mws-dashboard/ui/model/bedrock";
import { Gauge } from "lucide-react";
import { MoreFields } from "@mws-dashboard/ui/presets";
import type { Metadata } from "next";

import { bedrock, ICONS, providerIcon, tone } from "../../../lib/clients";
import { InferTabs } from "../../../lib/links";
import { createProvisioned } from "../jobs";

export const metadata: Metadata = { title: "Provisioned Throughput" };

type Props = { searchParams: Promise<{ model?: string }> };

const NAME = { ...CreateProvisionedModelThroughput.provisionedModelName, generate: "name" as const, hint: "Letters and digits, single - or _ between them" };
const COMMITMENT: Record<string, string> = { "": "No commitment", OneMonth: "1 month", SixMonths: "6 months" };

export default async function Provisioned({ searchParams }: Props) {
  const { model } = await searchParams;
  const client = await bedrock();
  const data = await load(async () => {
    const [pts, foundation, custom] = await Promise.all([
      all((nextToken) => client.send(new ListProvisionedModelThroughputsCommand({ nextToken })), (r) => r.provisionedModelSummaries, (r) => r.nextToken),
      client.send(new ListFoundationModelsCommand({ byInferenceType: "PROVISIONED" })).then((r) => r.modelSummaries ?? []),
      all((nextToken) => client.send(new ListCustomModelsCommand({ nextToken })), (r) => r.modelSummaries, (r) => r.nextToken).catch(() => []),
    ]);
    return { pts, foundation, custom: custom.filter((m) => !m.modelStatus || m.modelStatus === "Active") };
  });
  if (!data.ok) {
    return (
      <Page title="Provisioned Throughput">
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { pts, foundation, custom } = data.value;
  const create = (
    <Sheet title="Purchase Provisioned Throughput" label="Purchase Provisioned Throughput" testId="create-provisioned">
      <ActionForm action={createProvisioned} submit="Purchase" testId="create-provisioned">
        <Field label="Name" rule={NAME} taken={pts.map((p) => p.provisionedModelName!)} unique>
          <input name="name" required autoFocus />
        </Field>
        <Field label="Model">
          <select name="model" defaultValue={model}>
            {custom.length > 0 && (
              <optgroup label="Custom models">
                {custom.map((m) => (
                  <option key={m.modelArn} value={m.modelArn}>
                    {m.modelName}
                  </option>
                ))}
              </optgroup>
            )}
            <optgroup label="Foundation models">
              {foundation.map((m) => (
                <option key={m.modelId} value={m.modelArn}>
                  {m.providerName} {m.modelName}
                </option>
              ))}
            </optgroup>
          </select>
        </Field>
        <div className="form-row">
          <Field label="Model units" rule={CreateProvisionedModelThroughput.modelUnits}>
            <input name="units" type="number" min={1} defaultValue={1} required />
          </Field>
        </div>
        <MoreFields>
        <Field label="Commitment term">
          <select name="commitment" defaultValue="">
            {Object.entries(COMMITMENT).map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Tags" format="tags">
          <textarea name="tags" rows={2} placeholder="team=ml" />
        </Field>
        </MoreFields>
      </ActionForm>
    </Sheet>
  );
  return (
    <Page title="Provisioned Throughput" actions={create}>
      <InferTabs active="provisioned" />
      <Section plain>
        <List
          label="Provisioned Throughput"
          empty={<Empty icon={ICONS.bedrock} action={create} />}
          rows={pts.map((p) => {
            const base = foundation.find((m) => m.modelArn === p.foundationModelArn);
            return {
              key: p.provisionedModelArn!,
              icon: <AwsIcon icon={providerIcon(base?.providerName) ?? ICONS.model} size={22} />,
              title: p.provisionedModelName,
              subtitle: <code>{p.modelArn?.includes(":custom-model/") ? p.modelArn.split("/").slice(1, 2).join("") + " (custom)" : p.modelArn?.split("/").pop()}</code>,
              href: `/bedrock/provisioned-model?arn=${encodeURIComponent(p.provisionedModelArn!)}`,
              meta: (
                <>
                  <Pill icon={<Gauge size={11} />} title="Model units">
                    {p.modelUnits}
                  </Pill>
                  {p.commitmentDuration && <Pill>{COMMITMENT[p.commitmentDuration]}</Pill>}
                  <Status tone={tone(p.status)}>{p.status ?? ""}</Status>
                  <span>{ago(p.creationTime)}</span>
                </>
              ),
            };
          })}
        />
      </Section>
    </Page>
  );
}
