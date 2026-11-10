import { GetProvisionedModelThroughputCommand, ListCustomModelsCommand } from "@aws-sdk/client-bedrock";
import { ago, all, load, when } from "@mws-dashboard/aws";
import { ActionForm, ErrorNotice, Facts, Field, Page, Section, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { UpdateProvisionedModelThroughput } from "@mws-dashboard/ui/model/bedrock";
import { CalendarClock, Clock, Gauge, MessageSquareText, Pencil, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { bedrock, ICONS, tone } from "../../../lib/clients";
import { ModelRef } from "../../../lib/links";
import { TagsSection } from "../../../lib/tags";
import { deleteProvisioned, updateProvisioned } from "../jobs";

export const metadata: Metadata = { title: "Provisioned Throughput" };

type Props = { searchParams: Promise<{ arn?: string }> };

const COMMITMENT: Record<string, string> = { OneMonth: "1 month", SixMonths: "6 months" };

export default async function ProvisionedModel({ searchParams }: Props) {
  const arn = (await searchParams).arn ?? "";
  const back = { href: "/bedrock/provisioned", label: "Provisioned Throughput" };
  const client = await bedrock();
  const data = await load(async () => client.send(new GetProvisionedModelThroughputCommand({ provisionedModelId: arn })));
  if (!data.ok) {
    return (
      <Page title={arn.split("/").pop()} icon={ICONS.model} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const p = data.value;
  // A custom model can be swapped for another customized from the same base.
  const siblings = await all((nextToken) => client.send(new ListCustomModelsCommand({ nextToken, baseModelArnEquals: p.foundationModelArn })), (r) => r.modelSummaries, (r) => r.nextToken).catch(() => []);
  const inService = p.status === "InService";
  return (
    <Page
      title={p.provisionedModelName}
      icon={ICONS.model}
      back={back}
      subtitle={p.provisionedModelArn}
      actions={
        <>
          {inService && (
            <Link className="icon-button plain" href={`/bedrock/playground?model=${encodeURIComponent(p.provisionedModelArn!)}`} aria-label="Open in playground" title="Playground">
              <MessageSquareText size={16} />
            </Link>
          )}
          {inService && (
            <Sheet title="Edit Provisioned Throughput" label="Edit" icon={<Pencil size={15} />} testId="edit-provisioned">
              <ActionForm action={updateProvisioned.bind(null, p.provisionedModelArn!, { name: p.provisionedModelName!, model: p.modelArn! })} submit="Save" testId="edit-provisioned">
                <Field label="Name" rule={UpdateProvisionedModelThroughput.desiredProvisionedModelName}>
                  <input name="name" defaultValue={p.provisionedModelName} required />
                </Field>
                {p.modelArn?.includes(":custom-model/") && siblings.length > 1 && (
                  <Field label="Model">
                    <select name="model" defaultValue={p.modelArn}>
                      {siblings.map((m) => (
                        <option key={m.modelArn} value={m.modelArn}>
                          {m.modelName}
                        </option>
                      ))}
                    </select>
                  </Field>
                )}
              </ActionForm>
            </Sheet>
          )}
          <ActionForm action={deleteProvisioned.bind(null, p.provisionedModelArn!)} submit="Delete" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${p.provisionedModelName}?`} />
        </>
      }
    >
      <Specs
        items={[
          { label: "Status", icon: <Gauge size={15} />, value: <Status tone={tone(p.status)}>{p.status ?? ""}</Status> },
          { label: "Model units", icon: <Gauge size={15} />, value: p.desiredModelUnits !== p.modelUnits ? `${p.modelUnits} → ${p.desiredModelUnits}` : p.modelUnits },
          p.commitmentDuration && { label: "Commitment", icon: <CalendarClock size={15} />, value: `${COMMITMENT[p.commitmentDuration] ?? p.commitmentDuration}, until ${when(p.commitmentExpirationTime).slice(0, 10)}` },
          { label: "Created", icon: <Clock size={15} />, value: ago(p.creationTime) },
        ]}
      />
      {p.failureMessage && <ErrorNotice error={p.failureMessage} />}
      <Section title="Details">
        <Facts
          items={[
            ["Model", <ModelRef key="m" arn={p.modelArn} />],
            p.desiredModelArn !== p.modelArn && ["Desired model", <ModelRef key="d" arn={p.desiredModelArn} />],
            p.foundationModelArn !== p.modelArn && ["Base model", <ModelRef key="f" arn={p.foundationModelArn} />],
            ["Updated", when(p.lastModifiedTime)],
          ]}
        />
      </Section>
      <TagsSection arn={p.provisionedModelArn!} path="/bedrock/provisioned-model" />
    </Page>
  );
}
