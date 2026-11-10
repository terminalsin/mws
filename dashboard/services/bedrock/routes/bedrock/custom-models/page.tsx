import { ListCustomModelsCommand, ListFoundationModelsCommand, ListModelCustomizationJobsCommand } from "@aws-sdk/client-bedrock";
import { ago, all, load } from "@mws-dashboard/aws";
import { bucketOptions, roleOptions } from "@mws-dashboard/aws/auto";
import { ActionForm, AutoPick, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Section, Segments, Sheet, Status } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { CreateModelCustomizationJob } from "@mws-dashboard/ui/model/bedrock";
import { ruleAt } from "@mws-dashboard/ui/validation";
import { FlaskConical } from "lucide-react";
import type { Metadata } from "next";

import { bedrock, ICONS, providerIcon, tone } from "../../../lib/clients";
import { RUNNING, TYPE_LABEL } from "../../../lib/links";
import { createCustomizationJob } from "../jobs";

export const metadata: Metadata = { title: "Custom models" };

type Props = { searchParams: Promise<{ tab?: string }> };

const at = (p: string) => ruleAt(CreateModelCustomizationJob, p);
const JOB_NAME = { ...CreateModelCustomizationJob.jobName, generate: "name" as const };
const MODEL_NAME = { ...CreateModelCustomizationJob.customModelName, generate: "name" as const, hint: "Letters and digits, single - or _ between them" };
const S3 = (p: string, required = true) => ({ ...at(p), format: "s3url" as const, required });


export default async function CustomModels({ searchParams }: Props) {
  const { tab = "models" } = await searchParams;
  const client = await bedrock();
  const data = await load(async () => {
    const [models, jobs, bases] = await Promise.all([
      all((nextToken) => client.send(new ListCustomModelsCommand({ nextToken })), (r) => r.modelSummaries, (r) => r.nextToken),
      all((nextToken) => client.send(new ListModelCustomizationJobsCommand({ nextToken })), (r) => r.modelCustomizationJobSummaries, (r) => r.nextToken),
      client.send(new ListFoundationModelsCommand({})).then((r) => (r.modelSummaries ?? []).filter((m) => m.customizationsSupported?.length)),
    ]);
    return { models, jobs, bases };
  });
  if (!data.ok) {
    return (
      <Page title="Custom models">
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { models, jobs, bases } = data.value;
  const [roles, buckets] = await Promise.all([roleOptions("bedrock.amazonaws.com"), bucketOptions()]);
  const known = buckets.map((b) => `s3://${b.value}/`);
  const types = [...new Set(bases.flatMap((m) => m.customizationsSupported ?? []))];
  const create = (
    <Sheet title="Customize model" label="Customize model" icon={<FlaskConical size={16} />} testId="create-customization">
      <ActionForm action={createCustomizationJob} submit="Create job" testId="create-customization">
        <div className="form-row">
          <Field label="Job name" rule={JOB_NAME} taken={jobs.map((j) => j.jobName!)} unique>
            <input name="jobName" required autoFocus />
          </Field>
          <Field label="Model name" rule={MODEL_NAME} taken={models.map((m) => m.modelName!)}>
            <input name="modelName" required />
          </Field>
        </div>
        <div className="form-row">
          <Field label="Base model">
            <select name="base" required>
              {bases.map((m) => (
                <option key={m.modelId} value={m.modelId}>
                  {m.providerName} {m.modelName} ({(m.customizationsSupported ?? []).map((c) => TYPE_LABEL[c] ?? c).join(", ")})
                </option>
              ))}
            </select>
          </Field>
          <Field label="Customization" rule={at("customizationType")}>
            <select name="type" defaultValue="FINE_TUNING">
              {types.map((t) => (
                <option key={t} value={t}>
                  {TYPE_LABEL[t] ?? t}
                </option>
              ))}
            </select>
          </Field>
        </div>
        <Field label="Training data" rule={S3("trainingDataConfig.s3Uri")} known={known}>
          <input name="training" required placeholder="s3://bucket/train.jsonl" />
        </Field>
        <Field label="Validation data" rule={S3("validationDataConfig.validators.s3Uri", false)} known={known}>
          <input name="validation" placeholder="s3://bucket/validation.jsonl" />
        </Field>
        <Field label="Output location" rule={S3("outputDataConfig.s3Uri")} known={known}>
          <input name="output" required placeholder="s3://bucket/output/" />
        </Field>
        <Field label="Hyperparameters" format="pairs">
          <textarea name="hyper" rows={3} defaultValue={"epochCount=2\nbatchSize=1\nlearningRate=0.00001"} />
        </Field>
        <AutoPick name="role" label="Service role" creates="AmazonBedrockCustomizationRole" options={roles} testId="customization-role" />
        <Field label="Model KMS key" rule={{ ...at("customModelKmsKeyId"), required: false }}>
          <input name="kms" placeholder="alias/my-key" />
        </Field>
        <Field label="Model tags" format="tags">
          <textarea name="tags" rows={2} placeholder="team=ml" />
        </Field>
      </ActionForm>
    </Sheet>
  );
  const running = jobs.some((j) => RUNNING.test(j.status ?? "")) || models.some((m) => RUNNING.test(m.modelStatus ?? ""));
  return (
    <Page title="Custom models" actions={create}>
      <LiveRefresh when={running} />
      <Segments
        items={[
          { label: "Models", href: "/bedrock/custom-models", active: tab !== "jobs", count: models.length },
          { label: "Training jobs", href: "/bedrock/custom-models?tab=jobs", active: tab === "jobs", count: jobs.length },
        ]}
      />
      <Section plain>
        {tab === "jobs" ? (
          <List
            label="Training jobs"
            empty={<Empty icon={ICONS.bedrock} action={create} />}
            rows={jobs.map((j) => ({
              key: j.jobArn!,
              icon: <FlaskConical size={18} />,
              title: j.jobName,
              subtitle: <code>{j.baseModelArn?.split("/").pop()}</code>,
              href: `/bedrock/customization-job?arn=${encodeURIComponent(j.jobArn!)}`,
              meta: (
                <>
                  {j.customizationType && <Pill>{TYPE_LABEL[j.customizationType] ?? j.customizationType}</Pill>}
                  <Status tone={tone(j.status)}>{j.status ?? ""}</Status>
                  <span>{ago(j.creationTime)}</span>
                </>
              ),
            }))}
          />
        ) : (
          <List
            label="Custom models"
            empty={<Empty icon={ICONS.bedrock} action={create} />}
            rows={models.map((m) => ({
              key: m.modelArn!,
              icon: <AwsIcon icon={providerIcon(m.baseModelName) ?? ICONS.model} size={22} />,
              title: m.modelName,
              subtitle: <code>{m.baseModelArn?.split("/").pop()}</code>,
              href: `/bedrock/custom-model?arn=${encodeURIComponent(m.modelArn!)}`,
              meta: (
                <>
                  {m.customizationType && <Pill>{TYPE_LABEL[m.customizationType] ?? m.customizationType}</Pill>}
                  {m.modelStatus && m.modelStatus !== "Active" && <Status tone={tone(m.modelStatus)}>{m.modelStatus}</Status>}
                  <span>{ago(m.creationTime)}</span>
                </>
              ),
            }))}
          />
        )}
      </Section>
    </Page>
  );
}
