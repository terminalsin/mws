import { ListFoundationModelsCommand, ListInferenceProfilesCommand, ListModelInvocationJobsCommand } from "@aws-sdk/client-bedrock";
import { ago, all, load } from "@mws-dashboard/aws";
import { bucketOptions, roleOptions } from "@mws-dashboard/aws/auto";
import { ActionForm, AutoPick, Empty, ErrorNotice, Field, List, Page, Section, Sheet, Status } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { CreateModelInvocationJob } from "@mws-dashboard/ui/model/bedrock";
import { ruleAt } from "@mws-dashboard/ui/validation";
import { Layers } from "lucide-react";
import { MoreFields } from "@mws-dashboard/ui/presets";
import type { Metadata } from "next";

import { bedrock, ICONS, tone } from "../../../lib/clients";
import { InferTabs, RUNNING } from "../../../lib/links";
import { createBatchJob } from "../jobs";

export const metadata: Metadata = { title: "Batch inference" };

const at = (p: string) => ruleAt(CreateModelInvocationJob, p);
const NAME = { ...CreateModelInvocationJob.jobName, generate: "name" as const };

export default async function Batch() {
  const client = await bedrock();
  const data = await load(async () => {
    const [jobs, models, profiles] = await Promise.all([
      all((nextToken) => client.send(new ListModelInvocationJobsCommand({ nextToken })), (r) => r.invocationJobSummaries, (r) => r.nextToken),
      client.send(new ListFoundationModelsCommand({ byOutputModality: "TEXT" })).then((r) => (r.modelSummaries ?? []).filter((m) => m.inferenceTypesSupported?.includes("ON_DEMAND"))),
      client.send(new ListInferenceProfilesCommand({ maxResults: 1000 })).then((r) => r.inferenceProfileSummaries ?? [], () => []),
    ]);
    return { jobs, models, profiles };
  });
  if (!data.ok) {
    return (
      <Page title="Batch inference">
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { jobs, models, profiles } = data.value;
  const [roles, buckets] = await Promise.all([roleOptions("bedrock.amazonaws.com"), bucketOptions()]);
  const known = buckets.map((b) => `s3://${b.value}/`);
  const create = (
    <Sheet title="Create batch inference job" label="Create job" testId="create-batch">
      <ActionForm action={createBatchJob} submit="Create job" testId="create-batch">
        <Field label="Job name" rule={NAME} taken={jobs.map((j) => j.jobName!)} unique>
          <input name="jobName" required autoFocus />
        </Field>
        <Field label="Model">
          <select name="model">
            {models.map((m) => (
              <option key={m.modelId} value={m.modelId}>
                {m.providerName} {m.modelName}
              </option>
            ))}
            {profiles.length > 0 && (
              <optgroup label="Inference profiles">
                {profiles.map((p) => (
                  <option key={p.inferenceProfileArn} value={p.type === "APPLICATION" ? p.inferenceProfileArn : p.inferenceProfileId}>
                    {p.inferenceProfileName}
                  </option>
                ))}
              </optgroup>
            )}
          </select>
        </Field>
        <Field label="Input data (JSONL)" rule={{ ...at("inputDataConfig.s3InputDataConfig.s3Uri"), format: "s3url" }} known={known}>
          <input name="input" required placeholder="s3://bucket/input/records.jsonl" />
        </Field>
        <Field label="Output location" rule={{ ...at("outputDataConfig.s3OutputDataConfig.s3Uri"), format: "s3url" }} known={known}>
          <input name="output" required placeholder="s3://bucket/output/" />
        </Field>
        <MoreFields>
        <AutoPick name="role" label="Service role" creates="AmazonBedrockBatchInferenceRole" options={roles} testId="batch-role" />
        <Field label="Timeout (hours)" rule={at("timeoutDurationInHours")}>
          <input name="timeout" type="number" placeholder="24" />
        </Field>
        <Field label="Tags" format="tags">
          <textarea name="tags" rows={2} placeholder="team=ml" />
        </Field>
        </MoreFields>
      </ActionForm>
    </Sheet>
  );
  return (
    <Page title="Batch inference" actions={create}>
      <LiveRefresh when={jobs.some((j) => RUNNING.test(j.status ?? ""))} />
      <InferTabs active="batch" />
      <Section plain>
        <List
          label="Batch inference jobs"
          empty={<Empty icon={ICONS.bedrock} action={create} />}
          rows={jobs.map((j) => ({
            key: j.jobArn!,
            icon: <Layers size={18} />,
            title: j.jobName,
            subtitle: <code>{j.modelId?.split("/").pop()}</code>,
            href: `/bedrock/batch-job?arn=${encodeURIComponent(j.jobArn!)}`,
            meta: (
              <>
                {j.totalRecordCount != null && (
                  <span title="Succeeded / total records">
                    {j.successRecordCount ?? 0}/{j.totalRecordCount}
                  </span>
                )}
                <Status tone={tone(j.status)}>{j.status ?? ""}</Status>
                <span>{ago(j.submitTime)}</span>
              </>
            ),
          }))}
        />
      </Section>
    </Page>
  );
}
