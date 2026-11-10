import { ListFoundationModelsCommand } from "@aws-sdk/client-bedrock";
import { ListAsyncInvokesCommand } from "@aws-sdk/client-bedrock-runtime";
import { ago, all, load } from "@mws-dashboard/aws";
import { bucketOptions } from "@mws-dashboard/aws/auto";
import { ActionForm, Empty, ErrorNotice, Field, List, Page, Section, Sheet, Status } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { StartAsyncInvoke } from "@mws-dashboard/ui/model/bedrock-runtime";
import { ruleAt } from "@mws-dashboard/ui/validation";
import { Send } from "lucide-react";
import type { Metadata } from "next";

import { bedrock, bedrockRuntime, ICONS, tone } from "../../../lib/clients";
import { InferTabs, RUNNING } from "../../../lib/links";
import { startAsyncInvoke } from "../jobs";

export const metadata: Metadata = { title: "Async invocations" };

const OUTPUT = { ...ruleAt(StartAsyncInvoke, "outputDataConfig.s3OutputDataConfig.s3Uri"), format: "s3url" as const };

// A request body that works for the video model, the usual async target.
const SAMPLE = JSON.stringify({ taskType: "TEXT_VIDEO", textToVideoParams: { text: "A lighthouse at dawn" }, videoGenerationConfig: { durationSeconds: 6, fps: 24, dimension: "1280x720" } }, null, 2);

export default async function AsyncInvokes() {
  const data = await load(async () => {
    const runtime = await bedrockRuntime();
    const [invokes, models] = await Promise.all([
      all((nextToken) => runtime.send(new ListAsyncInvokesCommand({ nextToken, sortBy: "SubmissionTime", sortOrder: "Descending" })), (r) => r.asyncInvokeSummaries, (r) => r.nextToken),
      (await bedrock()).send(new ListFoundationModelsCommand({})).then((r) => (r.modelSummaries ?? []).filter((m) => m.inferenceTypesSupported?.includes("ON_DEMAND"))),
    ]);
    return { invokes, models };
  });
  if (!data.ok) {
    return (
      <Page title="Async invocations">
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { invokes, models } = data.value;
  const buckets = await bucketOptions();
  const video = models.find((m) => (m.outputModalities as string[] | undefined)?.includes("VIDEO"));
  const start = (
    <Sheet title="Start async invocation" label="Start invocation" icon={<Send size={15} />} testId="start-async">
      <ActionForm action={startAsyncInvoke} submit="Start" testId="start-async">
        <Field label="Model" rule={StartAsyncInvoke.modelId}>
          <select name="model" defaultValue={video?.modelId}>
            {models.map((m) => (
              <option key={m.modelId} value={m.modelId}>
                {m.providerName} {m.modelName}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Model input" format="json">
          <textarea name="input" rows={8} defaultValue={SAMPLE} required />
        </Field>
        <Field label="Output location" rule={OUTPUT} known={buckets.map((b) => `s3://${b.value}/`)}>
          <input name="output" required placeholder="s3://bucket/async/" />
        </Field>
        <Field label="Tags" format="tags">
          <textarea name="tags" rows={2} placeholder="team=ml" />
        </Field>
      </ActionForm>
    </Sheet>
  );
  return (
    <Page title="Async invocations" actions={start}>
      <LiveRefresh when={invokes.some((i) => RUNNING.test(i.status ?? ""))} />
      <InferTabs active="async" />
      <Section plain>
        <List
          label="Async invocations"
          empty={<Empty icon={ICONS.bedrock} action={start} />}
          rows={invokes.map((i) => ({
            key: i.invocationArn!,
            icon: <Send size={18} />,
            title: i.invocationArn?.split("/").pop(),
            subtitle: <code>{i.modelArn?.split("/").pop()}</code>,
            href: `/bedrock/async-invoke?arn=${encodeURIComponent(i.invocationArn!)}`,
            meta: (
              <>
                <Status tone={tone(i.status)}>{i.status ?? ""}</Status>
                <span>{ago(i.submitTime)}</span>
              </>
            ),
          }))}
        />
      </Section>
    </Page>
  );
}
