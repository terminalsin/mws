import { GetModelInvocationJobCommand } from "@aws-sdk/client-bedrock";
import { ago, load, when } from "@mws-dashboard/aws";
import { ActionForm, ErrorNotice, Facts, Metric, Metrics, Page, Section, Specs, Status } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { Clock, Hourglass, Layers, Square } from "lucide-react";
import type { Metadata } from "next";

import { bedrock, ICONS, tone } from "../../../lib/clients";
import { ModelRef, RoleLink, RUNNING, S3Link } from "../../../lib/links";
import { TagsSection } from "../../../lib/tags";
import { stopBatchJob } from "../jobs";

export const metadata: Metadata = { title: "Batch inference job" };

type Props = { searchParams: Promise<{ arn?: string }> };

export default async function BatchJob({ searchParams }: Props) {
  const arn = (await searchParams).arn ?? "";
  const back = { href: "/bedrock/batch", label: "Batch inference" };
  const data = await load(async () => (await bedrock()).send(new GetModelInvocationJobCommand({ jobIdentifier: arn })));
  if (!data.ok) {
    return (
      <Page title={arn.split("/").pop()} icon={ICONS.bedrock} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const j = data.value;
  const running = RUNNING.test(j.status ?? "");
  const outUri = j.outputDataConfig?.s3OutputDataConfig?.s3Uri;
  const jobId = j.jobArn?.split("/").pop();
  return (
    <Page
      title={j.jobName}
      icon={ICONS.bedrock}
      back={back}
      subtitle={j.jobArn}
      actions={
        running ? <ActionForm action={stopBatchJob.bind(null, j.jobArn!)} submit="Stop job" icon={<Square size={16} />} tone="danger" confirm={`Stop ${j.jobName}?`} testId="stop-batch" /> : undefined
      }
    >
      <LiveRefresh when={running} />
      <Specs
        items={[
          { label: "Status", icon: <Layers size={15} />, value: <Status tone={tone(j.status)}>{j.status ?? ""}</Status> },
          { label: "Submitted", icon: <Clock size={15} />, value: ago(j.submitTime) },
          j.jobExpirationTime && running && { label: "Expires", icon: <Hourglass size={15} />, value: ago(j.jobExpirationTime) },
        ]}
      />
      {j.message && (j.status === "Failed" || j.status === "PartiallyCompleted") && <ErrorNotice error={j.message} />}
      {j.totalRecordCount != null && (
        <Metrics>
          <Metric label="Records" value={j.totalRecordCount} />
          <Metric label="Processed" value={j.processedRecordCount ?? 0} />
          <Metric label="Succeeded" value={j.successRecordCount ?? 0} tone="good" />
          <Metric label="Errors" value={j.errorRecordCount ?? 0} tone={j.errorRecordCount ? "bad" : undefined} />
        </Metrics>
      )}
      <Section title="Details">
        <Facts
          items={[
            ["Model", <ModelRef key="m" arn={j.modelId} />],
            ["Service role", <RoleLink key="r" arn={j.roleArn} />],
            ["Input", <S3Link key="i" uri={j.inputDataConfig?.s3InputDataConfig?.s3Uri} />],
            ["Output", <S3Link key="o" uri={outUri && jobId ? `${outUri.replace(/\/?$/, "/")}${jobId}/` : outUri} />],
            j.timeoutDurationInHours && ["Timeout", `${j.timeoutDurationInHours} h`],
            j.message && j.status !== "Failed" && j.status !== "PartiallyCompleted" && ["Message", j.message],
            ["Submitted", when(j.submitTime)],
            j.endTime && ["Ended", when(j.endTime)],
          ]}
        />
      </Section>
      <TagsSection arn={j.jobArn!} path="/bedrock/batch-job" />
    </Page>
  );
}
