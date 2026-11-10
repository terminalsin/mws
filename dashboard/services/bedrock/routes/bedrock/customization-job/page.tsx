import { GetModelCustomizationJobCommand } from "@aws-sdk/client-bedrock";
import { ago, load, when } from "@mws-dashboard/aws";
import { ActionForm, ErrorNotice, Facts, Page, Section, Specs, Status } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { Clock, FlaskConical, Square, Timer } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import type { ReactNode } from "react";

import { bedrock, ICONS, tone } from "../../../lib/clients";
import { KmsLink, ModelRef, RoleLink, RUNNING, S3Link, TYPE_LABEL } from "../../../lib/links";
import { TagsSection } from "../../../lib/tags";
import { stopCustomizationJob } from "../jobs";

export const metadata: Metadata = { title: "Training job" };

type Props = { searchParams: Promise<{ arn?: string }> };

function duration(start?: Date, end?: Date) {
  if (!start || !end) return undefined;
  const s = Math.round((end.getTime() - start.getTime()) / 1000);
  return s < 120 ? `${s}s` : `${Math.round(s / 60)}m`;
}

export default async function CustomizationJob({ searchParams }: Props) {
  const arn = (await searchParams).arn ?? "";
  const back = { href: "/bedrock/custom-models?tab=jobs", label: "Training jobs" };
  const data = await load(async () => (await bedrock()).send(new GetModelCustomizationJobCommand({ jobIdentifier: arn })));
  if (!data.ok) {
    return (
      <Page title={arn.split("/").pop()} icon={ICONS.model} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const j = data.value;
  const running = RUNNING.test(j.status ?? "");
  const hyper = Object.entries(j.hyperParameters ?? {});
  const stages = [
    ["Validation", j.statusDetails?.validationDetails],
    ["Data processing", j.statusDetails?.dataProcessingDetails],
    ["Training", j.statusDetails?.trainingDetails],
  ].filter(([, d]) => d) as [string, { status?: string; creationTime?: Date; lastModifiedTime?: Date }][];
  return (
    <Page
      title={j.jobName}
      icon={ICONS.model}
      back={back}
      subtitle={j.jobArn}
      actions={
        j.status === "InProgress" ? (
          <ActionForm action={stopCustomizationJob.bind(null, j.jobArn!)} submit="Stop job" icon={<Square size={16} />} tone="danger" confirm={`Stop ${j.jobName}?`} testId="stop-customization" />
        ) : undefined
      }
    >
      <LiveRefresh when={running} />
      <Specs
        items={[
          { label: "Status", icon: <FlaskConical size={15} />, value: <Status tone={tone(j.status)}>{j.status ?? ""}</Status> },
          j.customizationType && { label: "Customization", icon: <FlaskConical size={15} />, value: TYPE_LABEL[j.customizationType] ?? j.customizationType },
          { label: "Created", icon: <Clock size={15} />, value: ago(j.creationTime) },
          duration(j.creationTime, j.endTime) && { label: "Duration", icon: <Timer size={15} />, value: duration(j.creationTime, j.endTime) },
        ]}
      />
      {j.failureMessage && <ErrorNotice error={j.failureMessage} />}
      {stages.length > 0 && (
        <Section title="Progress">
          <Facts items={stages.map(([label, d]) => [label, <Status key={label} tone={tone(d.status)}>{d.status ?? ""}</Status>])} />
        </Section>
      )}
      <Section title="Details">
        <Facts
          items={[
            ["Base model", <ModelRef key="b" arn={j.baseModelArn} />],
            [
              "Custom model",
              j.outputModelArn ? (
                <Link key="m" href={`/bedrock/custom-model?arn=${encodeURIComponent(j.outputModelArn)}`}>
                  {j.outputModelName}
                </Link>
              ) : (
                j.outputModelName
              ),
            ],
            ["Service role", <RoleLink key="r" arn={j.roleArn} />],
            ["Training data", <S3Link key="t" uri={j.trainingDataConfig?.s3Uri} />],
            ...(j.validationDataConfig?.validators ?? []).map((v, i) => ["Validation data", <S3Link key={`v${i}`} uri={v.s3Uri} />] as [string, ReactNode]),
            ["Output", <S3Link key="o" uri={j.outputDataConfig?.s3Uri} />],
            j.outputModelKmsKeyArn && ["KMS key", <KmsLink key="k" arn={j.outputModelKmsKeyArn} />],
            j.trainingMetrics?.trainingLoss != null && ["Training loss", j.trainingMetrics.trainingLoss],
            ["Created", when(j.creationTime)],
            j.endTime && ["Ended", when(j.endTime)],
          ]}
        />
      </Section>
      {hyper.length > 0 && (
        <Section title="Hyperparameters">
          <Facts items={hyper.map(([k, v]) => [k, <code key={k}>{v}</code>])} />
        </Section>
      )}
      <TagsSection arn={j.jobArn!} path="/bedrock/customization-job" />
    </Page>
  );
}
