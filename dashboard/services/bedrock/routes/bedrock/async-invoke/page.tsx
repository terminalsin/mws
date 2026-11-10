import { GetAsyncInvokeCommand } from "@aws-sdk/client-bedrock-runtime";
import { ago, load, when } from "@mws-dashboard/aws";
import { ErrorNotice, Facts, Page, Section, Specs, Status } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { Clock, Send, Timer } from "lucide-react";
import type { Metadata } from "next";

import { bedrockRuntime, ICONS, tone } from "../../../lib/clients";
import { KmsLink, ModelRef, RUNNING, S3Link } from "../../../lib/links";

export const metadata: Metadata = { title: "Async invocation" };

type Props = { searchParams: Promise<{ arn?: string }> };

export default async function AsyncInvoke({ searchParams }: Props) {
  const arn = (await searchParams).arn ?? "";
  const back = { href: "/bedrock/async", label: "Async invocations" };
  const data = await load(async () => (await bedrockRuntime()).send(new GetAsyncInvokeCommand({ invocationArn: arn })));
  if (!data.ok) {
    return (
      <Page title={arn.split("/").pop()} icon={ICONS.bedrock} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const i = data.value;
  const out = i.outputDataConfig?.s3OutputDataConfig;
  const seconds = i.endTime && i.submitTime ? Math.round((i.endTime.getTime() - i.submitTime.getTime()) / 1000) : undefined;
  return (
    <Page title={i.invocationArn?.split("/").pop()} icon={ICONS.bedrock} back={back} subtitle={i.invocationArn}>
      <LiveRefresh when={RUNNING.test(i.status ?? "")} />
      <Specs
        items={[
          { label: "Status", icon: <Send size={15} />, value: <Status tone={tone(i.status)}>{i.status ?? ""}</Status> },
          { label: "Submitted", icon: <Clock size={15} />, value: ago(i.submitTime) },
          seconds != null && { label: "Duration", icon: <Timer size={15} />, value: `${seconds}s` },
        ]}
      />
      {i.failureMessage && <ErrorNotice error={i.failureMessage} />}
      <Section title="Details">
        <Facts
          items={[
            ["Model", <ModelRef key="m" arn={i.modelArn} />],
            ["Output", <S3Link key="o" uri={out?.s3Uri?.replace(/\/?$/, "/")} />],
            out?.kmsKeyId && ["KMS key", <KmsLink key="k" arn={out.kmsKeyId} />],
            out?.bucketOwner && ["Bucket owner", out.bucketOwner],
            i.clientRequestToken && ["Client token", <code key="t">{i.clientRequestToken}</code>],
            ["Submitted", when(i.submitTime)],
            i.endTime && ["Ended", when(i.endTime)],
          ]}
        />
      </Section>
    </Page>
  );
}
