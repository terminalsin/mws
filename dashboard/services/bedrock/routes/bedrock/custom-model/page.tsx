import { GetCustomModelCommand } from "@aws-sdk/client-bedrock";
import { ago, load, when } from "@mws-dashboard/aws";
import { ActionForm, ErrorNotice, Facts, Page, Section, Specs, Status } from "@mws-dashboard/ui";
import { Boxes, Clock, FlaskConical, Gauge, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import type { ReactNode } from "react";

import { bedrock, ICONS, tone } from "../../../lib/clients";
import { KmsLink, ModelRef, S3Link, TYPE_LABEL } from "../../../lib/links";
import { TagsSection } from "../../../lib/tags";
import { deleteCustomModel } from "../jobs";

export const metadata: Metadata = { title: "Custom model" };

type Props = { searchParams: Promise<{ arn?: string }> };

export default async function CustomModel({ searchParams }: Props) {
  const arn = (await searchParams).arn ?? "";
  const back = { href: "/bedrock/custom-models", label: "Custom models" };
  const data = await load(async () => (await bedrock()).send(new GetCustomModelCommand({ modelIdentifier: arn })));
  if (!data.ok) {
    return (
      <Page title={arn.split("/").pop()} icon={ICONS.model} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const m = data.value;
  const hyper = Object.entries(m.hyperParameters ?? {});
  return (
    <Page
      title={m.modelName}
      icon={ICONS.model}
      back={back}
      subtitle={m.modelArn}
      actions={
        <>
          {m.modelStatus === "Active" && (
            <Link className="icon-button plain" href={`/bedrock/provisioned?model=${encodeURIComponent(m.modelArn!)}`} aria-label="Purchase Provisioned Throughput" title="Purchase Provisioned Throughput">
              <Gauge size={16} />
            </Link>
          )}
          <ActionForm action={deleteCustomModel.bind(null, m.modelArn!)} submit="Delete model" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${m.modelName}?`} />
        </>
      }
    >
      <Specs
        items={[
          m.modelStatus && { label: "Status", icon: <Boxes size={15} />, value: <Status tone={tone(m.modelStatus)}>{m.modelStatus}</Status> },
          m.customizationType && { label: "Customization", icon: <FlaskConical size={15} />, value: TYPE_LABEL[m.customizationType] ?? m.customizationType },
          { label: "Created", icon: <Clock size={15} />, value: ago(m.creationTime) },
        ]}
      />
      {m.failureMessage && <ErrorNotice error={m.failureMessage} />}
      <Section title="Details">
        <Facts
          items={[
            ["Base model", <ModelRef key="b" arn={m.baseModelArn} />],
            m.jobArn && ["Training job", <Link key="j" href={`/bedrock/customization-job?arn=${encodeURIComponent(m.jobArn)}`}>{m.jobName ?? m.jobArn.split("/").pop()}</Link>],
            m.trainingDataConfig?.s3Uri && ["Training data", <S3Link key="t" uri={m.trainingDataConfig.s3Uri} />],
            ...(m.validationDataConfig?.validators ?? []).map((v, i) => ["Validation data", <S3Link key={`v${i}`} uri={v.s3Uri} />] as [string, ReactNode]),
            m.outputDataConfig?.s3Uri && ["Output", <S3Link key="o" uri={m.outputDataConfig.s3Uri} />],
            m.modelKmsKeyArn && ["KMS key", <KmsLink key="k" arn={m.modelKmsKeyArn} />],
            m.trainingMetrics?.trainingLoss != null && ["Training loss", m.trainingMetrics.trainingLoss],
            ...(m.validationMetrics ?? []).map((v, i) => [`Validation loss ${i + 1}`, v.validationLoss] as [string, ReactNode]),
            ["Created", when(m.creationTime)],
          ]}
        />
      </Section>
      {hyper.length > 0 && (
        <Section title="Hyperparameters">
          <Facts items={hyper.map(([k, v]) => [k, <code key={k}>{v}</code>])} />
        </Section>
      )}
      <TagsSection arn={m.modelArn!} path="/bedrock/custom-model" />
    </Page>
  );
}
