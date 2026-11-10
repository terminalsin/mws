import { GetModelInvocationLoggingConfigurationCommand } from "@aws-sdk/client-bedrock";
import { load } from "@mws-dashboard/aws";
import { bucketOptions, roleOptions } from "@mws-dashboard/aws/auto";
import { ActionForm, AutoPick, AwsIcon, ErrorNotice, Field, List, Page, Pill, Section, Sheet } from "@mws-dashboard/ui";
import { PutModelInvocationLoggingConfiguration } from "@mws-dashboard/ui/model/bedrock";
import { ruleAt } from "@mws-dashboard/ui/validation";
import { PowerOff, Settings2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { bedrock } from "../../../lib/clients";
import { saveLogging, stopLogging } from "../actions";
import { Providers } from "./providers";

export const metadata: Metadata = { title: "Settings" };

const at = (path: string) => ruleAt(PutModelInvocationLoggingConfiguration, `loggingConfig.${path}`);
// Either destination may be left empty; CloudWatch Logs' own name rule.
const LOG_GROUP = { ...at("cloudWatchConfig.logGroupName"), required: false, pattern: "^[.\\-_/#A-Za-z0-9]+$", hint: "Letters, digits and . - _ / #" };
const BUCKET = { ...at("s3Config.bucketName"), required: false, format: "bucket" as const };
const PREFIX = at("s3Config.keyPrefix");

export default async function Settings() {
  const config = await load(async () => (await (await bedrock()).send(new GetModelInvocationLoggingConfigurationCommand({}))).loggingConfig);
  if (!config.ok) {
    return (
      <Page title="Settings">
        <ErrorNotice error={config.error} />
      </Page>
    );
  }
  const c = config.value;
  const [roles, buckets] = await Promise.all([roleOptions("bedrock.amazonaws.com"), bucketOptions()]);
  const cw = c?.cloudWatchConfig;
  const s3 = c?.s3Config;
  const kinds = c && [c.textDataDeliveryEnabled && "text", c.imageDataDeliveryEnabled && "image", c.embeddingDataDeliveryEnabled && "embeddings", c.videoDataDeliveryEnabled && "video", c.audioDataDeliveryEnabled && "audio"].filter(Boolean);
  return (
    <Page title="Settings">
      <Providers />
      <Section
        title="Model invocation logging"
        actions={
          <>
            {c && <ActionForm action={stopLogging} submit="Turn off logging" icon={<PowerOff size={15} />} tone="danger" confirm="Stop logging model invocations?" />}
            <Sheet title="Model invocation logging" label="Edit logging" icon={<Settings2 size={15} />} testId="edit-logging">
              <ActionForm action={saveLogging} submit="Save" testId="edit-logging">
                <Field label="Log group" rule={LOG_GROUP}>
                  <input name="logGroup" defaultValue={cw?.logGroupName ?? (c ? "" : "/aws/bedrock/invocations")} />
                </Field>
                <AutoPick name="role" label="Service role" creates="AmazonBedrockInvocationLoggingRole" options={roles} preferred={cw?.roleArn} testId="logging-role" />
                <div className="form-row">
                  <Field label="S3 bucket" rule={BUCKET} known={buckets.map((b) => b.value)}>
                    <input name="bucket" defaultValue={s3?.bucketName} />
                  </Field>
                  <Field label="Prefix" rule={PREFIX}>
                    <input name="prefix" defaultValue={s3?.keyPrefix} />
                  </Field>
                </div>
                <fieldset className="checks">
                  <legend>Data types</legend>
                  <label className="check">
                    <input type="checkbox" name="text" defaultChecked={c ? !!c.textDataDeliveryEnabled : true} /> Text
                  </label>
                  <label className="check">
                    <input type="checkbox" name="images" defaultChecked={c?.imageDataDeliveryEnabled} /> Images
                  </label>
                  <label className="check">
                    <input type="checkbox" name="embeddings" defaultChecked={c?.embeddingDataDeliveryEnabled} /> Embeddings
                  </label>
                  <label className="check">
                    <input type="checkbox" name="video" defaultChecked={c?.videoDataDeliveryEnabled} /> Video
                  </label>
                  <label className="check">
                    <input type="checkbox" name="audio" defaultChecked={c?.audioDataDeliveryEnabled} /> Audio
                  </label>
                </fieldset>
              </ActionForm>
            </Sheet>
          </>
        }
      >
        {c ? (
          <List
            label="Destinations"
            rows={[
              cw?.logGroupName && {
                key: "cw",
                icon: <AwsIcon icon="service/AmazonCloudWatch" size={22} />,
                title: <Link href={`/logs/group?name=${encodeURIComponent(cw.logGroupName)}`}>{cw.logGroupName}</Link>,
                subtitle: cw.roleArn?.split("/").pop(),
              },
              s3?.bucketName && {
                key: "s3",
                icon: <AwsIcon icon="service/AmazonSimpleStorageService" size={22} />,
                title: <Link href={`/s3/${s3.bucketName}${s3.keyPrefix ? `?prefix=${encodeURIComponent(s3.keyPrefix)}` : ""}`}>{`s3://${s3.bucketName}/${s3.keyPrefix ?? ""}`}</Link>,
              },
              cw?.largeDataDeliveryS3Config?.bucketName && {
                key: "large",
                icon: <AwsIcon icon="service/AmazonSimpleStorageService" size={22} />,
                title: (
                  <Link href={`/s3/${cw.largeDataDeliveryS3Config.bucketName}${cw.largeDataDeliveryS3Config.keyPrefix ? `?prefix=${encodeURIComponent(cw.largeDataDeliveryS3Config.keyPrefix)}` : ""}`}>
                    {`s3://${cw.largeDataDeliveryS3Config.bucketName}/${cw.largeDataDeliveryS3Config.keyPrefix ?? ""}`}
                  </Link>
                ),
                subtitle: "Large payloads from CloudWatch Logs",
              },
            ]
              .filter((r) => !!r)
              .map((r) => ({ ...r, meta: <span className="chips">{(kinds as string[]).map((k) => <Pill key={k}>{k}</Pill>)}</span> }))}
          />
        ) : (
          <span className="muted">Off</span>
        )}
      </Section>
    </Page>
  );
}
