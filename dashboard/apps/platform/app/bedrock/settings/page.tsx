import { GetModelInvocationLoggingConfigurationCommand } from "@aws-sdk/client-bedrock";
import { load } from "@mws-dashboard/aws";
import { roleOptions } from "@mws-dashboard/aws/auto";
import { ActionForm, AutoPick, AwsIcon, ErrorNotice, Field, List, Page, Pill, Section, Sheet, zoneHref } from "@mws-dashboard/ui";
import { PowerOff, Settings2 } from "lucide-react";
import type { Metadata } from "next";

import { bedrock } from "../../../lib/clients";
import { saveLogging, stopLogging } from "../actions";
import { Providers } from "./providers";

export const metadata: Metadata = { title: "Settings" };

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
  const roles = await roleOptions("bedrock.amazonaws.com");
  const cw = c?.cloudWatchConfig;
  const s3 = c?.s3Config;
  const kinds = c && [c.textDataDeliveryEnabled && "text", c.imageDataDeliveryEnabled && "image", c.embeddingDataDeliveryEnabled && "embeddings", c.videoDataDeliveryEnabled && "video"].filter(Boolean);
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
                <Field label="Log group">
                  <input name="logGroup" defaultValue={cw?.logGroupName ?? "/aws/bedrock/invocations"} />
                </Field>
                <AutoPick name="role" label="Service role" creates="AmazonBedrockInvocationLoggingRole" options={roles} preferred={cw?.roleArn} testId="logging-role" />
                <div className="form-row">
                  <Field label="S3 bucket">
                    <input name="bucket" defaultValue={s3?.bucketName} />
                  </Field>
                  <Field label="Prefix">
                    <input name="prefix" defaultValue={s3?.keyPrefix} />
                  </Field>
                </div>
                <label className="check">
                  <input type="checkbox" name="images" defaultChecked={c?.imageDataDeliveryEnabled} /> Images
                </label>
                <label className="check">
                  <input type="checkbox" name="embeddings" defaultChecked={c?.embeddingDataDeliveryEnabled} /> Embeddings
                </label>
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
                title: <a href={`${zoneHref("observability", "/logs/group")}?name=${encodeURIComponent(cw.logGroupName)}`}>{cw.logGroupName}</a>,
                subtitle: cw.roleArn?.split("/").pop(),
              },
              s3?.bucketName && {
                key: "s3",
                icon: <AwsIcon icon="service/AmazonSimpleStorageService" size={22} />,
                title: <a href={zoneHref("storage", `/s3/${s3.bucketName}${s3.keyPrefix ? `?prefix=${encodeURIComponent(s3.keyPrefix)}` : ""}`)}>{`s3://${s3.bucketName}/${s3.keyPrefix ?? ""}`}</a>,
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
