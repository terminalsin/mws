import { GetEventSelectorsCommand, GetInsightSelectorsCommand, GetTrailCommand, GetTrailStatusCommand, ListTagsCommand } from "@aws-sdk/client-cloudtrail";
import { ago, frameInfo, load, region as currentRegion, shortName } from "@mws-dashboard/aws";
import { ActionForm, CodeBlock, CopyValue, ErrorNotice, Facts, Field, Page, Pill, Section, Sheet, Specs, Status, Tags, type Rule } from "@mws-dashboard/ui";
import { UpdateTrail } from "@mws-dashboard/ui/model/cloudtrail";
import { Braces, Globe, Lightbulb, Pause, Pencil, Play, ShieldCheck, Tag, Trash2 } from "lucide-react";
import { MoreFields } from "@mws-dashboard/ui/presets";
import type { Metadata } from "next";
import Link from "next/link";
import type { ReactNode } from "react";

import { ICONS, cloudtrail, links, shadowOf } from "../../../lib/clients";
import { deleteTrail, saveAdvancedSelectors, saveEventSelectors, saveInsights, saveTags, setLogging, updateTrail } from "../actions";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";

type Props = { searchParams: Promise<{ arn?: string }> };

export async function generateMetadata({ searchParams }: Props): Promise<Metadata> {
  return { title: shortName((await searchParams).arn) || "Trail" };
}

const ARN_RULE: Rule = { format: "arn" };
const PREFIX: Rule = { ...UpdateTrail.S3KeyPrefix, maxLength: 200, hint: "Optional folder in the bucket" };

export default async function TrailPage({ searchParams }: Props) {
  const arn = (await searchParams).arn ?? "";
  const back = { href: "/cloudtrail?tab=trails", label: "Trails" };
  const client = await cloudtrail();
  const [region, me] = await Promise.all([currentRegion(), frameInfo()]);
  const data = await load(async () => {
    const [trail, status, selectors, insights] = await Promise.all([
      client.send(new GetTrailCommand({ Name: arn })).then((r) => r.Trail!),
      load(() => client.send(new GetTrailStatusCommand({ Name: arn }))),
      load(() => client.send(new GetEventSelectorsCommand({ TrailName: arn }))),
      load(() => client.send(new GetInsightSelectorsCommand({ TrailName: arn }))),
    ]);
    return { trail, status, selectors, insights };
  });
  if (!data.ok) {
    return (
      <Page title={shortName(arn)} icon={ICONS.cloudtrail} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { trail: t, status, selectors, insights } = data.value;
  const shadow = shadowOf(t, region, me.account);
  const tags = shadow ? null : await load(async () => (await client.send(new ListTagsCommand({ ResourceIdList: [arn] }))).ResourceTagList?.[0]?.TagsList ?? []);
  const logging = status.ok && !!status.value.IsLogging;
  const basic = selectors.ok ? (selectors.value.EventSelectors ?? []) : [];
  const advanced = selectors.ok ? (selectors.value.AdvancedEventSelectors ?? []) : [];
  const first = basic[0];
  const valuesOf = (type: string) => basic.flatMap((s) => s.DataResources ?? []).filter((d) => d.Type === type).flatMap((d) => d.Values ?? []);
  const insightTypes = insights.ok ? (insights.value.InsightSelectors ?? []).map((i) => i.InsightType!) : [];
  const s = status.ok ? status.value : undefined;
  return (
    <Page
      title={t.Name}
      icon={ICONS.cloudtrail}
      back={back}
      actions={
        shadow ? undefined : (
          <>
            <Sheet title="Edit trail" label="Edit trail" icon={<Pencil size={15} aria-hidden />} testId="edit-trail">
              <ActionForm action={updateTrail.bind(null, arn)} submit="Save" testId="edit-trail">
                <div className="form-row">
                  <Field label="S3 bucket" format="bucket">
                    <ResourcePicker kind="s3-bucket" name="bucket" required defaultValue={t.S3BucketName} />
                  </Field>
                  <Field label="Prefix" rule={PREFIX}>
                    <input name="prefix" defaultValue={t.S3KeyPrefix} />
                  </Field>
                </div>
                <MoreFields expanded={!!(t.SnsTopicARN || t.KmsKeyId || t.CloudWatchLogsLogGroupArn)}>
                  <Field label="SNS topic" hint="Name or ARN; empty turns notifications off">
                    <ResourcePicker kind="sns-topic" name="topic" defaultValue={t.SnsTopicARN} />
                  </Field>
                  <Field label="KMS key" hint="Key ID, ARN or alias; empty uses SSE-S3">
                    <ResourcePicker kind="kms-key" name="kms" exclude="AWS managed" defaultValue={t.KmsKeyId} />
                  </Field>
                  <Field label="CloudWatch Logs log group ARN" rule={ARN_RULE}>
                    <ResourcePicker kind="log-group" use="arn" name="logGroup" defaultValue={t.CloudWatchLogsLogGroupArn} />
                  </Field>
                  <Field label="CloudWatch Logs role ARN" rule={ARN_RULE}>
                    <ResourcePicker kind="iam-role" name="logRole" service="cloudtrail.amazonaws.com" defaultValue={t.CloudWatchLogsRoleArn} />
                  </Field>
                </MoreFields>
                <label className="check">
                  <input type="checkbox" name="multi" defaultChecked={t.IsMultiRegionTrail} /> All Regions
                </label>
                <Field label="Global service events">
                  <label className="check">
                    <input type="checkbox" name="global" defaultChecked={t.IncludeGlobalServiceEvents} /> Include IAM, STS and other global events
                  </label>
                </Field>
                <label className="check">
                  <input type="checkbox" name="validation" defaultChecked={t.LogFileValidationEnabled} /> Log file validation
                </label>
              </ActionForm>
            </Sheet>
            {status.ok && (
              <ActionForm
                action={setLogging.bind(null, arn, !logging)}
                submit={logging ? "Stop logging" : "Start logging"}
                icon={logging ? <Pause size={16} aria-hidden /> : <Play size={16} aria-hidden />}
                testId="toggle-logging"
              />
            )}
            <ActionForm action={deleteTrail.bind(null, arn, true)} submit="Delete trail" icon={<Trash2 size={16} aria-hidden />} tone="danger" confirm={`Delete ${t.Name}?`} testId="delete-trail" />
          </>
        )
      }
    >
      <Specs
        items={[
          { label: "Logging", icon: logging ? <Play size={15} /> : <Pause size={15} />, value: <Status tone={logging ? "good" : "neutral"}>{status.ok ? (logging ? "Logging" : "Off") : "Unknown"}</Status> },
          t.IsMultiRegionTrail && { label: "Regions", icon: <Globe size={15} />, value: "All Regions" },
          t.LogFileValidationEnabled && { label: "Log file validation", icon: <ShieldCheck size={15} />, value: "Validated" },
          insightTypes.length > 0 && { label: "Insights", icon: <Lightbulb size={15} />, value: insightTypes.map((i) => i.replace(/Insight$/, "")).join(", ") },
        ]}
      />
      {shadow && (
        <div className="banner" role="note">
          {shadow}: shown here as a shadow trail; changes are made from {t.HomeRegion && t.HomeRegion !== region ? t.HomeRegion : "the owner account"}.
        </div>
      )}
      {!status.ok && <ErrorNotice error={status.error} />}
      {s?.LatestDeliveryError && <ErrorNotice error={`Delivery to S3 failing: ${s.LatestDeliveryError}`} />}
      {s?.LatestNotificationError && <ErrorNotice error={`SNS notification failing: ${s.LatestNotificationError}`} />}
      {s?.LatestCloudWatchLogsDeliveryError && <ErrorNotice error={`CloudWatch Logs delivery failing: ${s.LatestCloudWatchLogsDeliveryError}`} />}
      <Section title="General details">
        <Facts
          items={[
            ["ARN", <CopyValue value={t.TrailARN} label="Copy trail ARN" />],
            ["Home Region", t.HomeRegion],
            ["S3 bucket", <Link href={links.bucket(t.S3BucketName!)}>{`s3://${t.S3BucketName}/${t.S3KeyPrefix ?? ""}`}</Link>],
            t.KmsKeyId ? ["KMS key", <Link href={links.key(t.KmsKeyId)}>{shortName(t.KmsKeyId)}</Link>] : ["Encryption", "SSE-S3"],
            t.SnsTopicARN && ["SNS topic", <Link href={links.topic(t.SnsTopicARN)}>{shortName(t.SnsTopicARN)}</Link>],
            t.CloudWatchLogsLogGroupArn && ["CloudWatch Logs", <Link href={links.logGroup(t.CloudWatchLogsLogGroupArn)}>{t.CloudWatchLogsLogGroupArn.split(":log-group:")[1]?.replace(/:\*$/, "")}</Link>],
            t.CloudWatchLogsRoleArn && ["Logs role", <Link href={links.role(t.CloudWatchLogsRoleArn)}>{shortName(t.CloudWatchLogsRoleArn)}</Link>],
            ["Global service events", t.IncludeGlobalServiceEvents ? "Included" : "Excluded"],
            t.IsOrganizationTrail && ["Organization trail", <Pill tone="info">Organization</Pill>],
            s?.LatestDeliveryTime && ["Last delivery", <span title={s.LatestDeliveryTime.toISOString()}>{ago(s.LatestDeliveryTime)}</span>],
            s?.LatestDigestDeliveryTime && ["Last digest", ago(s.LatestDigestDeliveryTime)],
            s?.LatestCloudWatchLogsDeliveryTime && ["Last CloudWatch Logs delivery", ago(s.LatestCloudWatchLogsDeliveryTime)],
            s?.StartLoggingTime && ["Logging started", ago(s.StartLoggingTime)],
            s?.StopLoggingTime && !logging && ["Logging stopped", ago(s.StopLoggingTime)],
          ]}
        />
      </Section>
      <Section
        title="Event selectors"
        actions={
          shadow ? undefined : (
            <>
              <Sheet title="Event selectors" label="Edit event selectors" icon={<Pencil size={15} aria-hidden />} testId="edit-selectors">
                <ActionForm action={saveEventSelectors.bind(null, arn)} submit="Save" testId="edit-selectors">
                  <label className="check">
                    <input type="checkbox" name="management" defaultChecked={advanced.length ? true : (first?.IncludeManagementEvents ?? true)} /> Management events
                  </label>
                  <Field label="API activity">
                    <select name="rw" defaultValue={first?.ReadWriteType ?? "All"}>
                      <option value="All">Read and write</option>
                      <option value="ReadOnly">Read only</option>
                      <option value="WriteOnly">Write only</option>
                    </select>
                  </Field>
                  <label className="check">
                    <input type="checkbox" name="excludeKms" defaultChecked={!!first?.ExcludeManagementEventSources?.includes("kms.amazonaws.com")} /> Exclude AWS KMS events
                  </label>
                  <Field label="S3 data events" hint="Buckets or bucket/prefix, one per line; * for all buckets">
                    <textarea name="s3" rows={3} defaultValue={valuesOf("AWS::S3::Object").map((v) => (v === "arn:aws:s3" || v === "arn:aws:s3:::" ? "*" : v.replace(/^arn:aws:s3:::/, "").replace(/\/$/, ""))).join("\n")} />
                  </Field>
                  <Field label="Lambda data events" hint="Function ARNs, one per line; * for all functions">
                    <textarea name="lambda" rows={2} defaultValue={valuesOf("AWS::Lambda::Function").map((v) => (v === "arn:aws:lambda" ? "*" : v)).join("\n")} />
                  </Field>
                </ActionForm>
              </Sheet>
              <Sheet title="Advanced event selectors" label="Edit advanced event selectors" icon={<Braces size={15} aria-hidden />} testId="edit-advanced">
                <ActionForm action={saveAdvancedSelectors.bind(null, arn)} submit="Save" testId="edit-advanced">
                  <Field label="AdvancedEventSelectors" format="json" hint="Replaces the basic selectors">
                    <textarea
                      name="advanced"
                      rows={14}
                      defaultValue={JSON.stringify(
                        advanced.length
                          ? advanced
                          : [
                              { Name: "Management events", FieldSelectors: [{ Field: "eventCategory", Equals: ["Management"] }] },
                              { Name: "S3 data events", FieldSelectors: [{ Field: "eventCategory", Equals: ["Data"] }, { Field: "resources.type", Equals: ["AWS::S3::Object"] }] },
                            ],
                        null,
                        2,
                      )}
                    />
                  </Field>
                </ActionForm>
              </Sheet>
            </>
          )
        }
      >
        {!selectors.ok ? (
          <ErrorNotice error={selectors.error} />
        ) : advanced.length ? (
          <CodeBlock value={JSON.stringify(advanced)} label="Advanced event selectors" />
        ) : (
          <Facts
            items={basic.flatMap((sel, i) => [
              [
                basic.length > 1 ? `Selector ${i + 1}` : "Management events",
                sel.IncludeManagementEvents ? `${sel.ReadWriteType === "ReadOnly" ? "Read" : sel.ReadWriteType === "WriteOnly" ? "Write" : "Read and write"}${sel.ExcludeManagementEventSources?.length ? ` · excluding ${sel.ExcludeManagementEventSources.join(", ")}` : ""}` : "Off",
              ] as [string, string],
              ...(sel.DataResources ?? []).map((d) => [`Data: ${d.Type}`, (d.Values ?? []).map((v) => <div key={v}>{v === "arn:aws:s3" || v === "arn:aws:s3:::" || v === "arn:aws:lambda" ? "All" : v}</div>)] as [string, ReactNode]),
            ])}
          />
        )}
      </Section>
      <Section
        title="Insights"
        actions={
          shadow ? undefined : (
            <Sheet title="Insights events" label="Edit Insights" icon={<Lightbulb size={15} aria-hidden />} testId="edit-insights">
              <ActionForm action={saveInsights.bind(null, arn)} submit="Save" testId="edit-insights">
                <label className="check">
                  <input type="checkbox" name="insight" value="ApiCallRateInsight" defaultChecked={insightTypes.includes("ApiCallRateInsight")} /> API call rate
                </label>
                <label className="check">
                  <input type="checkbox" name="insight" value="ApiErrorRateInsight" defaultChecked={insightTypes.includes("ApiErrorRateInsight")} /> API error rate
                </label>
              </ActionForm>
            </Sheet>
          )
        }
      >
        {insightTypes.length ? (
          <span className="chips">
            {insightTypes.map((i) => (
              <Pill key={i}>{i}</Pill>
            ))}
            <Link href="/cloudtrail?category=insight">Insights events</Link>
          </span>
        ) : (
          <span className="muted">Off</span>
        )}
      </Section>
      {tags && (
        <Section
          title="Tags"
          icon={<Tag size={15} aria-hidden />}
          actions={
            <Sheet title="Tags" label="Edit tags" icon={<Pencil size={15} aria-hidden />} testId="edit-trail-tags">
              <ActionForm action={saveTags.bind(null, arn, tags.ok ? tags.value.map((x) => x.Key!) : [])} submit="Save" testId="edit-trail-tags">
                <Field label="One Key=Value per line" format="tags">
                  <textarea name="tags" defaultValue={(tags.ok ? tags.value : []).map((x) => `${x.Key}=${x.Value ?? ""}`).join("\n")} />
                </Field>
              </ActionForm>
            </Sheet>
          }
        >
          {!tags.ok ? <ErrorNotice error={tags.error} /> : tags.value.length ? <Tags tags={tags.value} /> : <span className="muted">None</span>}
        </Section>
      )}
    </Page>
  );
}
