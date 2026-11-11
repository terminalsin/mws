import {
  GetBucketEncryptionCommand,
  GetBucketLocationCommand,
  GetBucketLoggingCommand,
  GetBucketNotificationConfigurationCommand,
  GetBucketTaggingCommand,
  GetBucketVersioningCommand,
  GetBucketWebsiteCommand,
  GetObjectLockConfigurationCommand,
  ListBucketsCommand,
} from "@aws-sdk/client-s3";
import { endpoint, load, shortName } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, ErrorNotice, Facts, Field, List, Pill, Section, Sheet, Status, Tags, type Rule } from "@mws-dashboard/ui";
import { PutBucketWebsite } from "@mws-dashboard/ui/model/s3";
import { ruleAt } from "@mws-dashboard/ui/validation";
import { ExternalLink, Pencil, Plus, Trash2, Undo2 } from "lucide-react";
import Link from "next/link";

import { CONTROL_ICONS, bucketHref, links, optional, s3 } from "../../../lib/s3";
import {
  addNotification,
  deleteNotification,
  resetEncryption,
  saveEncryption,
  saveLogging,
  saveObjectLock,
  saveTags,
  saveWebsite,
  setEventBridge,
  setVersioning,
} from "../actions";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";

const EVENTS = [
  "s3:ObjectCreated:*",
  "s3:ObjectCreated:Put",
  "s3:ObjectCreated:Post",
  "s3:ObjectCreated:Copy",
  "s3:ObjectCreated:CompleteMultipartUpload",
  "s3:ObjectRemoved:*",
  "s3:ObjectRemoved:Delete",
  "s3:ObjectRemoved:DeleteMarkerCreated",
  "s3:ObjectRestore:*",
  "s3:ObjectTagging:*",
  "s3:LifecycleExpiration:*",
  "s3:Replication:*",
];

const NOTIFICATION_ID: Rule = { maxLength: 255, hint: "A name for this configuration", generate: "name" };
const INDEX: Rule = { ...ruleAt(PutBucketWebsite, "WebsiteConfiguration.IndexDocument.Suffix"), pattern: "^[^/]+$", hint: "Like index.html (no slashes)" };

type Destination = { id: string; kind: "SNS topic" | "SQS queue" | "Lambda function"; arn: string; href: string; icon: string; events: string[]; filter: string };

export async function Properties({ bucket }: { bucket: string }) {
  const client = await s3();
  const props = await load(async () => {
    const [location, versioning, encryption, tags, website, logging, notifications, lock] = await Promise.all([
      client.send(new GetBucketLocationCommand({ Bucket: bucket })),
      client.send(new GetBucketVersioningCommand({ Bucket: bucket })),
      optional(() => client.send(new GetBucketEncryptionCommand({ Bucket: bucket }))),
      optional(() => client.send(new GetBucketTaggingCommand({ Bucket: bucket }))),
      optional(() => client.send(new GetBucketWebsiteCommand({ Bucket: bucket }))),
      load(() => client.send(new GetBucketLoggingCommand({ Bucket: bucket }))),
      load(() => client.send(new GetBucketNotificationConfigurationCommand({ Bucket: bucket }))),
      load(() => optional(() => client.send(new GetObjectLockConfigurationCommand({ Bucket: bucket })))),
    ]);
    return { location, versioning, encryption, tags, website, logging, notifications, lock };
  });
  if (!props.ok) return <ErrorNotice error={props.error} />;
  const { location, versioning, encryption, tags, website, logging, notifications, lock } = props.value;
  const buckets = await load(async () => ((await client.send(new ListBucketsCommand({}))).Buckets ?? []).map((b) => b.Name!));
  const rule = encryption?.ServerSideEncryptionConfiguration?.Rules?.[0];
  const sse = rule?.ApplyServerSideEncryptionByDefault;
  const versioned = versioning.Status === "Enabled";
  const n = notifications.ok ? notifications.value : undefined;
  const filterOf = (f?: { Key?: { FilterRules?: { Name?: string; Value?: string }[] } }) =>
    (f?.Key?.FilterRules ?? []).map((r) => `${r.Name?.toLowerCase()}: ${r.Value}`).join(" · ");
  const destinations: Destination[] = n
    ? [
        ...(n.TopicConfigurations ?? []).map((c) => ({ id: c.Id!, kind: "SNS topic" as const, arn: c.TopicArn!, href: links.topic(c.TopicArn!), icon: "service/AmazonSimpleNotificationService", events: c.Events ?? [], filter: filterOf(c.Filter) })),
        ...(n.QueueConfigurations ?? []).map((c) => ({ id: c.Id!, kind: "SQS queue" as const, arn: c.QueueArn!, href: links.queue(c.QueueArn!), icon: "service/AmazonSimpleQueueService", events: c.Events ?? [], filter: filterOf(c.Filter) })),
        ...(n.LambdaFunctionConfigurations ?? []).map((c) => ({ id: c.Id!, kind: "Lambda function" as const, arn: c.LambdaFunctionArn!, href: links.lambda(c.LambdaFunctionArn!), icon: "service/AWSLambda", events: c.Events ?? [], filter: filterOf(c.Filter) })),
      ]
    : [];
  const target = logging.ok ? logging.value.LoggingEnabled : undefined;
  const websiteUrl = `${endpoint()}/_aws/s3-website/${bucket}/`;
  const lockConfig = lock.ok ? lock.value?.ObjectLockConfiguration : undefined;
  const retention = lockConfig?.Rule?.DefaultRetention;
  return (
    <>
      <Section
        title="Bucket overview"
        actions={<ActionForm action={setVersioning.bind(null, bucket, !versioned)} submit={versioned ? "Suspend versioning" : "Enable versioning"} tone="plain" inline />}
      >
        <Facts
          items={[
            ["Region", location.LocationConstraint || "us-east-1"],
            ["Versioning", <Status tone={versioned ? "good" : "neutral"}>{versioning.Status ?? "Off"}</Status>],
            versioning.MFADelete === "Enabled" && ["MFA delete", "Enabled"],
          ]}
        />
      </Section>
      <Section
        title="Tags"
        actions={
          <Sheet title="Tags" label="Edit tags" icon={<Pencil size={15} aria-hidden />} testId="edit-tags">
            <ActionForm action={saveTags.bind(null, bucket)} submit="Save" testId="edit-tags">
              <Field label="One Key=Value per line" format="tags" hint="Empty removes every tag">
                <textarea name="tags" defaultValue={(tags?.TagSet ?? []).map((t) => `${t.Key}=${t.Value}`).join("\n")} />
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        {tags?.TagSet?.length ? <Tags tags={tags.TagSet} /> : <span className="muted">None</span>}
      </Section>
      <Section
        title="Default encryption"
        actions={
          <>
            <Sheet title="Default encryption" label="Edit default encryption" icon={<Pencil size={15} aria-hidden />} testId="edit-encryption">
              <ActionForm action={saveEncryption.bind(null, bucket)} submit="Save" testId="edit-encryption">
                <Field label="Encryption type">
                  <select name="algorithm" defaultValue={sse?.SSEAlgorithm ?? "AES256"}>
                    <option value="AES256">SSE-S3 (Amazon S3 managed keys)</option>
                    <option value="aws:kms">SSE-KMS (AWS KMS keys)</option>
                    <option value="aws:kms:dsse">DSSE-KMS (dual-layer)</option>
                  </select>
                </Field>
                <Field label="KMS key" hint="Key ID, ARN or alias; empty uses aws/s3">
                  <ResourcePicker kind="kms-key" name="kms" defaultValue={sse?.KMSMasterKeyID} />
                </Field>
                <label className="check">
                  <input type="checkbox" name="bucketKey" defaultChecked={rule?.BucketKeyEnabled ?? true} /> Bucket Key
                </label>
              </ActionForm>
            </Sheet>
            {sse && sse.SSEAlgorithm !== "AES256" && (
              <ActionForm action={resetEncryption.bind(null, bucket)} submit="Reset to SSE-S3" icon={<Undo2 size={15} aria-hidden />} confirm="Reset default encryption to SSE-S3?" />
            )}
          </>
        }
      >
        <Facts
          items={[
            ["Type", sse ? (sse.SSEAlgorithm === "AES256" ? "SSE-S3" : sse.SSEAlgorithm === "aws:kms" ? "SSE-KMS" : sse.SSEAlgorithm === "aws:kms:dsse" ? "DSSE-KMS" : sse.SSEAlgorithm) : "SSE-S3"],
            sse?.KMSMasterKeyID && ["KMS key", <Link href={links.key(sse.KMSMasterKeyID)}>{shortName(sse.KMSMasterKeyID)}</Link>],
            sse && sse.SSEAlgorithm !== "AES256" && ["Bucket Key", rule?.BucketKeyEnabled ? "Enabled" : "Disabled"],
          ]}
        />
      </Section>
      <Section
        title="Server access logging"
        actions={
          <Sheet title="Server access logging" label="Edit server access logging" icon={<Pencil size={15} aria-hidden />} testId="edit-logging">
            <ActionForm action={saveLogging.bind(null, bucket)} submit="Save" testId="edit-logging">
              <Field label="Destination bucket" hint="Empty turns logging off">
                <select name="target" defaultValue={target?.TargetBucket ?? ""}>
                  <option value="">Off</option>
                  {(buckets.ok ? buckets.value : []).map((b) => (
                    <option key={b} value={b}>
                      {b}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Prefix" rule={{ maxLength: 1024, hint: "Like logs/" }}>
                <input name="prefix" defaultValue={target?.TargetPrefix ?? `${bucket}/`} />
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        {!logging.ok ? (
          <ErrorNotice error={logging.error} />
        ) : target ? (
          <Facts items={[["Destination", <Link href={bucketHref(target.TargetBucket!, { prefix: target.TargetPrefix })}>{`s3://${target.TargetBucket}/${target.TargetPrefix ?? ""}`}</Link>]]} />
        ) : (
          <span className="muted">Off</span>
        )}
      </Section>
      <Section
        title="Event notifications"
        count={destinations.length}
        actions={
          <>
            {n && (
              <ActionForm
                action={setEventBridge.bind(null, bucket, !n.EventBridgeConfiguration)}
                submit={n.EventBridgeConfiguration ? "Stop sending to EventBridge" : "Send to EventBridge"}
                tone="plain"
                inline
                testId="eventbridge"
              />
            )}
            <Sheet title="Create event notification" label="Create event notification" icon={<Plus size={15} aria-hidden />} testId="create-notification">
              <ActionForm action={addNotification.bind(null, bucket)} submit="Save" testId="create-notification">
                <Field label="Name" rule={NOTIFICATION_ID} taken={destinations.map((d) => d.id)} unique>
                  <input name="id" required />
                </Field>
                <div className="form-row">
                  <Field label="Prefix">
                    <input name="prefix" placeholder="images/" />
                  </Field>
                  <Field label="Suffix">
                    <input name="suffix" placeholder=".jpg" />
                  </Field>
                </div>
                <fieldset className="field" data-testid="notification-events">
                  <legend className="field-label">Event types</legend>
                  {EVENTS.map((e) => (
                    <label key={e} className="check">
                      <input type="checkbox" name="events" value={e} defaultChecked={e === "s3:ObjectCreated:*"} /> <code>{e}</code>
                    </label>
                  ))}
                </fieldset>
                <Field label="Destination">
                  <select name="type" defaultValue="sqs">
                    <option value="sqs">SQS queue</option>
                    <option value="sns">SNS topic</option>
                    <option value="lambda">Lambda function</option>
                  </select>
                </Field>
                <Field label="Destination ARN" format="arn">
                  <ResourcePicker kind={["sqs-queue", "sns-topic", "lambda-function"]} use="arn" name="arn" required />
                </Field>
              </ActionForm>
            </Sheet>
          </>
        }
      >
        {!notifications.ok ? (
          <ErrorNotice error={notifications.error} />
        ) : (
          <>
            {n?.EventBridgeConfiguration && (
              <p>
                <Pill tone="info" icon={<AwsIcon icon="service/AmazonEventBridge" size={14} />}>
                  Sending every event to EventBridge
                </Pill>{" "}
                <Link href="/events">Rules</Link>
              </p>
            )}
            <List
              label="Event notifications"
              empty={n?.EventBridgeConfiguration ? undefined : <span className="muted">None</span>}
              rows={destinations.map((d) => ({
                key: d.id,
                icon: <AwsIcon icon={d.icon} size={22} />,
                title: d.id,
                subtitle: (
                  <>
                    <Link href={d.href}>{shortName(d.arn)}</Link> · {d.events.join(", ")}
                    {d.filter && ` · ${d.filter}`}
                  </>
                ),
                meta: <Pill>{d.kind}</Pill>,
                actions: <ActionForm action={deleteNotification.bind(null, bucket, d.id)} submit={`Delete ${d.id}`} icon={<Trash2 size={15} aria-hidden />} tone="danger" confirm={`Delete event notification ${d.id}?`} />,
              }))}
            />
          </>
        )}
      </Section>
      <Section
        title="Static website hosting"
        actions={
          <Sheet title="Static website hosting" label="Edit static website hosting" icon={<Pencil size={15} aria-hidden />} testId="edit-website">
            <ActionForm action={saveWebsite.bind(null, bucket)} submit="Save" testId="edit-website">
              <Field label="Hosting">
                <select name="mode" defaultValue={website ? (website.RedirectAllRequestsTo ? "redirect" : "host") : "host"}>
                  <option value="host">Host a static website</option>
                  <option value="redirect">Redirect requests</option>
                  <option value="off">Disabled</option>
                </select>
              </Field>
              <div className="form-row">
                <Field label="Index document" rule={INDEX}>
                  <input name="index" defaultValue={website?.IndexDocument?.Suffix ?? "index.html"} />
                </Field>
                <Field label="Error document">
                  <input name="error" defaultValue={website?.ErrorDocument?.Key} placeholder="error.html" />
                </Field>
              </div>
              <div className="form-row">
                <Field label="Redirect to host" format="domain">
                  <input name="redirect" defaultValue={website?.RedirectAllRequestsTo?.HostName} />
                </Field>
                <Field label="Protocol">
                  <select name="protocol" defaultValue={website?.RedirectAllRequestsTo?.Protocol ?? ""}>
                    <option value="">As requested</option>
                    <option value="https">https</option>
                    <option value="http">http</option>
                  </select>
                </Field>
              </div>
            </ActionForm>
          </Sheet>
        }
      >
        {website ? (
          <Facts
            items={[
              [
                "Endpoint",
                <a href={websiteUrl} target="_blank" rel="noreferrer">
                  {websiteUrl} <ExternalLink size={12} aria-hidden />
                </a>,
              ],
              website.IndexDocument && ["Index document", website.IndexDocument.Suffix],
              website.ErrorDocument && ["Error document", website.ErrorDocument.Key],
              website.RedirectAllRequestsTo && ["Redirects to", `${website.RedirectAllRequestsTo.Protocol ?? ""}${website.RedirectAllRequestsTo.Protocol ? "://" : ""}${website.RedirectAllRequestsTo.HostName}`],
              website.RoutingRules?.length ? ["Routing rules", website.RoutingRules.length] : null,
            ]}
          />
        ) : (
          <span className="muted">Disabled</span>
        )}
      </Section>
      <Section
        title="Object Lock"
        icon={<AwsIcon icon={CONTROL_ICONS.lock} size={16} />}
        actions={
          lockConfig?.ObjectLockEnabled === "Enabled" ? (
            <Sheet title="Default retention" label="Edit Object Lock default retention" icon={<Pencil size={15} aria-hidden />} testId="edit-object-lock">
              <ActionForm action={saveObjectLock.bind(null, bucket)} submit="Save" testId="edit-object-lock">
                <Field label="Default retention mode">
                  <select name="mode" defaultValue={retention?.Mode ?? ""}>
                    <option value="">None</option>
                    <option value="GOVERNANCE">Governance</option>
                    <option value="COMPLIANCE">Compliance</option>
                  </select>
                </Field>
                <Field label="Days" rule={{ type: "integer", min: 1 }}>
                  <input name="days" type="number" min={1} defaultValue={retention?.Days ?? 1} />
                </Field>
              </ActionForm>
            </Sheet>
          ) : undefined
        }
      >
        {!lock.ok ? (
          <ErrorNotice error={lock.error} />
        ) : lockConfig?.ObjectLockEnabled === "Enabled" ? (
          <Facts
            items={[
              ["Object Lock", <Status tone="good">Enabled</Status>],
              ["Default retention", retention ? `${retention.Mode?.toLowerCase()} · ${retention.Days ? `${retention.Days} days` : `${retention.Years} years`}` : "None"],
            ]}
          />
        ) : (
          <span className="muted">Disabled</span>
        )}
      </Section>
    </>
  );
}
