import {
  DescribeDeliveryStreamCommand,
  ListTagsForDeliveryStreamCommand,
  type DestinationDescription,
} from "@aws-sdk/client-firehose";
import { ListObjectsV2Command, S3Client } from "@aws-sdk/client-s3";
import { ago, bytes, client, load, when } from "@mws-dashboard/aws";
import {
  ActionForm,
  AwsIcon,
  Empty,
  ErrorNotice,
  Facts,
  Field,
  FileIcon,
  List,
  Page,
  Section,
  Segments,
  Sheet,
  Specs,
  Status,
  Tags,
} from "@mws-dashboard/ui";
import {
  PutRecord,
  StartDeliveryStreamEncryption,
  UpdateDestination,
} from "@mws-dashboard/ui/model/firehose";
import {
  ArrowRight,
  ChartLine,
  Clock,
  ListPlus,
  Lock,
  Pencil,
  Send,
  Tag,
  Trash2,
  X,
} from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, STATUS_TONE, firehose, streamHref } from "../../../lib/clients";
import {
  COMPRESSIONS,
  destinationOf,
  lambdaOf,
  s3Href,
} from "../../../lib/firehose";
import { functionArns } from "../../../lib/network";
import {
  addTags,
  deleteDeliveryStream,
  putFirehoseRecord,
  putRecordBatch,
  removeTag,
  setEncryption,
  updateDestination,
} from "../actions";

type Props = { searchParams: Promise<{ name?: string; tab?: string }> };

export async function generateMetadata({
  searchParams,
}: Props): Promise<Metadata> {
  return { title: (await searchParams).name ?? "Firehose stream" };
}

const U = UpdateDestination.ExtendedS3DestinationUpdate.fields!;
const H = UpdateDestination.HttpEndpointDestinationUpdate.fields!;
const roleHref = (arn: string | undefined) =>
  arn ? `/iam/roles/${encodeURIComponent(arn.split("/").pop()!)}` : undefined;
const fnHref = (arn: string) =>
  `/lambda/${encodeURIComponent(arn.split(":")[6] ?? arn)}`;
const bucketOf = (arn: string | undefined) => arn?.split(":::").pop() ?? "";

/** The settings that matter of whichever destination the stream has. */
function destinationFacts(d: DestinationDescription | undefined) {
  const s3 = d?.ExtendedS3DestinationDescription ?? d?.S3DestinationDescription;
  const ext = d?.ExtendedS3DestinationDescription;
  const http = d?.HttpEndpointDestinationDescription;
  const splunk = d?.SplunkDestinationDescription;
  const backup =
    http?.S3DestinationDescription ??
    splunk?.S3DestinationDescription ??
    ext?.S3BackupDescription;
  const processing =
    ext?.ProcessingConfiguration ??
    http?.ProcessingConfiguration ??
    splunk?.ProcessingConfiguration;
  const fn = lambdaOf(processing);
  const logging =
    s3?.CloudWatchLoggingOptions ??
    http?.CloudWatchLoggingOptions ??
    splunk?.CloudWatchLoggingOptions;
  const buffer =
    s3?.BufferingHints ?? http?.BufferingHints ?? splunk?.BufferingHints;
  const roleArn = s3?.RoleARN ?? http?.RoleARN ?? backup?.RoleARN;
  return [
    http && ["Endpoint", http.EndpointConfiguration?.Url],
    http?.EndpointConfiguration?.Name && [
      "Endpoint name",
      http.EndpointConfiguration.Name,
    ],
    http && [
      "Content encoding",
      http.RequestConfiguration?.ContentEncoding ?? "NONE",
    ],
    splunk && [
      "HEC endpoint",
      `${splunk.HECEndpoint} (${splunk.HECEndpointType})`,
    ],
    (http?.RetryOptions ?? splunk?.RetryOptions) && [
      "Retry duration",
      `${(http?.RetryOptions ?? splunk?.RetryOptions)?.DurationInSeconds} s`,
    ],
    s3 && [
      "Bucket",
      <Link key="b" href={s3Href(s3.BucketARN, s3.Prefix)}>
        {bucketOf(s3.BucketARN)}
      </Link>,
    ],
    s3?.Prefix && ["Prefix", <code key="p">{s3.Prefix}</code>],
    s3?.ErrorOutputPrefix && [
      "Error prefix",
      <Link key="e" href={s3Href(s3.BucketARN, s3.ErrorOutputPrefix)}>
        <code>{s3.ErrorOutputPrefix}</code>
      </Link>,
    ],
    buffer && [
      "Buffer",
      `${buffer.IntervalInSeconds} s / ${buffer.SizeInMBs} MiB`,
    ],
    s3?.CompressionFormat &&
      s3.CompressionFormat !== "UNCOMPRESSED" && [
        "Compression",
        s3.CompressionFormat,
      ],
    ext?.FileExtension && ["File extension", ext.FileExtension],
    s3?.EncryptionConfiguration?.KMSEncryptionConfig && [
      "Object encryption",
      s3.EncryptionConfiguration.KMSEncryptionConfig.AWSKMSKeyARN?.split(
        "/",
      ).pop(),
    ],
    fn && [
      "Transform",
      <Link key="f" href={fnHref(fn)}>
        {fn.split(":")[6]}
      </Link>,
    ],
    processing?.Enabled &&
      !fn && [
        "Processing",
        processing.Processors?.map((p) => p.Type).join(", "),
      ],
    ext?.DynamicPartitioningConfiguration?.Enabled && [
      "Dynamic partitioning",
      "On",
    ],
    ext?.DataFormatConversionConfiguration?.Enabled && [
      "Format conversion",
      "On",
    ],
    (ext?.S3BackupMode === "Enabled" ||
      http?.S3BackupMode ||
      splunk?.S3BackupMode) && [
      "S3 backup",
      http?.S3BackupMode ?? splunk?.S3BackupMode ?? "Source records",
    ],
    backup && [
      "Backup bucket",
      <Link key="bb" href={s3Href(backup.BucketARN, backup.Prefix)}>
        {bucketOf(backup.BucketARN)}
        {backup.Prefix ? `/${backup.Prefix}` : ""}
      </Link>,
    ],
    logging?.Enabled && [
      "Error logging",
      <Link
        key="l"
        href={`/logs/group?${new URLSearchParams({ name: logging.LogGroupName ?? "" })}`}
      >
        {logging.LogGroupName}
      </Link>,
    ],
    roleArn && [
      "Role",
      <Link key="r" href={roleHref(roleArn)!}>
        {roleArn.split("/").pop()}
      </Link>,
    ],
  ] as ([string, React.ReactNode] | false | undefined | "")[];
}

async function Objects({ d }: { d: DestinationDescription | undefined }) {
  const s3 =
    d?.ExtendedS3DestinationDescription ??
    d?.S3DestinationDescription ??
    d?.HttpEndpointDestinationDescription?.S3DestinationDescription ??
    d?.SplunkDestinationDescription?.S3DestinationDescription;
  if (!s3) return <Empty icon={ICONS.firehose} />;
  const bucket = bucketOf(s3.BucketARN);
  const prefix = (s3.Prefix ?? "").split("!{")[0];
  const objects = await load(async () => {
    const c = await client(S3Client, { forcePathStyle: true });
    const out: { Key?: string; Size?: number; LastModified?: Date }[] = [];
    let token: string | undefined;
    do {
      const r = await c.send(
        new ListObjectsV2Command({
          Bucket: bucket,
          Prefix: prefix || undefined,
          ContinuationToken: token,
        }),
      );
      out.push(...(r.Contents ?? []));
      token = r.NextContinuationToken;
    } while (token && out.length < 5000);
    return {
      list: out.sort(
        (a, b) =>
          (b.LastModified?.getTime() ?? 0) - (a.LastModified?.getTime() ?? 0),
      ),
      truncated: !!token,
    };
  });
  if (!objects.ok) return <ErrorNotice error={objects.error} />;
  const errors = s3.ErrorOutputPrefix
    ? objects.value.list.filter((o) =>
        o.Key?.startsWith(s3.ErrorOutputPrefix!.split("!{")[0]),
      )
    : [];
  const shown = objects.value.list.slice(0, 50);
  return (
    <Section
      title="Delivered objects"
      count={objects.value.list.length}
      actions={
        <Link
          className="icon-button plain"
          href={s3Href(s3.BucketARN, s3.Prefix)}
          aria-label="Open in S3"
          title="Open in S3"
        >
          <ArrowRight size={15} />
        </Link>
      }
      plain
    >
      {errors.length > 0 && (
        <ErrorNotice
          error={`${errors.length} object${errors.length > 1 ? "s" : ""} under the error prefix`}
        />
      )}
      <List
        label="Delivered objects"
        empty={<Empty icon="resource/AmazonSimpleStorageServiceBucket" />}
        rows={shown.map((o) => ({
          key: o.Key!,
          icon: <FileIcon name={o.Key!} />,
          title: o.Key!.slice(prefix.length) || o.Key,
          href: `/api/s3/object?${new URLSearchParams({ bucket, key: o.Key! })}`,
          external: true,
          meta: (
            <>
              <span>{bytes(o.Size)}</span>
              <span>{ago(o.LastModified)}</span>
            </>
          ),
        }))}
      />
      {objects.value.list.length > shown.length && (
        <p className="more-items">
          <span>
            Newest {shown.length} of{" "}
            {objects.value.list.length.toLocaleString()}
            {objects.value.truncated ? "+" : ""}
          </span>
          <Link href={s3Href(s3.BucketARN, s3.Prefix)}>All in S3</Link>
        </p>
      )}
    </Section>
  );
}

export default async function DeliveryStream({ searchParams }: Props) {
  const { name = "", tab: rawTab } = await searchParams;
  const tab = ["configuration", "objects", "tags"].includes(rawTab ?? "")
    ? rawTab!
    : "configuration";
  const back = { href: "/firehose", label: "Firehose streams" };
  const data = await load(
    async () =>
      (
        await (
          await firehose()
        ).send(new DescribeDeliveryStreamCommand({ DeliveryStreamName: name }))
      ).DeliveryStreamDescription!,
  );
  if (!data.ok) {
    return (
      <Page title={name} icon={ICONS.firehose} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const s = data.value;
  const d = destinationOf(s);
  const dest = s.Destinations?.[0];
  const s3 =
    dest?.ExtendedS3DestinationDescription ?? dest?.S3DestinationDescription;
  const http = dest?.HttpEndpointDestinationDescription;
  const splunk = dest?.SplunkDestinationDescription;
  const source = s.Source?.KinesisStreamSourceDescription;
  const enc = s.DeliveryStreamEncryptionConfiguration;
  const active = s.DeliveryStreamStatus === "ACTIVE";
  const editable = active && (s3 || http || splunk);
  const [functions, tags] = await Promise.all([
    load(functionArns),
    load(
      async () =>
        (
          await (
            await firehose()
          ).send(
            new ListTagsForDeliveryStreamCommand({ DeliveryStreamName: name }),
          )
        ).Tags ?? [],
    ),
  ]);
  const fn = lambdaOf(
    dest?.ExtendedS3DestinationDescription?.ProcessingConfiguration ??
      http?.ProcessingConfiguration ??
      splunk?.ProcessingConfiguration,
  );
  const logging =
    s3?.CloudWatchLoggingOptions ??
    http?.CloudWatchLoggingOptions ??
    splunk?.CloudWatchLoggingOptions;
  const buffer =
    s3?.BufferingHints ?? http?.BufferingHints ?? splunk?.BufferingHints;
  const base = streamHref(name);
  const fnList = functions.ok ? functions.value : [];
  return (
    <Page
      title={name}
      icon={ICONS.firehose}
      back={back}
      subtitle={s.DeliveryStreamARN}
      actions={
        <>
          {!source && active && (
            <>
              <Sheet
                title="Test with demo data"
                label="Put record"
                icon={<Send size={16} />}
                testId="put-firehose-record"
              >
                <ActionForm
                  action={putFirehoseRecord.bind(null, name)}
                  submit="Put record"
                  testId="put-firehose-record"
                >
                  <Field label="Record" rule={PutRecord.Record.fields!.Data}>
                    <textarea
                      name="data"
                      rows={5}
                      required
                      className="code-editor"
                      defaultValue={'{"ticker":"AMZN","price":181.2}'}
                    />
                  </Field>
                  <Field label="Delimiter" rule={{ enum: ["on", "off"] }}>
                    <select name="newline" defaultValue="on">
                      <option value="on">Newline after the record</option>
                      <option value="off">None</option>
                    </select>
                  </Field>
                </ActionForm>
              </Sheet>
              <Sheet
                title="Put record batch"
                label="Put record batch"
                icon={<ListPlus size={16} />}
                testId="put-record-batch"
              >
                <ActionForm
                  action={putRecordBatch.bind(null, name)}
                  submit="Put batch"
                  testId="put-record-batch"
                >
                  <Field
                    label="Data"
                    rule={{ required: true }}
                    hint="One record per line, up to 500"
                  >
                    <textarea
                      name="data"
                      rows={6}
                      className="code-editor"
                      defaultValue={
                        '{"ticker":"AMZN","price":181.2}\n{"ticker":"MSFT","price":410.5}'
                      }
                    />
                  </Field>
                </ActionForm>
              </Sheet>
            </>
          )}
          {editable && (
            <Sheet
              title="Edit destination"
              label="Edit destination"
              icon={<Pencil size={16} />}
              testId="edit-destination"
            >
              <ActionForm
                action={updateDestination.bind(null, name)}
                submit="Save"
                testId="edit-destination"
              >
                <input type="hidden" name="version" value={s.VersionId} />
                {http && (
                  <>
                    <Field
                      label="Endpoint URL"
                      rule={
                        H.EndpointConfiguration.fields?.Url ?? { format: "url" }
                      }
                      format="url"
                    >
                      <input
                        name="url"
                        defaultValue={http.EndpointConfiguration?.Url}
                        required
                      />
                    </Field>
                    <div className="form-grid">
                      <Field label="Endpoint name" rule={{ maxLength: 256 }}>
                        <input
                          name="endpointName"
                          defaultValue={http.EndpointConfiguration?.Name}
                        />
                      </Field>
                      <Field
                        label="Access key"
                        rule={{ maxLength: 4096 }}
                        hint="Empty keeps it"
                      >
                        <input
                          name="accessKey"
                          type="password"
                          autoComplete="off"
                        />
                      </Field>
                      <Field
                        label="Content encoding"
                        rule={{ enum: ["NONE", "GZIP"] }}
                      >
                        <select
                          name="encoding"
                          defaultValue={
                            http.RequestConfiguration?.ContentEncoding ?? "NONE"
                          }
                        >
                          <option value="NONE">None</option>
                          <option value="GZIP">GZIP</option>
                        </select>
                      </Field>
                    </div>
                  </>
                )}
                {splunk && (
                  <>
                    <Field
                      label="HEC endpoint"
                      rule={{ maxLength: 2048 }}
                      format="url"
                    >
                      <input
                        name="hec"
                        defaultValue={splunk.HECEndpoint}
                        required
                      />
                    </Field>
                    <Field
                      label="HEC token"
                      rule={{ maxLength: 2048 }}
                      hint="Empty keeps it"
                    >
                      <input
                        name="hecToken"
                        type="password"
                        autoComplete="off"
                      />
                    </Field>
                  </>
                )}
                {(http || splunk) && (
                  <Field
                    label="Retry duration (s)"
                    rule={{
                      type: "integer",
                      min: 0,
                      max: 7200,
                      unit: "seconds",
                    }}
                  >
                    <input
                      name="retry"
                      type="number"
                      defaultValue={
                        (http?.RetryOptions ?? splunk?.RetryOptions)
                          ?.DurationInSeconds ?? 300
                      }
                    />
                  </Field>
                )}
                {s3 && (
                  <div className="form-grid">
                    <Field label="Prefix" rule={U.Prefix}>
                      <input name="prefix" defaultValue={s3.Prefix} />
                    </Field>
                    <Field label="Error prefix" rule={U.ErrorOutputPrefix}>
                      <input
                        name="errorPrefix"
                        defaultValue={s3.ErrorOutputPrefix}
                      />
                    </Field>
                    <Field label="Compression" rule={U.CompressionFormat}>
                      <select
                        name="compression"
                        defaultValue={s3.CompressionFormat ?? "UNCOMPRESSED"}
                      >
                        {COMPRESSIONS.map((c) => (
                          <option key={c}>{c}</option>
                        ))}
                      </select>
                    </Field>
                    {dest?.ExtendedS3DestinationDescription && (
                      <Field label="File extension" rule={U.FileExtension}>
                        <input
                          name="extension"
                          defaultValue={
                            dest.ExtendedS3DestinationDescription.FileExtension
                          }
                        />
                      </Field>
                    )}
                  </div>
                )}
                <div className="form-grid">
                  <Field
                    label="Buffer interval (s)"
                    rule={{ type: "integer", min: 0, max: 900 }}
                  >
                    <input
                      name="interval"
                      type="number"
                      defaultValue={buffer?.IntervalInSeconds}
                    />
                  </Field>
                  <Field
                    label="Buffer size (MiB)"
                    rule={{
                      type: "integer",
                      min: 1,
                      max: http ? 64 : splunk ? 5 : 128,
                    }}
                  >
                    <input
                      name="size"
                      type="number"
                      defaultValue={buffer?.SizeInMBs}
                    />
                  </Field>
                </div>
                {!dest?.S3DestinationDescription ||
                dest.ExtendedS3DestinationDescription ||
                http ||
                splunk ? (
                  <>
                    <Field
                      label="Transform with Lambda"
                      rule={{ format: "arn", known: fnList }}
                      hint="Empty turns processing off"
                    >
                      <input
                        name="lambda"
                        list="edit-functions"
                        defaultValue={fn}
                      />
                    </Field>
                    <datalist id="edit-functions">
                      {fnList.map((f) => (
                        <option key={f} value={f} />
                      ))}
                    </datalist>
                    <label className="check">
                      <input
                        type="checkbox"
                        name="logging"
                        defaultChecked={!!logging?.Enabled}
                      />{" "}
                      Log delivery errors to CloudWatch
                    </label>
                    {logging?.LogGroupName && (
                      <input
                        type="hidden"
                        name="logGroup"
                        value={logging.LogGroupName}
                      />
                    )}
                  </>
                ) : null}
                <Field label="Role ARN" rule={{ ...U.RoleARN, format: "arn" }}>
                  <input
                    name="role"
                    defaultValue={
                      s3?.RoleARN ??
                      http?.RoleARN ??
                      splunk?.S3DestinationDescription?.RoleARN
                    }
                  />
                </Field>
              </ActionForm>
            </Sheet>
          )}
          {active && (
            <Sheet
              title="Server-side encryption"
              label="Encryption"
              icon={<Lock size={16} />}
              testId="firehose-encryption"
            >
              <ActionForm
                action={setEncryption.bind(null, name)}
                submit="Save"
                testId="firehose-encryption"
              >
                <Field
                  label="Encryption"
                  rule={{ enum: ["", "AWS_OWNED_CMK", "CUSTOMER_MANAGED_CMK"] }}
                >
                  <select
                    name="keyType"
                    defaultValue={
                      enc?.Status === "ENABLED" || enc?.Status === "ENABLING"
                        ? (enc.KeyType ?? "AWS_OWNED_CMK")
                        : ""
                    }
                  >
                    <option value="">Off</option>
                    <option value="AWS_OWNED_CMK">AWS owned key</option>
                    <option value="CUSTOMER_MANAGED_CMK">
                      Customer managed key
                    </option>
                  </select>
                </Field>
                <Field
                  label="KMS key ARN"
                  rule={{
                    ...StartDeliveryStreamEncryption
                      .DeliveryStreamEncryptionConfigurationInput.fields!
                      .KeyARN,
                    format: "arn",
                  }}
                  hint="Customer managed key only"
                >
                  <input name="key" defaultValue={enc?.KeyARN} />
                </Field>
              </ActionForm>
            </Sheet>
          )}
          <Link
            className="icon-button plain"
            href={`/metrics?${new URLSearchParams({ ns: "AWS/Firehose", q: name })}`}
            aria-label="Metrics"
            title="Metrics"
          >
            <ChartLine size={16} aria-hidden />
          </Link>
          <ActionForm
            action={deleteDeliveryStream.bind(null, name)}
            submit="Delete Firehose stream"
            icon={<Trash2 size={16} />}
            tone="danger"
            confirm={`Delete ${name}?`}
            testId="delete-delivery-stream"
          />
        </>
      }
    >
      {s.FailureDescription && (
        <ErrorNotice
          error={`${s.FailureDescription.Type}: ${s.FailureDescription.Details}`}
        />
      )}
      {enc?.FailureDescription && (
        <ErrorNotice
          error={`Encryption ${enc.FailureDescription.Type}: ${enc.FailureDescription.Details}`}
        />
      )}
      <Specs
        items={[
          {
            label: "Status",
            icon: <AwsIcon icon={ICONS.firehose} size={16} />,
            value: (
              <Status tone={STATUS_TONE(s.DeliveryStreamStatus)}>
                {s.DeliveryStreamStatus?.toLowerCase() ?? ""}
              </Status>
            ),
          },
          buffer && {
            label: "Buffer",
            icon: <Clock size={15} />,
            value: `${buffer.IntervalInSeconds}s / ${buffer.SizeInMBs} MiB`,
          },
          s3?.CompressionFormat &&
            s3.CompressionFormat !== "UNCOMPRESSED" && {
              label: "Compression",
              icon: <Lock size={15} />,
              value: s3.CompressionFormat,
            },
          enc?.Status &&
            enc.Status !== "DISABLED" && {
              label: "Encryption",
              icon: <Lock size={15} />,
              value: (
                <Status
                  tone={STATUS_TONE(enc.Status)}
                >{`${enc.Status.toLowerCase()}${enc.KeyType === "CUSTOMER_MANAGED_CMK" ? " · CMK" : ""}`}</Status>
              ),
            },
          {
            label: "Version",
            icon: <Tag size={15} />,
            value: `v${s.VersionId}`,
          },
        ]}
      />
      <div className="flow" aria-label="Flow">
        {source ? (
          <Link
            className="flow-node"
            href={`/kinesis/stream?${new URLSearchParams({ name: source.KinesisStreamARN?.split("/").pop() ?? "" })}`}
          >
            <AwsIcon icon={ICONS.kinesis} size={34} />
            <span>{source.KinesisStreamARN?.split("/").pop()}</span>
          </Link>
        ) : (
          <div className="flow-node">
            <AwsIcon icon="resource/Internet" size={34} />
            <span>Direct PUT</span>
          </div>
        )}
        <ArrowRight className="flow-arrow" size={20} aria-hidden />
        {fn && (
          <>
            <Link className="flow-node" href={fnHref(fn)}>
              <AwsIcon icon="resource/AWSLambdaLambdaFunction" size={34} />
              <span>{fn.split(":")[6]}</span>
            </Link>
            <ArrowRight className="flow-arrow" size={20} aria-hidden />
          </>
        )}
        <div className="flow-node">
          <AwsIcon icon={ICONS.firehose} size={34} />
          <span>{name}</span>
        </div>
        <ArrowRight className="flow-arrow" size={20} aria-hidden />
        {d.href ? (
          <Link className="flow-node" href={d.href}>
            <AwsIcon icon={d.icon} size={34} />
            <span>{d.target}</span>
          </Link>
        ) : (
          <div className="flow-node">
            <AwsIcon icon={d.icon} size={34} />
            <span>{d.target || d.kind}</span>
          </div>
        )}
      </div>
      <Segments
        label="Firehose stream"
        items={[
          {
            label: "Configuration",
            href: base,
            active: tab === "configuration",
          },
          {
            label: "Destination objects",
            href: `${base}&tab=objects`,
            active: tab === "objects",
          },
          {
            label: "Tags",
            href: `${base}&tab=tags`,
            active: tab === "tags",
            count: tags.ok ? tags.value.length || undefined : undefined,
          },
        ]}
      />
      {tab === "objects" ? (
        <Objects d={dest} />
      ) : tab === "tags" ? (
        <Section
          title="Tags"
          actions={
            <Sheet title="Add tags" label="Add tags" testId="add-firehose-tags">
              <ActionForm
                action={addTags.bind(null, name)}
                submit="Add"
                testId="add-firehose-tags"
              >
                <Field label="Tags" rule={{ format: "tags", maxLength: 8192 }}>
                  <textarea name="tags" rows={3} placeholder="team=data" />
                </Field>
              </ActionForm>
            </Sheet>
          }
          plain
        >
          {tags.ok ? (
            <List
              label="Tags"
              empty={<Empty />}
              rows={tags.value.map((t) => ({
                key: t.Key!,
                title: <Tags tags={[t]} />,
                actions: (
                  <ActionForm
                    action={removeTag.bind(null, name, t.Key!)}
                    submit={`Remove ${t.Key}`}
                    icon={<X size={14} />}
                    tone="danger"
                  />
                ),
              }))}
            />
          ) : (
            <ErrorNotice error={tags.error} />
          )}
        </Section>
      ) : (
        <Section>
          <Facts
            items={[
              [
                "Source",
                source ? (
                  <Link
                    key="s"
                    href={`/kinesis/stream?${new URLSearchParams({ name: source.KinesisStreamARN?.split("/").pop() ?? "" })}`}
                  >
                    {source.KinesisStreamARN}
                  </Link>
                ) : (
                  "Direct PUT"
                ),
              ],
              source?.RoleARN && [
                "Source role",
                <Link key="sr" href={roleHref(source.RoleARN)!}>
                  {source.RoleARN.split("/").pop()}
                </Link>,
              ],
              ["Destination", d.kind],
              ...destinationFacts(dest),
              enc?.Status &&
                enc.Status !== "DISABLED" && [
                  "Encryption",
                  `${enc.Status} · ${enc.KeyType === "CUSTOMER_MANAGED_CMK" ? (enc.KeyARN?.split("/").pop() ?? "CMK") : "AWS owned key"}`,
                ],
              ["Created", when(s.CreateTimestamp)],
              s.LastUpdateTimestamp && ["Updated", when(s.LastUpdateTimestamp)],
            ]}
          />
        </Section>
      )}
    </Page>
  );
}
