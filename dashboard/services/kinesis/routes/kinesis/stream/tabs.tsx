import {
  GetResourcePolicyCommand,
  ListStreamConsumersCommand,
  ListTagsForResourceCommand,
  type Shard,
  type StreamDescriptionSummary,
} from "@aws-sdk/client-kinesis";
import {
  DescribeDeliveryStreamCommand,
  FirehoseClient,
  ListDeliveryStreamsCommand,
} from "@aws-sdk/client-firehose";
import { KMSClient, ListAliasesCommand } from "@aws-sdk/client-kms";
import {
  LambdaClient,
  ListEventSourceMappingsCommand,
} from "@aws-sdk/client-lambda";
import { ago, all, client, load } from "@mws-dashboard/aws";
import {
  ActionForm,
  AwsIcon,
  Empty,
  ErrorNotice,
  Facts,
  Field,
  List,
  More,
  Pill,
  Section,
  Sheet,
  Status,
  Tags,
  type Rule,
} from "@mws-dashboard/ui";
import {
  IncreaseStreamRetentionPeriod,
  PutResourcePolicy,
  RegisterStreamConsumer,
  SplitShard,
  StartStreamEncryption,
  TagResource,
} from "@mws-dashboard/ui/model/kinesis";
import { ArrowRight, Combine, Layers, Split, Trash2, X } from "lucide-react";
import Link from "next/link";

import { ICONS, STATUS_TONE, kinesis, streamHref } from "../../../lib/clients";
import {
  decode,
  newestRecords,
  shardPage,
  type Rec,
} from "../../../lib/records";
import {
  addTags,
  deregisterConsumer,
  mergeShards,
  registerConsumer,
  removeTag,
  savePolicy,
  setEncryption,
  setMode,
  setMonitoring,
  setRetention,
  splitShard,
} from "../actions";

export type Search = {
  name?: string;
  tab?: string;
  shard?: string;
  from?: string;
  at?: string;
  seq?: string;
  it?: string;
};

function RecordList({ records }: { records: Rec[] }) {
  return (
    <List
      label="Records"
      empty={<div className="empty">No records</div>}
      rows={records.map((r) => {
        const d = decode(r.Data);
        return {
          key: `${r.shard}-${r.SequenceNumber}`,
          icon: <Pill>{r.PartitionKey?.slice(0, 12)}</Pill>,
          title: <code className="clip">{d.text.replace(/\s+/g, " ")}</code>,
          subtitle: `${r.shard} · ${r.SequenceNumber}`,
          meta: (
            <>
              {d.kind && <Pill tone="info">{d.kind}</Pill>}
              <span title={r.ApproximateArrivalTimestamp?.toISOString()}>
                {ago(r.ApproximateArrivalTimestamp)}
              </span>
            </>
          ),
        };
      })}
    />
  );
}

const FROM: [string, string][] = [
  ["recent", "Newest"],
  ["trim", "Trim horizon"],
  ["latest", "Latest"],
  ["at", "At timestamp"],
  ["seq", "At sequence number"],
];

export async function ViewerTab({
  name,
  shards,
  search,
}: {
  name: string;
  shards: Shard[];
  search: Search;
}) {
  const { shard, from = "recent", at, seq, it } = search;
  const base = (p: Record<string, string | undefined>) =>
    streamHref(
      name,
      Object.fromEntries(
        Object.entries({ shard, from, at, seq, ...p }).filter(
          (e): e is [string, string] => !!e[1],
        ),
      ),
    );
  const picker = (
    <form className="search-page-form form-grid" action="/kinesis/stream">
      <input type="hidden" name="name" value={name} />
      <Field label="Shard" rule={{}}>
        <select name="shard" defaultValue={shard ?? ""}>
          <option value="">All shards</option>
          {shards.map((s) => (
            <option key={s.ShardId} value={s.ShardId}>
              {s.ShardId}
              {s.SequenceNumberRange?.EndingSequenceNumber ? " (closed)" : ""}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Starting position" rule={{}}>
        <select name="from" defaultValue={from}>
          {FROM.map(([k, l]) => (
            <option key={k} value={k}>
              {l}
            </option>
          ))}
        </select>
      </Field>
      <Field
        label="Timestamp"
        rule={{ type: "string" }}
        hint="With At timestamp"
      >
        <input name="at" type="datetime-local" step={1} defaultValue={at} />
      </Field>
      <Field
        label="Sequence number"
        rule={{ type: "string", pattern: "^(0|[1-9]\\d*)$" }}
        hint="With At sequence number"
      >
        <input name="seq" defaultValue={seq} />
      </Field>
      <div className="form-actions">
        <button type="submit" className="button primary">
          Get records
        </button>
      </div>
    </form>
  );
  // Newest records across shards, or one shard from a chosen position.
  if (!shard || from === "recent") {
    const pool = shard ? shards.filter((s) => s.ShardId === shard) : shards;
    const data = await load(() => newestRecords(name, pool));
    return (
      <>
        {picker}
        {data.ok ? (
          <>
            {data.value.errors.map((e) => (
              <ErrorNotice key={e.shard} error={`${e.shard}: ${e.error}`} />
            ))}
            <Section
              title="Newest records"
              count={data.value.records.length}
              plain
            >
              <RecordList records={data.value.records} />
            </Section>
          </>
        ) : (
          <ErrorNotice error={data.error} />
        )}
      </>
    );
  }
  const type =
    from === "trim"
      ? "TRIM_HORIZON"
      : from === "latest"
        ? "LATEST"
        : from === "seq"
          ? "AT_SEQUENCE_NUMBER"
          : "AT_TIMESTAMP";
  const page = await load(() =>
    shardPage(name, shard, {
      type,
      timestamp: at ? new Date(at.endsWith("Z") ? at : `${at}Z`) : undefined,
      sequence: seq,
      iterator: it,
    }),
  );
  return (
    <>
      {picker}
      {page.ok ? (
        <Section title={shard} count={page.value.records.length} plain>
          <RecordList records={page.value.records} />
          {page.value.next &&
            (page.value.records.length > 0 || (page.value.behind ?? 0) > 0) && (
              <More
                shown={page.value.records.length}
                noun="records"
                href={base({ it: page.value.next })}
              />
            )}
          {page.value.behind !== undefined && (
            <p className="muted">
              {page.value.behind
                ? `${Math.round(page.value.behind / 1000)} s behind the tip`
                : "At the tip"}
            </p>
          )}
        </Section>
      ) : (
        <ErrorNotice error={page.error} />
      )}
    </>
  );
}

/** The hash key in the middle of a shard's range, where a split halves it. */
const middle = (s: Shard) =>
  (
    (BigInt(s.HashKeyRange!.StartingHashKey!) +
      BigInt(s.HashKeyRange!.EndingHashKey!)) /
      BigInt(2) +
    BigInt(1)
  ).toString();

export function ShardsTab({
  name,
  shards,
  provisioned,
  active,
}: {
  name: string;
  shards: Shard[];
  provisioned: boolean;
  active: boolean;
}) {
  const open = shards
    .filter((s) => !s.SequenceNumberRange?.EndingSequenceNumber)
    .sort((a, b) =>
      BigInt(a.HashKeyRange!.StartingHashKey!) <
      BigInt(b.HashKeyRange!.StartingHashKey!)
        ? -1
        : 1,
    );
  const next = (s: Shard) => {
    const end = BigInt(s.HashKeyRange!.EndingHashKey!);
    return open.find(
      (o) => BigInt(o.HashKeyRange!.StartingHashKey!) === end + BigInt(1),
    );
  };
  return (
    <List
      label="Shards"
      rows={shards.map((sh) => {
        const closed = !!sh.SequenceNumberRange?.EndingSequenceNumber;
        const adjacent = closed ? undefined : next(sh);
        return {
          key: sh.ShardId!,
          icon: <Layers size={18} />,
          title: sh.ShardId,
          subtitle: (
            <>
              {sh.ParentShardId
                ? `from ${sh.ParentShardId}${sh.AdjacentParentShardId ? ` + ${sh.AdjacentParentShardId}` : ""} · `
                : ""}
              <span
                title={`${sh.HashKeyRange?.StartingHashKey} – ${sh.HashKeyRange?.EndingHashKey}`}
              >
                hash {shortKey(sh.HashKeyRange?.StartingHashKey)} –{" "}
                {shortKey(sh.HashKeyRange?.EndingHashKey)}
              </span>
            </>
          ),
          href: streamHref(name, { shard: sh.ShardId!, from: "trim" }),
          meta: (
            <Status tone={closed ? "neutral" : "good"}>
              {closed ? "Closed" : "Open"}
            </Status>
          ),
          actions:
            provisioned && active && !closed ? (
              <>
                <Sheet
                  title={`Split ${sh.ShardId}`}
                  label={`Split ${sh.ShardId}`}
                  icon={<Split size={15} />}
                  testId="split-shard"
                >
                  <ActionForm
                    action={splitShard.bind(
                      null,
                      name,
                      sh.ShardId!,
                      middle(sh),
                    )}
                    submit="Split"
                    testId="split-shard"
                  >
                    <Field
                      label="New starting hash key"
                      rule={{
                        ...SplitShard.NewStartingHashKey,
                        required: false,
                      }}
                      hint="Empty splits the range in half"
                    >
                      <input name="hash" placeholder={middle(sh)} />
                    </Field>
                  </ActionForm>
                </Sheet>
                {adjacent && (
                  <ActionForm
                    action={mergeShards.bind(
                      null,
                      name,
                      sh.ShardId!,
                      adjacent.ShardId!,
                    )}
                    submit={`Merge ${sh.ShardId} with ${adjacent.ShardId}`}
                    icon={<Combine size={15} />}
                    confirm={`Merge ${sh.ShardId} with ${adjacent.ShardId}?`}
                  />
                )}
              </>
            ) : undefined,
        };
      })}
    />
  );
}

const shortKey = (k: string | undefined) =>
  !k
    ? ""
    : k.length > 8
      ? `${k.slice(0, 4)}…${k.slice(-3)} (${k.length} digits)`
      : k;

export async function ConsumersTab({
  arn,
  active,
}: {
  arn: string;
  active: boolean;
}) {
  const consumers = await load(async () => {
    const c = await kinesis();
    return all(
      (NextToken) =>
        c.send(new ListStreamConsumersCommand({ StreamARN: arn, NextToken })),
      (r) => r.Consumers,
      (r) => r.NextToken,
    );
  });
  const register = active ? (
    <Sheet
      title="Register consumer"
      label="Register consumer"
      testId="register-consumer"
    >
      <ActionForm
        action={registerConsumer.bind(null, arn)}
        submit="Register"
        testId="register-consumer"
      >
        <Field
          label="Name"
          rule={RegisterStreamConsumer.ConsumerName}
          taken={
            consumers.ok ? consumers.value.map((c) => c.ConsumerName!) : []
          }
          generate="name"
          unique
        >
          <input name="name" autoFocus />
        </Field>
      </ActionForm>
    </Sheet>
  ) : null;
  return (
    <Section
      title="Enhanced fan-out"
      count={consumers.ok ? consumers.value.length : undefined}
      actions={register}
      plain
    >
      {consumers.ok ? (
        <List
          label="Consumers"
          empty={<Empty icon={ICONS.kinesis} />}
          rows={consumers.value.map((c) => ({
            key: c.ConsumerARN!,
            icon: <AwsIcon icon={ICONS.kinesis} size={20} />,
            title: c.ConsumerName,
            subtitle: c.ConsumerARN,
            meta: (
              <>
                <Status tone={STATUS_TONE(c.ConsumerStatus)}>
                  {c.ConsumerStatus?.toLowerCase() ?? ""}
                </Status>
                <span>{ago(c.ConsumerCreationTimestamp)}</span>
              </>
            ),
            actions:
              c.ConsumerStatus === "ACTIVE" ? (
                <ActionForm
                  action={deregisterConsumer.bind(null, c.ConsumerARN!)}
                  submit={`Deregister ${c.ConsumerName}`}
                  icon={<Trash2 size={15} />}
                  tone="danger"
                  confirm={`Deregister ${c.ConsumerName}?`}
                />
              ) : undefined,
          }))}
        />
      ) : (
        <ErrorNotice error={consumers.error} />
      )}
    </Section>
  );
}

/** Who reads the stream: Firehose streams with it as their source and Lambda
 * event source mappings on it. */
export async function ApplicationsTab({
  arn,
  name,
}: {
  arn: string;
  name: string;
}) {
  const [firehoses, mappings] = await Promise.all([
    load(async () => {
      const c = await client(FirehoseClient);
      const names: string[] = [];
      let start: string | undefined;
      for (;;) {
        const out = await c.send(
          new ListDeliveryStreamsCommand({
            Limit: 10000,
            DeliveryStreamType: "KinesisStreamAsSource",
            ExclusiveStartDeliveryStreamName: start,
          }),
        );
        names.push(...(out.DeliveryStreamNames ?? []));
        if (!out.HasMoreDeliveryStreams || !out.DeliveryStreamNames?.length)
          break;
        start = names[names.length - 1];
      }
      const described = await Promise.all(
        names.map((n) =>
          c
            .send(new DescribeDeliveryStreamCommand({ DeliveryStreamName: n }))
            .then(
              (r) => r.DeliveryStreamDescription,
              () => undefined,
            ),
        ),
      );
      return described.filter(
        (d) =>
          d?.Source?.KinesisStreamSourceDescription?.KinesisStreamARN === arn,
      );
    }),
    load(async () => {
      const c = await client(LambdaClient);
      return all(
        (Marker) =>
          c.send(
            new ListEventSourceMappingsCommand({ EventSourceArn: arn, Marker }),
          ),
        (r) => r.EventSourceMappings,
        (r) => r.NextMarker,
      );
    }),
  ]);
  return (
    <>
      <Section title="Consumers" plain>
        {firehoses.ok && mappings.ok ? (
          <List
            label="Applications"
            empty={<Empty icon={ICONS.kinesis} />}
            rows={[
              ...firehoses.value.map((f) => ({
                key: f!.DeliveryStreamARN!,
                icon: <AwsIcon icon="service/AmazonDataFirehose" size={20} />,
                title: f!.DeliveryStreamName,
                subtitle: "Firehose stream",
                href: `/firehose/stream?${new URLSearchParams({ name: f!.DeliveryStreamName! })}`,
                meta: (
                  <Status tone={STATUS_TONE(f!.DeliveryStreamStatus)}>
                    {f!.DeliveryStreamStatus?.toLowerCase() ?? ""}
                  </Status>
                ),
              })),
              ...mappings.value.map((m) => {
                const fn = m.FunctionArn?.split(":")[6] ?? "";
                return {
                  key: m.UUID!,
                  icon: (
                    <AwsIcon
                      icon="resource/AWSLambdaLambdaFunction"
                      size={20}
                    />
                  ),
                  title: fn,
                  subtitle: `Lambda trigger · batch ${m.BatchSize ?? ""} · ${m.StartingPosition ?? ""}`,
                  href: `/lambda/${encodeURIComponent(fn)}?tab=triggers`,
                  meta: (
                    <Status tone={m.State === "Enabled" ? "good" : "neutral"}>
                      {m.State ?? ""}
                    </Status>
                  ),
                };
              }),
            ]}
          />
        ) : (
          <ErrorNotice
            error={
              !firehoses.ok
                ? firehoses.error
                : !mappings.ok
                  ? mappings.error
                  : ""
            }
          />
        )}
      </Section>
      <p>
        <Link
          href={`/metrics?${new URLSearchParams({ ns: "AWS/Kinesis", q: name })}`}
        >
          AWS/Kinesis metrics <ArrowRight size={12} aria-hidden />
        </Link>
      </p>
    </>
  );
}

// Kinesis keeps data 24 hours to 365 days.
const RETENTION: Rule = {
  ...IncreaseStreamRetentionPeriod.RetentionPeriodHours,
  min: 24,
  max: 8760,
};

export async function ConfigurationTab({
  s,
  active,
}: {
  s: StreamDescriptionSummary;
  active: boolean;
}) {
  const arn = s.StreamARN!;
  const c = await kinesis();
  const [tags, policy, aliases] = await Promise.all([
    load(
      async () =>
        (await c.send(new ListTagsForResourceCommand({ ResourceARN: arn })))
          .Tags ?? [],
    ),
    load(
      async () =>
        (await c.send(new GetResourcePolicyCommand({ ResourceARN: arn })))
          .Policy ?? "",
    ),
    load(async () => {
      const k = await client(KMSClient);
      return all(
        (Marker) => k.send(new ListAliasesCommand({ Marker })),
        (r) => r.Aliases?.map((a) => a.AliasName!),
        (r) => (r.Truncated ? r.NextMarker : undefined),
      );
    }),
  ]);
  const provisioned = s.StreamModeDetails?.StreamMode !== "ON_DEMAND";
  const encrypted = s.EncryptionType === "KMS";
  const enhanced =
    s.EnhancedMonitoring?.flatMap((m) => m.ShardLevelMetrics ?? []) ?? [];
  const METRICS = [
    "IncomingBytes",
    "IncomingRecords",
    "OutgoingBytes",
    "OutgoingRecords",
    "WriteProvisionedThroughputExceeded",
    "ReadProvisionedThroughputExceeded",
    "IteratorAgeMilliseconds",
  ];
  return (
    <>
      <Section
        title="Stream settings"
        actions={
          active ? (
            <>
              <Sheet
                title="Data retention"
                label="Edit retention"
                testId="edit-retention"
              >
                <ActionForm
                  action={setRetention.bind(
                    null,
                    s.StreamName!,
                    s.RetentionPeriodHours ?? 24,
                  )}
                  submit="Save"
                  testId="edit-retention"
                >
                  <Field
                    label="Retention (hours)"
                    rule={RETENTION}
                    hint="24 hours to 365 days"
                  >
                    <input
                      name="hours"
                      type="number"
                      defaultValue={s.RetentionPeriodHours}
                    />
                  </Field>
                </ActionForm>
              </Sheet>
              <Sheet
                title="Capacity mode"
                label="Edit capacity mode"
                testId="edit-mode"
              >
                <ActionForm
                  action={setMode.bind(null, arn)}
                  submit="Save"
                  testId="edit-mode"
                >
                  <Field
                    label="Capacity mode"
                    rule={{ enum: ["ON_DEMAND", "PROVISIONED"] }}
                  >
                    <select
                      name="mode"
                      defaultValue={provisioned ? "ON_DEMAND" : "PROVISIONED"}
                    >
                      <option value="ON_DEMAND">On-demand</option>
                      <option value="PROVISIONED">Provisioned</option>
                    </select>
                  </Field>
                </ActionForm>
              </Sheet>
              <Sheet
                title="Server-side encryption"
                label="Edit encryption"
                testId="edit-encryption"
              >
                <ActionForm
                  action={setEncryption.bind(null, s.StreamName!)}
                  submit="Save"
                  testId="edit-encryption"
                >
                  <label className="check">
                    <input
                      type="checkbox"
                      name="enabled"
                      defaultChecked={encrypted}
                    />{" "}
                    Encrypt with KMS
                  </label>
                  <Field
                    label="KMS key"
                    rule={{ ...StartStreamEncryption.KeyId, required: false }}
                    known={aliases.ok ? aliases.value : []}
                  >
                    <input
                      name="key"
                      list="kinesis-keys"
                      defaultValue={s.KeyId ?? "alias/aws/kinesis"}
                    />
                  </Field>
                  <datalist id="kinesis-keys">
                    {(aliases.ok ? aliases.value : []).map((a) => (
                      <option key={a} value={a} />
                    ))}
                  </datalist>
                  {s.KeyId && (
                    <input type="hidden" name="current" value={s.KeyId} />
                  )}
                </ActionForm>
              </Sheet>
              <Sheet
                title="Enhanced (shard-level) metrics"
                label="Edit enhanced metrics"
                testId="edit-monitoring"
              >
                <ActionForm
                  action={setMonitoring.bind(null, s.StreamName!)}
                  submit="Save"
                  testId="edit-monitoring"
                >
                  {METRICS.map((m) => (
                    <label key={m} className="check">
                      <input
                        type="checkbox"
                        name="metrics"
                        value={m}
                        defaultChecked={
                          enhanced.includes(m as never) ||
                          enhanced.includes("ALL")
                        }
                      />{" "}
                      {m}
                    </label>
                  ))}
                </ActionForm>
              </Sheet>
            </>
          ) : undefined
        }
      >
        <Facts
          items={[
            ["Retention", `${s.RetentionPeriodHours} h`],
            ["Capacity mode", provisioned ? "Provisioned" : "On-demand"],
            [
              "Encryption",
              encrypted ? (
                <Link
                  key="k"
                  href={
                    s.KeyId?.startsWith("arn:")
                      ? `/kms/key?${new URLSearchParams({ id: s.KeyId.split("/").pop()! })}`
                      : "/kms?tab=aws"
                  }
                >
                  {s.KeyId}
                </Link>
              ) : (
                "Off"
              ),
            ],
            [
              "Shard-level metrics",
              enhanced.length ? enhanced.join(", ") : "Off",
            ],
            s.ConsumerCount !== undefined && ["Consumers", s.ConsumerCount],
            s.WarmThroughput?.CurrentMiBps !== undefined && [
              "Warm throughput",
              `${s.WarmThroughput.CurrentMiBps} MiB/s`,
            ],
          ]}
        />
      </Section>
      <Section
        title="Tags"
        actions={
          <Sheet title="Add tags" label="Add tags" testId="add-stream-tags">
            <ActionForm
              action={addTags.bind(null, arn)}
              submit="Add"
              testId="add-stream-tags"
            >
              <Field
                label="Tags"
                rule={{ ...TagResource.Tags, format: "tags" }}
              >
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
                  action={removeTag.bind(null, arn, t.Key!)}
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
      <Section
        title="Resource policy"
        actions={
          <Sheet
            title="Resource policy"
            label="Edit resource policy"
            testId="edit-policy"
          >
            <ActionForm
              action={savePolicy.bind(null, arn)}
              submit="Save"
              testId="edit-policy"
            >
              <Field
                label="Policy"
                rule={{
                  ...PutResourcePolicy.Policy,
                  required: false,
                  format: "policy",
                }}
                hint="Empty removes the policy"
              >
                <textarea
                  name="policy"
                  rows={10}
                  className="code-editor"
                  defaultValue={
                    policy.ok && policy.value
                      ? JSON.stringify(JSON.parse(policy.value), null, 2)
                      : ""
                  }
                />
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        {policy.ok ? (
          policy.value ? (
            <pre className="code">
              {JSON.stringify(JSON.parse(policy.value), null, 2)}
            </pre>
          ) : (
            <span className="muted">None</span>
          )
        ) : (
          <ErrorNotice error={policy.error} />
        )}
      </Section>
    </>
  );
}
