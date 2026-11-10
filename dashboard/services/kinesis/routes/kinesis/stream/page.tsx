import {
  DescribeStreamSummaryCommand,
  ListShardsCommand,
} from "@aws-sdk/client-kinesis";
import { all, load } from "@mws-dashboard/aws";
import {
  ActionForm,
  AwsIcon,
  ErrorNotice,
  Field,
  Page,
  Segments,
  Sheet,
  Specs,
  Status,
  type Rule,
} from "@mws-dashboard/ui";
import {
  PutRecord,
  PutRecords,
  UpdateShardCount,
} from "@mws-dashboard/ui/model/kinesis";
import {
  Clock,
  Layers,
  ListPlus,
  Lock,
  Send,
  SlidersHorizontal,
  Trash2,
  Users,
} from "lucide-react";
import type { Metadata } from "next";

import { ICONS, STATUS_TONE, kinesis, streamHref } from "../../../lib/clients";
import { deleteStream, putRecord, putRecords, reshard } from "../actions";
import {
  ApplicationsTab,
  ConfigurationTab,
  ConsumersTab,
  ShardsTab,
  ViewerTab,
  type Search,
} from "./tabs";

/** UpdateShardCount scales at most to double and at least to half the open
 * shards in one call (and to 10,000 shards per stream). */
function reshardRule(open: number): Rule {
  return {
    ...UpdateShardCount.TargetShardCount,
    min: Math.max(1, Math.ceil(open / 2)),
    max: Math.min(open * 2, 10000),
  };
}

type Props = { searchParams: Promise<Search> };

export async function generateMetadata({
  searchParams,
}: Props): Promise<Metadata> {
  return { title: (await searchParams).name ?? "Data stream" };
}

const TABS = ["viewer", "shards", "fanout", "applications", "configuration"];

export default async function Stream({ searchParams }: Props) {
  const search = await searchParams;
  const { name = "" } = search;
  const tab = TABS.includes(search.tab ?? "") ? search.tab! : "viewer";
  const back = { href: "/kinesis", label: "Data streams" };
  const client = await kinesis();
  const summary = await load(
    async () =>
      (
        await client.send(
          new DescribeStreamSummaryCommand({ StreamName: name }),
        )
      ).StreamDescriptionSummary!,
  );
  if (!summary.ok) {
    return (
      <Page title={name} icon={ICONS.kinesis} back={back}>
        <ErrorNotice error={summary.error} />
      </Page>
    );
  }
  const s = summary.value;
  const shards = await load(() =>
    all(
      (NextToken) =>
        client.send(
          new ListShardsCommand(
            NextToken ? { NextToken } : { StreamName: name },
          ),
        ),
      (r) => r.Shards,
      (r) => r.NextToken,
    ),
  );
  const provisioned = s.StreamModeDetails?.StreamMode !== "ON_DEMAND";
  const active = s.StreamStatus === "ACTIVE" || s.StreamStatus === "UPDATING";
  const base = streamHref(name);
  let body;
  if (!shards.ok) body = <ErrorNotice error={shards.error} />;
  else if (tab === "shards")
    body = (
      <ShardsTab
        name={name}
        shards={shards.value}
        provisioned={provisioned}
        active={s.StreamStatus === "ACTIVE"}
      />
    );
  else if (tab === "fanout")
    body = <ConsumersTab arn={s.StreamARN!} active={active} />;
  else if (tab === "applications")
    body = <ApplicationsTab arn={s.StreamARN!} name={name} />;
  else if (tab === "configuration")
    body = <ConfigurationTab s={s} active={s.StreamStatus === "ACTIVE"} />;
  else body = <ViewerTab name={name} shards={shards.value} search={search} />;
  return (
    <Page
      title={name}
      icon={ICONS.kinesis}
      back={back}
      subtitle={s.StreamARN}
      actions={
        <>
          {active && (
            <>
              <Sheet
                title="Put record"
                label="Put record"
                icon={<Send size={16} />}
                testId="put-record"
              >
                <ActionForm
                  action={putRecord.bind(null, name)}
                  submit="Put record"
                  testId="put-record"
                >
                  <Field label="Partition key" rule={PutRecord.PartitionKey}>
                    <input name="key" placeholder="random" />
                  </Field>
                  <Field
                    label="Explicit hash key"
                    rule={PutRecord.ExplicitHashKey}
                  >
                    <input name="hash" />
                  </Field>
                  <Field label="Data" rule={PutRecord.Data}>
                    <textarea
                      name="data"
                      rows={5}
                      required
                      className="code-editor"
                      defaultValue={'{\n  "event": "hello"\n}'}
                    />
                  </Field>
                </ActionForm>
              </Sheet>
              <Sheet
                title="Put record batch"
                label="Put record batch"
                icon={<ListPlus size={16} />}
                testId="put-records"
              >
                <ActionForm
                  action={putRecords.bind(null, name)}
                  submit="Put batch"
                  testId="put-records"
                >
                  <Field
                    label="Partition key"
                    rule={PutRecords.Records.item!.fields!.PartitionKey}
                    hint="Empty gives each record its own"
                  >
                    <input name="key" />
                  </Field>
                  <Field
                    label="Data"
                    rule={{ required: true }}
                    hint="One record per line, up to 500"
                  >
                    <textarea
                      name="data"
                      rows={6}
                      className="code-editor"
                      defaultValue={'{"event":"a"}\n{"event":"b"}'}
                    />
                  </Field>
                </ActionForm>
              </Sheet>
            </>
          )}
          {provisioned && s.StreamStatus === "ACTIVE" && (
            <Sheet
              title="Reshard"
              label="Reshard"
              icon={<SlidersHorizontal size={16} />}
              testId="reshard"
            >
              <ActionForm
                action={reshard.bind(null, name)}
                submit="Update"
                testId="reshard"
              >
                <Field
                  label="Open shards"
                  rule={reshardRule(s.OpenShardCount ?? 1)}
                >
                  <input
                    name="shards"
                    type="number"
                    defaultValue={s.OpenShardCount}
                  />
                </Field>
              </ActionForm>
            </Sheet>
          )}
          <ActionForm
            action={deleteStream.bind(null, name)}
            submit="Delete stream"
            icon={<Trash2 size={16} />}
            tone="danger"
            confirm={
              s.ConsumerCount
                ? `Delete ${name} and its ${s.ConsumerCount} registered consumer${s.ConsumerCount > 1 ? "s" : ""}?`
                : `Delete ${name}?`
            }
            testId="delete-stream"
          />
        </>
      }
    >
      <Specs
        items={[
          {
            label: "Status",
            icon: <AwsIcon icon={ICONS.kinesis} size={16} />,
            value: (
              <Status tone={STATUS_TONE(s.StreamStatus)}>
                {s.StreamStatus?.toLowerCase() ?? ""}
              </Status>
            ),
          },
          {
            label: "Capacity mode",
            icon: <SlidersHorizontal size={15} />,
            value: provisioned ? "Provisioned" : "On-demand",
          },
          {
            label: "Open shards",
            icon: <Layers size={15} />,
            value: s.OpenShardCount,
          },
          {
            label: "Retention",
            icon: <Clock size={15} />,
            value: `${s.RetentionPeriodHours}h`,
          },
          s.EncryptionType === "KMS" && {
            label: "Encryption",
            icon: <Lock size={15} />,
            value: s.KeyId?.split("/").pop() ?? "KMS",
          },
          !!s.ConsumerCount && {
            label: "Consumers",
            icon: <Users size={15} />,
            value: s.ConsumerCount,
          },
        ]}
      />
      <Segments
        label="Stream"
        items={[
          { label: "Data viewer", href: base, active: tab === "viewer" },
          {
            label: "Shards",
            href: `${base}&tab=shards`,
            active: tab === "shards",
            count: shards.ok ? shards.value.length : undefined,
          },
          {
            label: "Enhanced fan-out",
            href: `${base}&tab=fanout`,
            active: tab === "fanout",
            count: s.ConsumerCount || undefined,
          },
          {
            label: "Applications",
            href: `${base}&tab=applications`,
            active: tab === "applications",
          },
          {
            label: "Configuration",
            href: `${base}&tab=configuration`,
            active: tab === "configuration",
          },
        ]}
      />
      {body}
    </Page>
  );
}
