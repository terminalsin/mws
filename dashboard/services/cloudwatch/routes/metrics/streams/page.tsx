import { ListMetricStreamsCommand } from "@aws-sdk/client-cloudwatch";
import {
  FirehoseClient,
  ListDeliveryStreamsCommand,
} from "@aws-sdk/client-firehose";
import { ago, all, client, frameInfo, load } from "@mws-dashboard/aws";
import { roleOptions } from "@mws-dashboard/aws/auto";
import {
  ActionForm,
  AutoPick,
  AwsIcon,
  Empty,
  ErrorNotice,
  Field,
  List,
  Page,
  Pill,
  Sheet,
  Status,
} from "@mws-dashboard/ui";
import { PutMetricStream } from "@mws-dashboard/ui/model/cloudwatch";
import { ArrowRight, Pause, Play, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, cloudwatch } from "../../../lib/clients";
import {
  deleteMetricStream,
  putMetricStream,
  setMetricStream,
} from "../actions";

export const metadata: Metadata = { title: "Metric streams" };

export default async function MetricStreams() {
  const info = await frameInfo();
  const [streams, firehoses, roles] = await Promise.all([
    load(async () => {
      const c = await cloudwatch();
      return all(
        (NextToken) => c.send(new ListMetricStreamsCommand({ NextToken })),
        (r) => r.Entries,
        (r) => r.NextToken,
      );
    }),
    load(async () => {
      const c = await client(FirehoseClient);
      const names: string[] = [];
      let start: string | undefined;
      for (;;) {
        const out = await c.send(
          new ListDeliveryStreamsCommand({
            Limit: 10000,
            ExclusiveStartDeliveryStreamName: start,
          }),
        );
        names.push(...(out.DeliveryStreamNames ?? []));
        if (!out.HasMoreDeliveryStreams || !out.DeliveryStreamNames?.length)
          break;
        start = names[names.length - 1];
      }
      return names.map(
        (n) =>
          `arn:aws:firehose:${info.region}:${info.account}:deliverystream/${n}`,
      );
    }),
    roleOptions("streams.metrics.cloudwatch.amazonaws.com"),
  ]);
  const create = (
    <Sheet
      title="Create metric stream"
      label="Create metric stream"
      testId="create-metric-stream"
    >
      <ActionForm
        action={putMetricStream}
        submit="Create"
        testId="create-metric-stream"
      >
        <Field
          label="Name"
          rule={PutMetricStream.Name}
          taken={streams.ok ? streams.value.map((s) => s.Name!) : []}
          generate="name"
          unique
        >
          <input name="name" autoFocus />
        </Field>
        <Field
          label="Firehose stream"
          rule={{ ...PutMetricStream.FirehoseArn, format: "arn" }}
          known={firehoses.ok ? firehoses.value : []}
          arn={
            info.account
              ? `arn:aws:firehose:${info.region}:${info.account}:deliverystream/{}`
              : undefined
          }
        >
          <input name="firehose" list="metric-stream-firehoses" />
        </Field>
        <datalist id="metric-stream-firehoses">
          {(firehoses.ok ? firehoses.value : []).map((f) => (
            <option key={f} value={f} />
          ))}
        </datalist>
        <AutoPick
          name="role"
          label="Role"
          creates="CloudWatchMetricStreamFirehoseRole"
          options={roles}
          testId="metric-stream-role"
        />
        <div className="form-grid">
          <Field label="Format" rule={PutMetricStream.OutputFormat}>
            <select name="format" defaultValue="json">
              <option value="json">JSON</option>
              <option value="opentelemetry1.0">OpenTelemetry 1.0</option>
              <option value="opentelemetry0.7">OpenTelemetry 0.7</option>
            </select>
          </Field>
          <Field label="Namespaces" rule={{ enum: ["include", "exclude"] }}>
            <select name="mode" defaultValue="include">
              <option value="include">Only these</option>
              <option value="exclude">All but these</option>
            </select>
          </Field>
        </div>
        <Field
          label="Namespace filter"
          rule={{ maxLength: 4096 }}
          hint="Empty streams every namespace"
        >
          <input name="namespaces" placeholder="AWS/Lambda, MyApp" />
        </Field>
      </ActionForm>
    </Sheet>
  );
  return (
    <Page
      title="Metric streams"
      icon={ICONS.metrics}
      back={{ href: "/metrics", label: "Metrics" }}
      actions={create}
    >
      {streams.ok ? (
        <List
          label="Metric streams"
          empty={<Empty icon={ICONS.metrics} action={create} />}
          rows={streams.value.map((s) => {
            const fh = s.FirehoseArn?.split("/").pop() ?? "";
            const running = s.State === "running";
            return {
              key: s.Arn!,
              icon: <AwsIcon icon="service/AmazonDataFirehose" size={22} />,
              title: s.Name,
              subtitle: (
                <>
                  {s.OutputFormat} <ArrowRight size={11} aria-hidden /> {fh}
                </>
              ),
              href: `/firehose/stream?${new URLSearchParams({ name: fh })}`,
              meta: (
                <>
                  {s.OutputFormat !== "json" && (
                    <Pill
                      tone="warn"
                      title="MWS delivers only JSON metric streams"
                    >
                      not delivered
                    </Pill>
                  )}
                  <Status tone={running ? "good" : "neutral"}>
                    {s.State ?? ""}
                  </Status>
                  <span>{ago(s.LastUpdateDate)}</span>
                </>
              ),
              actions: (
                <>
                  <ActionForm
                    action={setMetricStream.bind(null, s.Name!, !running)}
                    submit={running ? `Stop ${s.Name}` : `Start ${s.Name}`}
                    icon={running ? <Pause size={15} /> : <Play size={15} />}
                  />
                  <ActionForm
                    action={deleteMetricStream.bind(null, s.Name!)}
                    submit={`Delete ${s.Name}`}
                    icon={<Trash2 size={15} />}
                    tone="danger"
                    confirm={`Delete ${s.Name}?`}
                  />
                </>
              ),
            };
          })}
        />
      ) : (
        <ErrorNotice error={streams.error} />
      )}
    </Page>
  );
}
