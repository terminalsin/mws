import { DescribeDeliveryStreamCommand } from "@aws-sdk/client-firehose";
import { ago, describeError, frameInfo, load } from "@mws-dashboard/aws";
import { bucketOptions } from "@mws-dashboard/aws/auto";
import {
  ActionForm,
  AutoPick,
  AwsIcon,
  Empty,
  ErrorNotice,
  Field,
  freeName,
  List,
  More,
  Page,
  Pill,
  Sheet,
  Status,
} from "@mws-dashboard/ui";
import { ArrowRight, Lock } from "lucide-react";
import { CreateDeliveryStream as Rules } from "@mws-dashboard/ui/model/firehose";
import { MoreFields } from "@mws-dashboard/ui/presets";
import type { Metadata } from "next";

import {
  ICONS,
  STATUS_TONE,
  allNames,
  firehose,
  namesPage,
  streamHref,
} from "../../lib/clients";
import { destinationOf } from "../../lib/firehose";
import { functionArns, kinesisArns, rolesTrusting } from "../../lib/network";
import { createDeliveryStream } from "./actions";
import { DestinationFields } from "./form";

export const metadata: Metadata = { title: "Firehose" };

const NAME = {
  ...Rules.DeliveryStreamName,
  hint: "Letters, digits, . - and _",
};
const SOURCE = {
  ...Rules.KinesisStreamSourceConfiguration.fields!.KinesisStreamARN,
  required: false,
};

type Props = { searchParams: Promise<{ start?: string }> };

export default async function DeliveryStreams({ searchParams }: Props) {
  const { start } = await searchParams;
  const [page, taken, roles, buckets, sources, functions, info] =
    await Promise.all([
      load(async () => {
        const client = await firehose();
        const { names, next } = await namesPage(start);
        // One failing stream shows its error on its row, not across the page.
        const rows = await Promise.all(
          names.map((n) =>
            client
              .send(
                new DescribeDeliveryStreamCommand({ DeliveryStreamName: n }),
              )
              .then(
                (r) => ({
                  name: n,
                  s: r.DeliveryStreamDescription!,
                  error: undefined,
                }),
                (e: unknown) => ({
                  name: n,
                  s: undefined,
                  error: describeError(e),
                }),
              ),
          ),
        );
        return { rows, next };
      }),
      load(allNames),
      load(() => rolesTrusting("firehose.amazonaws.com")),
      bucketOptions(),
      load(kinesisArns),
      load(functionArns),
      frameInfo(),
    ]);
  const names = taken.ok ? taken.value : [];
  const create = (
    <Sheet
      title="Create Firehose stream"
      label="Create Firehose stream"
      testId="create-delivery-stream"
    >
      <ActionForm
        action={createDeliveryStream}
        submit="Create"
        testId="create-delivery-stream"
      >
        <Field label="Name" rule={NAME} taken={names} generate="name" unique>
          <input
            name="name"
            required
            defaultValue={freeName("delivery-stream", names)}
            spellCheck={false}
          />
        </Field>
        <Field
          label="Source Kinesis stream ARN"
          rule={SOURCE}
          format="arn"
          known={sources.ok ? sources.value : []}
          arn={
            info.account
              ? `arn:aws:kinesis:${info.region}:${info.account}:stream/{}`
              : undefined
          }
        >
          <input name="source" placeholder="Direct PUT" />
        </Field>
        <AutoPick
          name="role"
          label="Role"
          creates="KinesisFirehoseServiceRole-<stream>"
          options={
            roles.ok
              ? roles.value.map((r) => ({ value: r.Arn!, label: r.RoleName! }))
              : []
          }
          testId="firehose-role"
        />
        <DestinationFields
          buckets={buckets}
          functions={functions.ok ? functions.value : []}
        />
        <MoreFields label="Encryption, tags">
          <label className="check">
            <input type="checkbox" name="sse" /> Server-side encryption (Direct
            PUT)
          </label>
          <Field label="Tags" rule={{ ...Rules.Tags, format: "tags" }}>
            <textarea name="tags" rows={1} placeholder="team=data" />
          </Field>
        </MoreFields>
      </ActionForm>
    </Sheet>
  );
  return (
    <Page title="Firehose streams" actions={create}>
      {page.ok ? (
        <>
          <List
            label="Firehose streams"
            empty={<Empty icon={ICONS.firehose} action={create} />}
            rows={page.value.rows.map(({ name, s, error }) => {
              if (!s)
                return {
                  key: name,
                  icon: <AwsIcon icon={ICONS.firehose} size={24} />,
                  title: name,
                  subtitle: error,
                  href: streamHref(name),
                  meta: <Status tone="bad">error</Status>,
                };
              const d = destinationOf(s);
              const source =
                s.Source?.KinesisStreamSourceDescription?.KinesisStreamARN;
              return {
                key: s.DeliveryStreamARN!,
                icon: <AwsIcon icon={ICONS.firehose} size={24} />,
                title: s.DeliveryStreamName,
                subtitle: (
                  <>
                    {source ? source.split("/").pop() : "Direct PUT"}{" "}
                    <ArrowRight size={11} aria-hidden /> {d.target}
                  </>
                ),
                href: streamHref(s.DeliveryStreamName!),
                meta: (
                  <>
                    {s.DeliveryStreamEncryptionConfiguration?.Status ===
                      "ENABLED" && <Lock size={13} aria-label="Encrypted" />}
                    <Pill>{d.kind}</Pill>
                    <Status tone={STATUS_TONE(s.DeliveryStreamStatus)}>
                      {s.DeliveryStreamStatus?.toLowerCase() ?? ""}
                    </Status>
                    <span>{ago(s.CreateTimestamp)}</span>
                  </>
                ),
              };
            })}
          />
          <More
            shown={page.value.rows.length}
            noun="streams"
            href={
              page.value.next
                ? `/firehose?${new URLSearchParams({ start: page.value.next })}`
                : undefined
            }
          />
        </>
      ) : (
        <ErrorNotice error={page.error} />
      )}
    </Page>
  );
}
