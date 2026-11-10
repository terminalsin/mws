import { ago, load } from "@mws-dashboard/aws";
import {
  ActionForm,
  AwsIcon,
  Empty,
  ErrorNotice,
  Field,
  List,
  Page,
  Pill,
  Sheet,
  Status,
  type Rule,
} from "@mws-dashboard/ui";
import { CreateStream } from "@mws-dashboard/ui/model/kinesis";
import type { Metadata } from "next";

import { ICONS, STATUS_TONE, listStreams, streamHref } from "../../lib/clients";
import { createStream } from "./actions";

export const metadata: Metadata = { title: "Kinesis" };

const STREAM_NAME: Rule = {
  ...CreateStream.StreamName,
  hint: "Letters, digits, _ . -",
  generate: "name",
};

export default async function Streams() {
  const streams = await load(listStreams);
  const names = streams.ok ? streams.value.map((s) => s.StreamName!) : [];
  const create = (
    <Sheet
      title="Create data stream"
      label="Create data stream"
      testId="create-stream"
    >
      <ActionForm action={createStream} submit="Create" testId="create-stream">
        <Field label="Name" rule={STREAM_NAME} taken={names} unique>
          <input name="name" required autoFocus />
        </Field>
        <div className="form-row">
          <Field
            label="Capacity mode"
            rule={CreateStream.StreamModeDetails.fields!.StreamMode}
          >
            <select name="mode" defaultValue="ON_DEMAND">
              <option value="ON_DEMAND">On-demand</option>
              <option value="PROVISIONED">Provisioned</option>
            </select>
          </Field>
          <Field label="Shards (provisioned)" rule={CreateStream.ShardCount}>
            <input name="shards" type="number" min={1} defaultValue={1} />
          </Field>
        </div>
        <Field label="Tags" rule={{ ...CreateStream.Tags, format: "tags" }}>
          <textarea name="tags" rows={1} placeholder="team=data" />
        </Field>
      </ActionForm>
    </Sheet>
  );
  return (
    <Page title="Data streams" actions={create}>
      {streams.ok ? (
        <List
          label="Data streams"
          empty={<Empty icon={ICONS.kinesis} action={create} />}
          rows={streams.value.map((s) => ({
            key: s.StreamARN!,
            icon: <AwsIcon icon={ICONS.kinesis} size={24} />,
            title: s.StreamName,
            href: streamHref(s.StreamName!),
            meta: (
              <>
                <Pill>
                  {s.StreamModeDetails?.StreamMode === "ON_DEMAND"
                    ? "On-demand"
                    : "Provisioned"}
                </Pill>
                <Status tone={STATUS_TONE(s.StreamStatus)}>
                  {s.StreamStatus?.toLowerCase()}
                </Status>
                <span>{ago(s.StreamCreationTimestamp)}</span>
              </>
            ),
          }))}
        />
      ) : (
        <ErrorNotice error={streams.error} />
      )}
    </Page>
  );
}
