import { ListStreamsCommand } from "@aws-sdk/client-kinesis";
import { ago, collect, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Sheet, Status } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { ICONS, STATUS_TONE, kinesis } from "../../lib/clients";
import { createStream } from "./actions";

export const metadata: Metadata = { title: "Kinesis" };

export default async function Streams() {
  const streams = await load(async () => {
    const client = await kinesis();
    return collect(
      (NextToken) => client.send(new ListStreamsCommand({ NextToken })),
      (r) => r.StreamSummaries,
      (r) => (r.HasMoreStreams ? r.NextToken : undefined),
    );
  });
  const create = (
    <Sheet title="Create data stream" label="Create data stream" testId="create-stream">
      <ActionForm action={createStream} submit="Create" testId="create-stream">
        <Field label="Name">
          <input name="name" required pattern="[a-zA-Z0-9_.\-]+" autoFocus />
        </Field>
        <div className="form-row">
          <Field label="Capacity mode">
            <select name="mode" defaultValue="ON_DEMAND">
              <option value="ON_DEMAND">On-demand</option>
              <option value="PROVISIONED">Provisioned</option>
            </select>
          </Field>
          <Field label="Shards (provisioned)">
            <input name="shards" type="number" min={1} defaultValue={1} />
          </Field>
        </div>
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
            href: `/kinesis/stream?name=${encodeURIComponent(s.StreamName!)}`,
            meta: (
              <>
                <Pill>{s.StreamModeDetails?.StreamMode === "ON_DEMAND" ? "On-demand" : "Provisioned"}</Pill>
                <Status tone={STATUS_TONE(s.StreamStatus)}>{s.StreamStatus?.toLowerCase()}</Status>
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
