import { ago, load } from "@mws-dashboard/aws";
import {
  ActionForm,
  AwsIcon,
  Empty,
  ErrorNotice,
  List,
  Page,
  Pill,
  Sheet,
  Status,
} from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { ICONS, STATUS_TONE, listStreams, streamHref } from "../../lib/clients";
import { CreateStreamFields } from "../../lib/create";
import { createStream } from "./actions";

export const metadata: Metadata = { title: "Kinesis" };

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
        <CreateStreamFields names={names} />
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
                {s.StreamModeDetails?.StreamMode !== "ON_DEMAND" && (
                  <Pill>provisioned</Pill>
                )}
                {s.StreamStatus !== "ACTIVE" && (
                  <Status tone={STATUS_TONE(s.StreamStatus)}>
                    {s.StreamStatus?.toLowerCase()}
                  </Status>
                )}
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
