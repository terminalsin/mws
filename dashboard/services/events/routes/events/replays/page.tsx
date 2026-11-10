import { DescribeReplayCommand, ListReplaysCommand } from "@aws-sdk/client-eventbridge";
import { ago, all, load, when } from "@mws-dashboard/aws";
import { ActionForm, Empty, ErrorNotice, List, Page, Pill, Status, type Tone } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { History, OctagonX } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { events } from "../../../lib/clients";
import { EventsTabs } from "../../../lib/tabs";
import { cancelReplay } from "../actions";

export const metadata: Metadata = { title: "Replays" };

const TONE: Record<string, Tone> = { COMPLETED: "good", FAILED: "bad", CANCELLED: "neutral", STARTING: "info", RUNNING: "info", CANCELLING: "info" };
const ACTIVE = new Set(["STARTING", "RUNNING", "CANCELLING"]);

export default async function Replays() {
  const list = await load(async () => {
    const client = await events();
    const replays = await all((NextToken) => client.send(new ListReplaysCommand({ NextToken })), (r) => r.Replays, (r) => r.NextToken);
    const details = await Promise.all(replays.map((r) => client.send(new DescribeReplayCommand({ ReplayName: r.ReplayName! })).catch(() => undefined)));
    return replays.map((r, i) => ({ ...r, detail: details[i] }));
  });
  return (
    <Page title="Replays">
      <EventsTabs active="replays" />
      {list.ok ? (
        <>
          <LiveRefresh when={list.value.some((r) => ACTIVE.has(r.State ?? ""))} />
          <List
            label="Replays"
            empty={<Empty icon="service/AmazonEventBridge" />}
            rows={[...list.value]
              .sort((a, b) => new Date(b.ReplayStartTime ?? 0).getTime() - new Date(a.ReplayStartTime ?? 0).getTime())
              .map((r) => {
                const archive = r.EventSourceArn?.split("/").pop();
                const destination = r.detail?.Destination?.Arn?.split("/").pop();
                return {
                  key: r.ReplayName!,
                  icon: <History size={18} aria-hidden />,
                  title: r.ReplayName,
                  subtitle: (
                    <>
                      <Link href={`/events/archives?archive=${encodeURIComponent(archive ?? "")}`}>{archive}</Link>
                      {destination && (
                        <>
                          {" → "}
                          <Link href={destination === "default" ? "/events" : `/events?bus=${encodeURIComponent(destination)}`}>{destination}</Link>
                        </>
                      )}
                      {" · "}
                      {when(r.EventStartTime)} – {when(r.EventEndTime)}
                      {r.StateReason && <> · {r.StateReason}</>}
                    </>
                  ),
                  meta: (
                    <>
                      {r.EventLastReplayedTime && <Pill title="Last replayed event">{when(r.EventLastReplayedTime)}</Pill>}
                      <span>{ago(r.ReplayStartTime)}</span>
                      <Status tone={TONE[r.State ?? ""] ?? "neutral"}>{r.State ?? ""}</Status>
                    </>
                  ),
                  actions:
                    r.State === "STARTING" || r.State === "RUNNING" ? (
                      <ActionForm action={cancelReplay.bind(null, r.ReplayName!)} submit={`Cancel ${r.ReplayName}`} icon={<OctagonX size={15} aria-hidden />} tone="danger" confirm={`Cancel replay ${r.ReplayName}?`} />
                    ) : undefined,
                };
              })}
          />
        </>
      ) : (
        <ErrorNotice error={list.error} />
      )}
    </Page>
  );
}
