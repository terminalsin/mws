"use server";

import {
  CreateLogGroupCommand,
  CreateLogStreamCommand,
  DeleteLogGroupCommand,
  PutLogEventsCommand,
  ResourceAlreadyExistsException,
} from "@aws-sdk/client-cloudwatch-logs";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { logs } from "../../lib/clients";

export async function createGroup(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Log group name");
    await (await logs()).send(new CreateLogGroupCommand({ logGroupName: name }));
    return `Created ${name}`;
  }, "/logs");
}

export async function deleteGroup(name: string) {
  return act(async () => {
    await (await logs()).send(new DeleteLogGroupCommand({ logGroupName: name }));
    redirect("/logs");
  });
}

/** Write one event, creating the stream when it does not exist yet. */
export async function writeEvent(group: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await logs();
    const stream = text(form, "stream") || "console";
    try {
      await client.send(new CreateLogStreamCommand({ logGroupName: group, logStreamName: stream }));
    } catch (e) {
      if (!(e instanceof ResourceAlreadyExistsException)) throw e;
    }
    await client.send(
      new PutLogEventsCommand({
        logGroupName: group,
        logStreamName: stream,
        logEvents: [{ timestamp: Date.now(), message: required(form, "message", "Message") }],
      }),
    );
    return `Wrote an event to ${stream}`;
  }, "/logs/group");
}
