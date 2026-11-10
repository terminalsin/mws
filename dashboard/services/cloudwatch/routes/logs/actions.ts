"use server";

import {
  CreateLogGroupCommand,
  CreateLogStreamCommand,
  DeleteLogGroupCommand,
  DeleteRetentionPolicyCommand,
  PutLogEventsCommand,
  PutRetentionPolicyCommand,
  ResourceAlreadyExistsException,
} from "@aws-sdk/client-cloudwatch-logs";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { logs } from "../../lib/clients";

export async function createGroup(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Log group name");
    const client = await logs();
    await client.send(new CreateLogGroupCommand({ logGroupName: name, logGroupClass: text(form, "infrequent") === "on" ? "INFREQUENT_ACCESS" : undefined }));
    const days = Number(text(form, "retention"));
    if (days) await client.send(new PutRetentionPolicyCommand({ logGroupName: name, retentionInDays: days }));
    return `Created ${name}`;
  }, { revalidate: ["/logs"], fields: { logGroupName: "name", retentionInDays: "retention" } });
}

export async function deleteGroup(name: string) {
  return act(async () => {
    await (await logs()).send(new DeleteLogGroupCommand({ logGroupName: name }));
    redirect("/logs");
  });
}

export async function setRetention(name: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const days = Number(text(form, "retention"));
      const client = await logs();
      if (days) await client.send(new PutRetentionPolicyCommand({ logGroupName: name, retentionInDays: days }));
      else await client.send(new DeleteRetentionPolicyCommand({ logGroupName: name }));
      return days ? `Kept for ${days} days` : "Kept forever";
    },
    { revalidate: ["/logs", "/logs/group"], fields: { retentionInDays: "retention", InvalidParameterException: "retention" } },
  );
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
    return `Wrote to ${stream}`;
  }, { revalidate: ["/logs/group"], fields: { logStreamName: "stream", "logEvents.message": "message" } });
}
