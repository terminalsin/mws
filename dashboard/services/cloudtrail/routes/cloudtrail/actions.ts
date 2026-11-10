"use server";

import { CreateTrailCommand, DeleteTrailCommand, StartLoggingCommand, StopLoggingCommand } from "@aws-sdk/client-cloudtrail";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { bucketFrom, cloudTrailBucketPolicy } from "@mws-dashboard/aws/auto";

import { cloudtrail } from "../../lib/clients";

export async function createTrail(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const Name = required(form, "name", "Trail name");
    const client = await cloudtrail();
    await client.send(new CreateTrailCommand({ Name, S3BucketName: await bucketFrom(form, "bucket", "aws-cloudtrail-logs", cloudTrailBucketPolicy), IsMultiRegionTrail: text(form, "multi") === "on", IncludeGlobalServiceEvents: true }));
    await client.send(new StartLoggingCommand({ Name }));
    return `Trail ${Name} logging`;
  }, { revalidate: ["/cloudtrail"], fields: { Name: "name", InvalidTrailNameException: "name" } });
}

export async function setLogging(name: string, on: boolean) {
  return act(async () => {
    const client = await cloudtrail();
    if (on) await client.send(new StartLoggingCommand({ Name: name }));
    else await client.send(new StopLoggingCommand({ Name: name }));
    return on ? "Logging" : "Stopped";
  }, "/cloudtrail");
}

export async function deleteTrail(name: string) {
  return act(async () => {
    await (await cloudtrail()).send(new DeleteTrailCommand({ Name: name }));
    return "Trail deleted";
  }, "/cloudtrail");
}
