"use server";

import {
  RebootInstancesCommand,
  RunInstancesCommand,
  StartInstancesCommand,
  StopInstancesCommand,
  TerminateInstancesCommand,
  type _InstanceType,
} from "@aws-sdk/client-ec2";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";

import { ec2 } from "../../lib/clients";

export async function launch(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = text(form, "name");
    const out = await (await ec2()).send(
      new RunInstancesCommand({
        ImageId: required(form, "image", "Image ID"),
        InstanceType: (text(form, "type") || "t3.micro") as _InstanceType,
        MinCount: 1,
        MaxCount: 1,
        ...(name ? { TagSpecifications: [{ ResourceType: "instance", Tags: [{ Key: "Name", Value: name }] }] } : {}),
      }),
    );
    return `Launched ${out.Instances?.map((i) => i.InstanceId).join(", ")}`;
  }, "/ec2");
}

export async function changeState(id: string, to: "start" | "stop" | "reboot" | "terminate") {
  return act(async () => {
    const client = await ec2();
    const InstanceIds = [id];
    if (to === "start") await client.send(new StartInstancesCommand({ InstanceIds }));
    else if (to === "stop") await client.send(new StopInstancesCommand({ InstanceIds }));
    else if (to === "reboot") await client.send(new RebootInstancesCommand({ InstanceIds }));
    else await client.send(new TerminateInstancesCommand({ InstanceIds }));
    return `${to} requested for ${id}`;
  }, "/ec2");
}
