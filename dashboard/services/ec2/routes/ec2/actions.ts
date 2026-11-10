"use server";

import {
  AuthorizeSecurityGroupIngressCommand,
  CreateKeyPairCommand,
  CreateSecurityGroupCommand,
  CreateTagsCommand,
  DeleteKeyPairCommand,
  DeleteSecurityGroupCommand,
  RebootInstancesCommand,
  RevokeSecurityGroupIngressCommand,
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
    const count = Math.max(1, Number(text(form, "count") || 1));
    const sg = text(form, "securityGroup");
    const out = await (await ec2()).send(
      new RunInstancesCommand({
        ImageId: required(form, "image", "Image"),
        InstanceType: (text(form, "type") || "t3.micro") as _InstanceType,
        MinCount: count,
        MaxCount: count,
        KeyName: text(form, "keyName") || undefined,
        SecurityGroupIds: sg ? [sg] : undefined,
        UserData: text(form, "userData") ? Buffer.from(text(form, "userData")).toString("base64") : undefined,
        ...(name ? { TagSpecifications: [{ ResourceType: "instance", Tags: [{ Key: "Name", Value: name }] }] } : {}),
      }),
    );
    return `Launched ${out.Instances?.map((i) => i.InstanceId).join(", ")}`;
  }, "/ec2");
}

export async function changeState(id: string, to: "start" | "stop" | "reboot" | "terminate") {
  return act(
    async () => {
      const client = await ec2();
      const InstanceIds = [id];
      if (to === "start") await client.send(new StartInstancesCommand({ InstanceIds }));
      else if (to === "stop") await client.send(new StopInstancesCommand({ InstanceIds }));
      else if (to === "reboot") await client.send(new RebootInstancesCommand({ InstanceIds }));
      else await client.send(new TerminateInstancesCommand({ InstanceIds }));
      return { start: "Starting", stop: "Stopping", reboot: "Rebooting", terminate: "Terminating" }[to];
    },
    "/ec2",
    "/ec2/instance",
  );
}

export async function rename(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await ec2()).send(new CreateTagsCommand({ Resources: [id], Tags: [{ Key: "Name", Value: text(form, "name") }] }));
    return "Renamed";
  }, "/ec2/instance");
}

export async function createKeyPair(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await ec2()).send(
      new CreateKeyPairCommand({ KeyName: required(form, "name", "Name"), KeyType: text(form, "type") === "rsa" ? "rsa" : "ed25519" }),
    );
    return { ok: true, message: "Save the private key now: it is not shown again", detail: out.KeyMaterial };
  }, "/ec2");
}

export async function deleteKeyPair(name: string) {
  return act(async () => {
    await (await ec2()).send(new DeleteKeyPairCommand({ KeyName: name }));
    return `Deleted ${name}`;
  }, "/ec2");
}

export async function createSecurityGroup(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Name");
    await (await ec2()).send(
      new CreateSecurityGroupCommand({ GroupName: name, Description: text(form, "description") || name, VpcId: text(form, "vpc") || undefined }),
    );
    return `Created ${name}`;
  }, "/ec2");
}

export async function deleteSecurityGroup(id: string) {
  return act(async () => {
    await (await ec2()).send(new DeleteSecurityGroupCommand({ GroupId: id }));
    return "Deleted";
  }, "/ec2");
}

export async function allowIngress(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const [from, to] = required(form, "ports", "Ports").split("-").map((p) => Number(p.trim()));
    const protocol = text(form, "protocol") || "tcp";
    await (await ec2()).send(
      new AuthorizeSecurityGroupIngressCommand({
        GroupId: id,
        IpPermissions: [
          {
            IpProtocol: protocol,
            FromPort: protocol === "-1" ? undefined : from,
            ToPort: protocol === "-1" ? undefined : (to ?? from),
            IpRanges: [{ CidrIp: text(form, "cidr") || "0.0.0.0/0" }],
          },
        ],
      }),
    );
    return "Rule added";
  }, "/ec2");
}

export async function revokeIngress(id: string, ruleId: string) {
  return act(async () => {
    await (await ec2()).send(new RevokeSecurityGroupIngressCommand({ GroupId: id, SecurityGroupRuleIds: [ruleId] }));
    return "Rule removed";
  }, "/ec2");
}
