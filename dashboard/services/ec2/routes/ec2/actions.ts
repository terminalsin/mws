"use server";

import {
  AuthorizeSecurityGroupIngressCommand,
  CreateKeyPairCommand,
  CreateSecurityGroupCommand,
  CreateTagsCommand,
  DeleteKeyPairCommand,
  DescribeInstanceTypesCommand,
  DeleteSecurityGroupCommand,
  RebootInstancesCommand,
  RevokeSecurityGroupIngressCommand,
  RunInstancesCommand,
  StartInstancesCommand,
  StopInstancesCommand,
  TerminateInstancesCommand,
  type _InstanceType,
} from "@aws-sdk/client-ec2";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";

import { ec2 } from "../../lib/clients";

/** The instance types MWS runs, optionally for one architecture. */
async function instanceTypes(arch?: string) {
  const client = await ec2();
  const types: string[] = [];
  let NextToken: string | undefined;
  do {
    const page = await client.send(
      new DescribeInstanceTypesCommand({ NextToken, ...(arch ? { Filters: [{ Name: "processor-info.supported-architecture", Values: [arch] }] } : {}) }),
    );
    types.push(...(page.InstanceTypes ?? []).map((t) => t.InstanceType!));
    NextToken = page.NextToken;
  } while (NextToken);
  return types;
}

const LAUNCH_FIELDS = {
  ImageId: "image",
  InstanceType: "type",
  KeyName: "keyName",
  MinCount: "count",
  MaxCount: "count",
  "InvalidAMIID.NotFound": "image",
  "InvalidAMIID.Malformed": "image",
  "InvalidAMIID.Unavailable": "image",
  "InvalidKeyPair.NotFound": "keyName",
  "InvalidGroup.NotFound": "securityGroup",
  "InvalidGroupId.Malformed": "securityGroup",
};

export async function launch(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = text(form, "name");
    const count = Math.max(1, Number(text(form, "count") || 1));
    const sg = text(form, "securityGroup");
    const type = text(form, "type") || "t3.micro";
    const out = await (await ec2()).send(
      new RunInstancesCommand({
        ImageId: required(form, "image", "Image"),
        InstanceType: type as _InstanceType,
        MinCount: count,
        MaxCount: count,
        KeyName: text(form, "keyName") || undefined,
        SecurityGroupIds: sg ? [sg] : undefined,
        UserData: text(form, "userData") ? Buffer.from(text(form, "userData")).toString("base64") : undefined,
        ...(name ? { TagSpecifications: [{ ResourceType: "instance", Tags: [{ Key: "Name", Value: name }] }] } : {}),
      }),
    ).catch(async (e: Error) => {
      // The type and image disagree, or MWS does not run the type: point at
      // the types that would work, so the field can offer the closest.
      const arch = e.message.match(/does not match the architecture '([\w-]+)' of the specified AMI/)?.[1];
      if (arch) throw new FieldError("type", `This image needs an ${arch} type`, "server", { known: await instanceTypes(arch) });
      if (/for InstanceType/.test(e.message)) throw new FieldError("type", `${type} isn't available`, "server", { known: await instanceTypes() });
      throw e;
    });
    return `Launched ${out.Instances?.map((i) => i.InstanceId).join(", ")}`;
  }, { revalidate: ["/ec2"], fields: LAUNCH_FIELDS });
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
  }, { revalidate: ["/ec2/instance"], fields: { Value: "name", "Tags.Value": "name" } });
}

export async function createKeyPair(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await ec2()).send(
      new CreateKeyPairCommand({ KeyName: required(form, "name", "Name"), KeyType: text(form, "type") === "rsa" ? "rsa" : "ed25519" }),
    );
    return { ok: true, message: "Save the private key now: it is not shown again", detail: out.KeyMaterial };
  }, { revalidate: ["/ec2"], fields: { KeyName: "name" } });
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
    await (await ec2())
      .send(new CreateSecurityGroupCommand({ GroupName: name, Description: text(form, "description") || name, VpcId: text(form, "vpc") || undefined }))
      .catch((e: Error) => {
        if (/format sg-/.test(e.message)) throw new FieldError("name", "Can't start with sg-", "pattern");
        throw e;
      });
    return `Created ${name}`;
  }, { revalidate: ["/ec2"], fields: { GroupName: "name", groupDescription: "description", Description: "description", "InvalidVpcID.NotFound": "vpc", VPCIdNotSpecified: "vpc" } });
}

export async function deleteSecurityGroup(id: string) {
  return act(async () => {
    await (await ec2()).send(new DeleteSecurityGroupCommand({ GroupId: id }));
    return "Deleted";
  }, "/ec2");
}

export async function allowIngress(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const protocol = text(form, "protocol") || "tcp";
    // Every port when the protocol is "all"; otherwise one port or a range.
    const ports = protocol === "-1" ? "" : required(form, "ports", "Ports");
    const [from, to] = ports.split("-").map((p) => Number(p.trim()));
    const cidr = required(form, "cidr", "Source CIDR");
    await (await ec2()).send(
      new AuthorizeSecurityGroupIngressCommand({
        GroupId: id,
        IpPermissions: [
          {
            IpProtocol: protocol,
            FromPort: protocol === "-1" ? undefined : from,
            ToPort: protocol === "-1" ? undefined : (to ?? from),
            IpRanges: [{ CidrIp: cidr }],
          },
        ],
      }),
    ).catch((e: Error) => {
      if (e.name === "InvalidPermission.Duplicate") throw new FieldError("ports", "This group already allows it");
      if (/CIDR block .* is malformed/.test(e.message)) throw new FieldError("cidr", "Not a CIDR block", "format");
      throw e;
    });
    return "Rule added";
  }, { revalidate: ["/ec2"], fields: { portRange: "ports", CidrIp: "cidr" } });
}

export async function revokeIngress(id: string, ruleId: string) {
  return act(async () => {
    await (await ec2()).send(new RevokeSecurityGroupIngressCommand({ GroupId: id, SecurityGroupRuleIds: [ruleId] }));
    return "Rule removed";
  }, "/ec2");
}
