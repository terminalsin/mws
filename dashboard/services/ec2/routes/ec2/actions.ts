"use server";

import {
  AssociateIamInstanceProfileCommand,
  AuthorizeSecurityGroupEgressCommand,
  AuthorizeSecurityGroupIngressCommand,
  CreateKeyPairCommand,
  CreateSecurityGroupCommand,
  CreateTagsCommand,
  DeleteKeyPairCommand,
  DeleteSecurityGroupCommand,
  DeleteTagsCommand,
  DescribeIamInstanceProfileAssociationsCommand,
  DescribeImagesCommand,
  DescribeInstanceTypesCommand,
  DescribeTagsCommand,
  DisassociateIamInstanceProfileCommand,
  ImportKeyPairCommand,
  ModifyInstanceAttributeCommand,
  ModifyInstanceMetadataOptionsCommand,
  MonitorInstancesCommand,
  RebootInstancesCommand,
  ReplaceIamInstanceProfileAssociationCommand,
  RevokeSecurityGroupEgressCommand,
  RevokeSecurityGroupIngressCommand,
  RunInstancesCommand,
  StartInstancesCommand,
  StopInstancesCommand,
  TerminateInstancesCommand,
  UnmonitorInstancesCommand,
  type BlockDeviceMapping,
  type HttpTokensState,
  type InstanceMetadataEndpointState,
  type InstanceMetadataTagsState,
  type IpPermission,
  type RunInstancesCommandInput,
  type VolumeType,
  type _InstanceType,
} from "@aws-sdk/client-ec2";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

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

/** Explain a type the image or MWS cannot run, on the type field. */
async function typeError(e: Error, type: string, field = "type"): Promise<never> {
  const arch = e.message.match(/does not match the architecture '([\w-]+)' of the specified AMI/)?.[1];
  if (arch) throw new FieldError(field, `This image needs an ${arch} type`, "server", { known: await instanceTypes(arch) });
  if (/for InstanceType/.test(e.message)) throw new FieldError(field, `${type} isn't available`, "server", { known: await instanceTypes() });
  throw e;
}

const LAUNCH_FIELDS = {
  ImageId: "image",
  InstanceType: "type",
  KeyName: "keyName",
  MinCount: "count",
  MaxCount: "count",
  SubnetId: "subnet",
  "InvalidAMIID.NotFound": "image",
  "InvalidAMIID.Malformed": "image",
  "InvalidAMIID.Unavailable": "image",
  "InvalidKeyPair.NotFound": "keyName",
  "InvalidGroup.NotFound": "securityGroups",
  "InvalidGroupId.Malformed": "securityGroups",
  "InvalidSubnetID.NotFound": "subnet",
  "InvalidParameterCombination": "securityGroups",
  "InvalidLaunchTemplateId.NotFound": "launchTemplate",
  "InvalidLaunchTemplateName.NotFoundException": "launchTemplate",
  "InvalidParameterValue": "iamProfile",
  "InvalidBlockDeviceMapping": "rootSize",
};

/** `key=value` lines as EC2 tags. */
function tagLines(value: string) {
  return value
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const at = l.indexOf("=");
      return at < 0 ? { Key: l, Value: "" } : { Key: l.slice(0, at).trim(), Value: l.slice(at + 1).trim() };
    });
}

export async function launch(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await ec2();
    const name = text(form, "name");
    const count = Math.max(1, Number(text(form, "count") || 1));
    const template = text(form, "launchTemplate");
    const image = template ? text(form, "image") : required(form, "image", "Image");
    const type = text(form, "type") || (template ? "" : "t3.micro");
    const groups = form.getAll("securityGroups").map(String).filter(Boolean);
    const subnet = text(form, "subnet");
    const publicIp = text(form, "publicIp");
    const profile = text(form, "iamProfile");
    const rootSize = Number(text(form, "rootSize")) || undefined;
    const rootType = text(form, "rootType") as VolumeType | "";
    const userData = text(form, "userData");

    // The root volume: the image's root device, resized or retyped.
    let BlockDeviceMappings: BlockDeviceMapping[] | undefined;
    if (image && (rootSize || rootType)) {
      const img = (await client.send(new DescribeImagesCommand({ ImageIds: [image] })).catch(() => undefined))?.Images?.[0];
      const root = img?.RootDeviceName ?? "/dev/xvda";
      const snapshot = img?.BlockDeviceMappings?.find((b) => b.DeviceName === root)?.Ebs;
      if (rootSize && snapshot?.VolumeSize && rootSize < snapshot.VolumeSize)
        throw new FieldError("rootSize", `The image's snapshot needs at least ${snapshot.VolumeSize} GiB`, "range", { min: snapshot.VolumeSize });
      BlockDeviceMappings = [{ DeviceName: root, Ebs: { VolumeSize: rootSize, VolumeType: rootType || undefined, DeleteOnTermination: true } }];
    }

    // A public IP choice needs a network interface spec, which then carries
    // the subnet and groups.
    const network: Partial<RunInstancesCommandInput> =
      publicIp && subnet
        ? { NetworkInterfaces: [{ DeviceIndex: 0, SubnetId: subnet, Groups: groups.length ? groups : undefined, AssociatePublicIpAddress: publicIp === "enable" }] }
        : { SubnetId: subnet || undefined, SecurityGroupIds: groups.length ? groups : undefined };
    if (publicIp && !subnet) throw new FieldError("subnet", "Pick a subnet to choose the public IP", "required");

    const out = await client
      .send(
        new RunInstancesCommand({
          ImageId: image || undefined,
          InstanceType: (type || undefined) as _InstanceType | undefined,
          MinCount: count,
          MaxCount: count,
          KeyName: text(form, "keyName") || undefined,
          ...network,
          ...(template ? { LaunchTemplate: { LaunchTemplateId: template, Version: text(form, "templateVersion") || "$Default" } } : {}),
          IamInstanceProfile: profile ? (profile.startsWith("arn:") ? { Arn: profile } : { Name: profile }) : undefined,
          BlockDeviceMappings,
          InstanceMarketOptions: text(form, "spot") === "on" ? { MarketType: "spot" } : undefined,
          Monitoring: text(form, "monitoring") === "on" ? { Enabled: true } : undefined,
          DisableApiTermination: text(form, "protect") === "on" ? true : undefined,
          UserData: userData ? Buffer.from(userData).toString("base64") : undefined,
          ...(name ? { TagSpecifications: [{ ResourceType: "instance", Tags: [{ Key: "Name", Value: name }] }] } : {}),
        }),
      )
      .catch((e: Error) => typeError(e, type));
    return `Launched ${out.Instances?.map((i) => i.InstanceId).join(", ")}`;
  }, { revalidate: ["/ec2"], fields: LAUNCH_FIELDS });
}

export async function changeState(id: string, to: "start" | "stop" | "reboot" | "terminate" | "hibernate" | "force-stop") {
  return act(
    async () => {
      const client = await ec2();
      const InstanceIds = [id];
      if (to === "start") await client.send(new StartInstancesCommand({ InstanceIds }));
      else if (to === "stop") await client.send(new StopInstancesCommand({ InstanceIds }));
      else if (to === "force-stop") await client.send(new StopInstancesCommand({ InstanceIds, Force: true }));
      else if (to === "hibernate") await client.send(new StopInstancesCommand({ InstanceIds, Hibernate: true }));
      else if (to === "reboot") await client.send(new RebootInstancesCommand({ InstanceIds }));
      else await client.send(new TerminateInstancesCommand({ InstanceIds }));
      return { start: "Starting", stop: "Stopping", "force-stop": "Stopping", hibernate: "Hibernating", reboot: "Rebooting", terminate: "Terminating" }[to];
    },
    "/ec2",
    "/ec2/instance",
  );
}

export async function rename(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await ec2()).send(new CreateTagsCommand({ Resources: [id], Tags: [{ Key: "Name", Value: text(form, "name") }] }));
    return "Renamed";
  }, { revalidate: ["/ec2", "/ec2/instance", "/ec2/volume", "/ec2/image", "/ec2/group"], fields: { Value: "name", "Tags.Value": "name" } });
}

/** Replace a resource's tags with the form's `key=value` lines: CreateTags
 * for new and changed ones, DeleteTags for the ones removed. */
export async function saveTags(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await ec2();
    const wanted = tagLines(text(form, "tags"));
    const keep = form.get("keepName") === "on";
    const current = (await client.send(new DescribeTagsCommand({ Filters: [{ Name: "resource-id", Values: [id] }] }))).Tags ?? [];
    const removed = current.filter((t) => !wanted.some((w) => w.Key === t.Key) && !(keep && t.Key === "Name"));
    const changed = wanted.filter((w) => !current.some((t) => t.Key === w.Key && (t.Value ?? "") === w.Value));
    if (removed.length) await client.send(new DeleteTagsCommand({ Resources: [id], Tags: removed.map((t) => ({ Key: t.Key })) }));
    if (changed.length) await client.send(new CreateTagsCommand({ Resources: [id], Tags: changed }));
    return removed.length || changed.length ? "Tags saved" : "No changes";
  }, { revalidate: ["/ec2", "/ec2/instance", "/ec2/volume", "/ec2/image", "/ec2/group", "/ec2/launch-template"], fields: { Tags: "tags", Key: "tags", Value: "tags", "Tag.Key": "tags", InvalidParameterValue: "tags" } });
}

// ---------------------------------------------------------------------------
// Instance settings.

const INSTANCE_PATHS = ["/ec2", "/ec2/instance"];

export async function changeInstanceType(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const type = required(form, "type", "Instance type");
    await (await ec2()).send(new ModifyInstanceAttributeCommand({ InstanceId: id, InstanceType: { Value: type } })).catch((e: Error) => typeError(e, type));
    return `Changed to ${type}`;
  }, { revalidate: INSTANCE_PATHS, fields: { InstanceType: "type", IncorrectInstanceState: "type" } });
}

export async function changeProtection(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await ec2();
    const InstanceId = id;
    await client.send(new ModifyInstanceAttributeCommand({ InstanceId, DisableApiTermination: { Value: form.get("termination") === "on" } }));
    await client.send(new ModifyInstanceAttributeCommand({ InstanceId, DisableApiStop: { Value: form.get("stop") === "on" } }));
    const behavior = text(form, "shutdown");
    if (behavior) await client.send(new ModifyInstanceAttributeCommand({ InstanceId, InstanceInitiatedShutdownBehavior: { Value: behavior } }));
    return "Saved";
  }, ...INSTANCE_PATHS);
}

export async function changeUserData(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const value = text(form, "userData");
    // The attribute takes the raw bytes: the SDK base64-encodes the blob.
    await (await ec2()).send(new ModifyInstanceAttributeCommand({ InstanceId: id, UserData: { Value: new TextEncoder().encode(value) } }));
    return "User data saved";
  }, { revalidate: INSTANCE_PATHS, fields: { UserData: "userData", IncorrectInstanceState: "userData" } });
}

export async function changeGroups(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const groups = form.getAll("securityGroups").map(String).filter(Boolean);
    if (!groups.length) throw new FieldError("securityGroups", "Pick at least one group", "required");
    await (await ec2()).send(new ModifyInstanceAttributeCommand({ InstanceId: id, Groups: groups }));
    return "Security groups changed";
  }, { revalidate: INSTANCE_PATHS, fields: { Groups: "securityGroups", "InvalidGroup.NotFound": "securityGroups" } });
}

export async function changeMetadata(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const hop = Number(text(form, "hopLimit")) || undefined;
    await (await ec2()).send(
      new ModifyInstanceMetadataOptionsCommand({
        InstanceId: id,
        HttpEndpoint: (text(form, "endpoint") || undefined) as InstanceMetadataEndpointState | undefined,
        HttpTokens: (text(form, "tokens") || undefined) as HttpTokensState | undefined,
        HttpPutResponseHopLimit: hop,
        InstanceMetadataTags: (text(form, "tags") || undefined) as InstanceMetadataTagsState | undefined,
      }),
    );
    return "Metadata options saved";
  }, { revalidate: INSTANCE_PATHS, fields: { HttpPutResponseHopLimit: "hopLimit", HttpTokens: "tokens", HttpEndpoint: "endpoint" } });
}

export async function changeMonitoring(id: string, enable: boolean) {
  return act(async () => {
    const client = await ec2();
    if (enable) await client.send(new MonitorInstancesCommand({ InstanceIds: [id] }));
    else await client.send(new UnmonitorInstancesCommand({ InstanceIds: [id] }));
    return enable ? "Detailed monitoring on" : "Detailed monitoring off";
  }, ...INSTANCE_PATHS);
}

/** Attach, replace or remove the instance's IAM instance profile. */
export async function changeInstanceProfile(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await ec2();
    const profile = text(form, "iamProfile");
    const current = (
      await client.send(new DescribeIamInstanceProfileAssociationsCommand({ Filters: [{ Name: "instance-id", Values: [id] }] }))
    ).IamInstanceProfileAssociations?.find((a) => a.State === "associated" || a.State === "associating");
    const IamInstanceProfile = profile.startsWith("arn:") ? { Arn: profile } : { Name: profile };
    if (!profile) {
      if (!current) return "No IAM role";
      await client.send(new DisassociateIamInstanceProfileCommand({ AssociationId: current.AssociationId }));
      return "IAM role removed";
    }
    if (current) await client.send(new ReplaceIamInstanceProfileAssociationCommand({ AssociationId: current.AssociationId, IamInstanceProfile }));
    else await client.send(new AssociateIamInstanceProfileCommand({ InstanceId: id, IamInstanceProfile }));
    return "IAM role changed";
  }, { revalidate: INSTANCE_PATHS, fields: { IamInstanceProfile: "iamProfile", InvalidParameterValue: "iamProfile", NoSuchEntity: "iamProfile" } });
}

// ---------------------------------------------------------------------------
// Key pairs.

export async function createKeyPair(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await ec2()).send(
      new CreateKeyPairCommand({ KeyName: required(form, "name", "Name"), KeyType: text(form, "type") === "rsa" ? "rsa" : "ed25519" }),
    );
    return { ok: true, message: "Save the private key now: it is not shown again", detail: out.KeyMaterial };
  }, { revalidate: ["/ec2"], fields: { KeyName: "name" } });
}

export async function importKeyPair(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Name");
    await (await ec2()).send(new ImportKeyPairCommand({ KeyName: name, PublicKeyMaterial: new TextEncoder().encode(required(form, "publicKey", "Public key")) }));
    return `Imported ${name}`;
  }, { revalidate: ["/ec2"], fields: { KeyName: "name", PublicKeyMaterial: "publicKey", "InvalidKey.Format": "publicKey", InvalidKeyFormat: "publicKey" } });
}

export async function deleteKeyPair(name: string) {
  return act(async () => {
    await (await ec2()).send(new DeleteKeyPairCommand({ KeyName: name }));
    return `Deleted ${name}`;
  }, "/ec2");
}

// ---------------------------------------------------------------------------
// Security groups.

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

/** Delete a group; `back` (from its own page) is where to go after. */
export async function deleteSecurityGroup(id: string, back?: unknown) {
  const result = await act(async () => {
    await (await ec2()).send(new DeleteSecurityGroupCommand({ GroupId: id }));
    return "Deleted";
  }, "/ec2");
  if (result.ok && typeof back === "string") redirect(back);
  return result;
}

/** "443", "8000-8080", or every port for the "all" protocol (and ICMP's -1). */
function portRange(form: FormData, protocol: string) {
  if (protocol === "-1") return { FromPort: undefined, ToPort: undefined };
  if (protocol === "icmp") {
    // ICMP takes a type and code ("8-0" is echo request), -1 for all.
    const m = text(form, "ports").match(/^(-?\d+)(?:-(-?\d+))?$/);
    return m ? { FromPort: Number(m[1]), ToPort: m[2] === undefined ? -1 : Number(m[2]) } : { FromPort: -1, ToPort: -1 };
  }
  const ports = required(form, "ports", "Ports");
  const [from, to] = ports.split("-").map((p) => Number(p.trim()));
  return { FromPort: from, ToPort: to ?? from };
}

const RULE_PATHS = ["/ec2", "/ec2/group"];
const RULE_FIELDS = { portRange: "ports", CidrIp: "cidr", CidrIpv6: "cidr6", GroupId: "group", PrefixListId: "prefixList", Description: "description", "InvalidGroup.NotFound": "group", "InvalidPrefixListID.NotFound": "prefixList" };

function ruleError(e: Error): never {
  if (e.name === "InvalidPermission.Duplicate") throw new FieldError("ports", "This group already allows it");
  if (/CIDR block .* is malformed/.test(e.message)) throw new FieldError("cidr", "Not a CIDR block", "format");
  throw e;
}

export async function allowIngress(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const protocol = text(form, "protocol") || "tcp";
    const cidr = required(form, "cidr", "Source CIDR");
    await (await ec2())
      .send(new AuthorizeSecurityGroupIngressCommand({ GroupId: id, IpPermissions: [{ IpProtocol: protocol, ...portRange(form, protocol), IpRanges: [{ CidrIp: cidr }] }] }))
      .catch(ruleError);
    return "Rule added";
  }, { revalidate: RULE_PATHS, fields: RULE_FIELDS });
}

/** An inbound or outbound rule to or from a CIDR block (v4 or v6), another
 * security group or a managed prefix list. */
export async function addRule(id: string, direction: "ingress" | "egress", _: ActionResult | null, form: FormData) {
  return act(async () => {
    const protocol = text(form, "protocol") || "tcp";
    const kind = text(form, "peer") || "cidr";
    const Description = text(form, "description") || undefined;
    const permission: IpPermission = { IpProtocol: protocol, ...portRange(form, protocol) };
    if (kind === "group") permission.UserIdGroupPairs = [{ GroupId: required(form, "group", "Security group"), Description }];
    else if (kind === "prefixList") permission.PrefixListIds = [{ PrefixListId: required(form, "prefixList", "Prefix list"), Description }];
    else if (kind === "cidr6") permission.Ipv6Ranges = [{ CidrIpv6: required(form, "cidr6", direction === "ingress" ? "Source" : "Destination"), Description }];
    else permission.IpRanges = [{ CidrIp: required(form, "cidr", direction === "ingress" ? "Source" : "Destination"), Description }];
    const client = await ec2();
    const input = { GroupId: id, IpPermissions: [permission] };
    await (direction === "ingress" ? client.send(new AuthorizeSecurityGroupIngressCommand(input)) : client.send(new AuthorizeSecurityGroupEgressCommand(input))).catch(ruleError);
    return "Rule added";
  }, { revalidate: RULE_PATHS, fields: RULE_FIELDS });
}

export async function revokeRule(id: string, direction: "ingress" | "egress", ruleId: string) {
  return act(async () => {
    const client = await ec2();
    const input = { GroupId: id, SecurityGroupRuleIds: [ruleId] };
    if (direction === "ingress") await client.send(new RevokeSecurityGroupIngressCommand(input));
    else await client.send(new RevokeSecurityGroupEgressCommand(input));
    return "Rule removed";
  }, ...RULE_PATHS);
}

export async function revokeIngress(id: string, ruleId: string) {
  return revokeRule(id, "ingress", ruleId);
}
