"use server";

import {
  CreateLaunchTemplateCommand,
  CreateLaunchTemplateVersionCommand,
  DeleteLaunchTemplateCommand,
  DeleteLaunchTemplateVersionsCommand,
  GetLaunchTemplateDataCommand,
  ModifyLaunchTemplateCommand,
  type RequestLaunchTemplateData,
  type ResponseLaunchTemplateData,
  type VolumeType,
  type _InstanceType,
} from "@aws-sdk/client-ec2";
import { act, checkFailures, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { LINKS, ec2 } from "../../lib/clients";

const PATHS = ["/ec2", "/ec2/launch-template"];
const FIELDS = {
  LaunchTemplateName: "name",
  VersionDescription: "description",
  "LaunchTemplateData.ImageId": "image",
  "LaunchTemplateData.InstanceType": "type",
  "InvalidLaunchTemplateName.AlreadyExistsException": "name",
  "InvalidLaunchTemplateName.MalformedException": "name",
  "InvalidAMIID.Malformed": "image",
  "InvalidAMIID.NotFound": "image",
  "InvalidKeyPair.NotFound": "keyName",
  "InvalidGroup.NotFound": "securityGroups",
};

/** The launch template data the form describes (blank fields left out). */
function templateData(form: FormData): RequestLaunchTemplateData {
  const groups = form.getAll("securityGroups").map(String).filter(Boolean);
  const profile = text(form, "iamProfile");
  const userData = text(form, "userData");
  const rootSize = Number(text(form, "rootSize")) || undefined;
  const rootType = (text(form, "rootType") || undefined) as VolumeType | undefined;
  const rootDevice = text(form, "rootDevice") || "/dev/xvda";
  const subnet = text(form, "subnet");
  const publicIp = text(form, "publicIp");
  const data: RequestLaunchTemplateData = {
    ImageId: text(form, "image") || undefined,
    InstanceType: (text(form, "type") || undefined) as _InstanceType | undefined,
    KeyName: text(form, "keyName") || undefined,
    // A subnet goes on the primary interface, which then carries the groups.
    ...(subnet
      ? { NetworkInterfaces: [{ DeviceIndex: 0, SubnetId: subnet, Groups: groups.length ? groups : undefined, AssociatePublicIpAddress: publicIp ? publicIp === "enable" : undefined }] }
      : { SecurityGroupIds: groups.length ? groups : undefined }),
    IamInstanceProfile: profile ? (profile.startsWith("arn:") ? { Arn: profile } : { Name: profile }) : undefined,
    BlockDeviceMappings: rootSize || rootType ? [{ DeviceName: rootDevice, Ebs: { VolumeSize: rootSize, VolumeType: rootType, DeleteOnTermination: true } }] : undefined,
    UserData: userData ? Buffer.from(userData).toString("base64") : undefined,
    Monitoring: form.get("monitoring") === "on" ? { Enabled: true } : undefined,
    DisableApiTermination: form.get("protect") === "on" || undefined,
    MetadataOptions: text(form, "tokens") ? { HttpTokens: text(form, "tokens") as "required" | "optional" } : undefined,
  };
  return Object.fromEntries(Object.entries(data).filter(([, v]) => v !== undefined)) as RequestLaunchTemplateData;
}

export async function createTemplate(_: ActionResult | null, form: FormData) {
  let id: string | undefined;
  const result = await act(async () => {
    const name = required(form, "name", "Name");
    const out = await (await ec2()).send(
      new CreateLaunchTemplateCommand({ LaunchTemplateName: name, VersionDescription: text(form, "description") || undefined, LaunchTemplateData: templateData(form) }),
    );
    id = out.LaunchTemplate?.LaunchTemplateId;
    return `Created ${name}`;
  }, { revalidate: PATHS, fields: FIELDS });
  if (result.ok && id && form.get("open") === "on") redirect(LINKS.template(id));
  return result;
}

/** A new version: the source version's data with the form's changes on top. */
export async function createVersion(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await ec2();
    const out = await client.send(
      new CreateLaunchTemplateVersionCommand({
        LaunchTemplateId: id,
        SourceVersion: text(form, "source") || undefined,
        VersionDescription: text(form, "description") || undefined,
        LaunchTemplateData: templateData(form),
      }),
    );
    const version = out.LaunchTemplateVersion?.VersionNumber;
    if (form.get("makeDefault") === "on" && version) await client.send(new ModifyLaunchTemplateCommand({ LaunchTemplateId: id, DefaultVersion: String(version) }));
    return `Version ${version} created`;
  }, { revalidate: PATHS, fields: { ...FIELDS, SourceVersion: "source" } });
}

export async function setDefaultVersion(id: string, version: number) {
  return act(async () => {
    await (await ec2()).send(new ModifyLaunchTemplateCommand({ LaunchTemplateId: id, DefaultVersion: String(version) }));
    return `Version ${version} is the default`;
  }, ...PATHS);
}

export async function deleteVersion(id: string, version: number) {
  return act(async () => {
    const out = await (await ec2()).send(new DeleteLaunchTemplateVersionsCommand({ LaunchTemplateId: id, Versions: [String(version)] }));
    checkFailures(out.UnsuccessfullyDeletedLaunchTemplateVersions, (f) => `Version ${f.VersionNumber}: ${f.ResponseError?.Message ?? f.ResponseError?.Code}`);
    return `Version ${version} deleted`;
  }, ...PATHS);
}

export async function deleteTemplate(id: string, back: boolean) {
  const result = await act(async () => {
    await (await ec2()).send(new DeleteLaunchTemplateCommand({ LaunchTemplateId: id }));
    return "Deleted";
  }, ...PATHS);
  if (result.ok && back) redirect("/ec2?tab=templates");
  return result;
}

/** Strip what GetLaunchTemplateData returns but CreateLaunchTemplate rejects
 * or should not copy (the instance's own network interface IDs and IPs). */
function reusable(data: ResponseLaunchTemplateData): RequestLaunchTemplateData {
  const { NetworkInterfaces, ...rest } = data;
  const interfaces = NetworkInterfaces?.map((n) => ({
    DeviceIndex: n.DeviceIndex,
    SubnetId: n.SubnetId,
    Groups: n.Groups,
    AssociatePublicIpAddress: n.AssociatePublicIpAddress,
    DeleteOnTermination: n.DeleteOnTermination,
    Description: n.Description,
  }));
  return { ...(rest as RequestLaunchTemplateData), ...(interfaces?.length ? { NetworkInterfaces: interfaces } : {}) };
}

/** A launch template with an instance's configuration (GetLaunchTemplateData). */
export async function templateFromInstance(instanceId: string, _: ActionResult | null, form: FormData) {
  let id: string | undefined;
  const result = await act(async () => {
    const client = await ec2();
    const name = required(form, "name", "Name");
    const data = (await client.send(new GetLaunchTemplateDataCommand({ InstanceId: instanceId }))).LaunchTemplateData;
    if (!data) throw new FieldError("name", "The instance has no launch data");
    const out = await client.send(
      new CreateLaunchTemplateCommand({ LaunchTemplateName: name, VersionDescription: `From ${instanceId}`, LaunchTemplateData: reusable(data) }),
    );
    id = out.LaunchTemplate?.LaunchTemplateId;
    return `Created ${name}`;
  }, { revalidate: PATHS, fields: FIELDS });
  if (result.ok && id) redirect(LINKS.template(id));
  return result;
}
