import type { Finding } from "@aws-sdk/client-guardduty";

import { RESOURCE_ICON } from "./clients";

export interface Affected {
  icon: string;
  kind: string;
  name: string;
  href?: string;
  detail?: string;
}

const enc = encodeURIComponent;

/** The resources a finding is about, linked to their consoles. Sample
 * findings name placeholder resources (`GeneratedFindingInstanceId`); their
 * links lead to an empty page, as AWS's do. */
export function affected(f: Finding): Affected[] {
  const r = f.Resource ?? {};
  const out: Affected[] = [];
  const i = r.InstanceDetails;
  if (i?.InstanceId) out.push({ icon: RESOURCE_ICON.Instance, kind: "EC2 instance", name: i.InstanceId, href: `/ec2/instance?id=${enc(i.InstanceId)}`, detail: [i.InstanceType, i.Platform, i.ImageId].filter(Boolean).join(" · ") });
  const k = r.AccessKeyDetails;
  if (k?.AccessKeyId || k?.UserName) {
    const href = k.UserType === "IAMUser" && k.UserName ? `/iam/users/${enc(k.UserName)}` : k.UserType === "AssumedRole" && k.UserName ? `/iam/roles/${enc(k.UserName)}` : undefined;
    out.push({ icon: RESOURCE_ICON.AccessKey, kind: k.UserType ?? "Access key", name: k.UserName ?? k.AccessKeyId!, href, detail: k.AccessKeyId });
  }
  for (const b of r.S3BucketDetails ?? []) {
    if (b.Name) out.push({ icon: RESOURCE_ICON.S3Bucket, kind: "S3 bucket", name: b.Name, href: `/s3/${enc(b.Name)}`, detail: b.PublicAccess?.EffectivePermission ? `${b.PublicAccess.EffectivePermission.toLowerCase().replace(/_/g, " ")}` : undefined });
  }
  for (const o of r.S3BucketDetails?.flatMap((b) => (b.S3ObjectDetails ?? []).map((o) => ({ ...o, bucket: b.Name }))) ?? []) {
    if (o.Key && o.bucket) out.push({ icon: RESOURCE_ICON.S3Object, kind: "S3 object", name: o.Key, href: `/s3/${enc(o.bucket)}/object?key=${enc(o.Key)}`, detail: o.Hash });
  }
  const e = r.EksClusterDetails;
  if (e?.Name) out.push({ icon: RESOURCE_ICON.EKSCluster, kind: "EKS cluster", name: e.Name, href: `/eks/cluster?name=${enc(e.Name)}` });
  const l = r.LambdaDetails;
  if (l?.FunctionName) out.push({ icon: RESOURCE_ICON.Lambda, kind: "Lambda function", name: l.FunctionName, href: `/lambda/${enc(l.FunctionName)}`, detail: l.Role });
  const d = r.RdsDbInstanceDetails;
  if (d?.DbInstanceIdentifier) out.push({ icon: RESOURCE_ICON.RDSDBInstance, kind: "RDS instance", name: d.DbInstanceIdentifier, href: `/rds/db?id=${enc(d.DbInstanceIdentifier)}`, detail: d.Engine });
  const c = r.EcsClusterDetails;
  if (c?.Name) out.push({ icon: RESOURCE_ICON.ECSCluster, kind: "ECS cluster", name: c.Name, href: `/ecs/cluster?name=${enc(c.Name)}`, detail: c.TaskDetails?.Arn });
  const v = r.EbsVolumeDetails;
  for (const vol of [...(v?.ScannedVolumeDetails ?? []), ...(v?.SkippedVolumeDetails ?? [])]) {
    if (vol.VolumeArn) out.push({ icon: RESOURCE_ICON.EBSVolume, kind: "EBS volume", name: vol.VolumeArn.split("/").pop()!, detail: vol.DeviceName });
  }
  if (r.ContainerDetails?.Name) out.push({ icon: RESOURCE_ICON.Container, kind: "Container", name: r.ContainerDetails.Name, detail: r.ContainerDetails.Image });
  return out;
}

/** Who or what acted, in one line: the remote IP and where it is, the API
 * called, the domain asked for. */
export function actor(f: Finding): [string, string][] {
  const a = f.Service?.Action;
  if (!a) return [];
  const out: [string, string][] = [["Action", a.ActionType ?? ""]];
  const n = a.NetworkConnectionAction;
  if (n) {
    out.push(["Direction", n.ConnectionDirection ?? ""]);
    if (n.RemoteIpDetails?.IpAddressV4) out.push(["Remote IP", [n.RemoteIpDetails.IpAddressV4, n.RemoteIpDetails.Country?.CountryName, n.RemoteIpDetails.Organization?.Org].filter(Boolean).join(" · ")]);
    if (n.RemotePortDetails?.Port) out.push(["Remote port", `${n.RemotePortDetails.Port} ${n.RemotePortDetails.PortName ?? ""}`.trim()]);
    if (n.LocalPortDetails?.Port) out.push(["Local port", `${n.LocalPortDetails.Port} ${n.LocalPortDetails.PortName ?? ""}`.trim()]);
    if (n.Protocol) out.push(["Protocol", n.Protocol]);
  }
  const api = a.AwsApiCallAction;
  if (api) {
    out.push(["API", [api.ServiceName, api.Api].filter(Boolean).join(" ")]);
    if (api.CallerType) out.push(["Caller", api.CallerType]);
    if (api.RemoteIpDetails?.IpAddressV4) out.push(["Remote IP", [api.RemoteIpDetails.IpAddressV4, api.RemoteIpDetails.Country?.CountryName, api.RemoteIpDetails.Organization?.Org].filter(Boolean).join(" · ")]);
    if (api.ErrorCode) out.push(["Error", api.ErrorCode]);
  }
  if (a.DnsRequestAction?.Domain) out.push(["Domain", `${a.DnsRequestAction.Domain}${a.DnsRequestAction.Blocked ? " (blocked)" : ""}`]);
  const p = a.PortProbeAction;
  if (p) for (const d of p.PortProbeDetails ?? []) out.push(["Probed", `${d.LocalPortDetails?.Port ?? ""} from ${d.RemoteIpDetails?.IpAddressV4 ?? "?"}`]);
  if (a.KubernetesApiCallAction) out.push(["Kubernetes API", [a.KubernetesApiCallAction.Verb, a.KubernetesApiCallAction.RequestUri].filter(Boolean).join(" ")]);
  if (a.RdsLoginAttemptAction?.RemoteIpDetails?.IpAddressV4) out.push(["Remote IP", a.RdsLoginAttemptAction.RemoteIpDetails.IpAddressV4]);
  return out.filter(([, v]) => v);
}
