"use server";

import { CreateLogGroupCommand, DescribeLogGroupsCommand, PutResourcePolicyCommand } from "@aws-sdk/client-cloudwatch-logs";
import { CreateKeyCommand } from "@aws-sdk/client-kms";
import {
  ActivateKeySigningKeyCommand,
  AssociateVPCWithHostedZoneCommand,
  ChangeResourceRecordSetsCommand,
  ChangeTagsForResourceCommand,
  CreateHealthCheckCommand,
  CreateHostedZoneCommand,
  CreateKeySigningKeyCommand,
  CreateQueryLoggingConfigCommand,
  CreateVPCAssociationAuthorizationCommand,
  DeactivateKeySigningKeyCommand,
  DeleteHealthCheckCommand,
  DeleteHostedZoneCommand,
  DeleteKeySigningKeyCommand,
  DeleteQueryLoggingConfigCommand,
  DeleteVPCAssociationAuthorizationCommand,
  DisableHostedZoneDNSSECCommand,
  DisassociateVPCFromHostedZoneCommand,
  EnableHostedZoneDNSSECCommand,
  GetHealthCheckCommand,
  TestDNSAnswerCommand,
  UpdateHealthCheckCommand,
  UpdateHostedZoneCommentCommand,
  type Change,
  type HealthCheckConfig,
  type HealthCheckRegion,
  type InsufficientDataHealthStatus,
  type ResourceRecordSet,
  type RRType,
  type VPCRegion,
} from "@aws-sdk/client-route-53";
import { act, FieldError, frameInfo, region, required, text, type ActionResult } from "@mws-dashboard/aws";
import { AUTO } from "@mws-dashboard/aws/auto";
import { redirect } from "next/navigation";

import { parseGeo, recordName } from "../../lib/choices";
import { kmsUsEast1, logsUsEast1, route53, zoneHref } from "../../lib/clients";
import { changeBatchField } from "../../lib/records";

export async function createZone(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const Name = required(form, "name", "Domain name");
    const vpc = text(form, "vpc");
    const out = await (await route53()).send(
      new CreateHostedZoneCommand({
        Name,
        CallerReference: `console-${Date.now()}`,
        HostedZoneConfig: { PrivateZone: !!vpc, Comment: text(form, "comment") || undefined },
        VPC: vpc ? { VPCId: vpc, VPCRegion: (await region()) as VPCRegion } : undefined,
        DelegationSetId: text(form, "delegationSet") || undefined,
      }),
    );
    redirect(zoneHref(out.HostedZone!.Id));
  }, { fields: { Name: "name", InvalidDomainName: "name", ConflictingDomainExists: "name", "HostedZoneConfig.Comment": "comment", InvalidVPCId: "vpc", NoSuchDelegationSet: "delegationSet" } });
}

export async function deleteZone(id: string) {
  return act(async () => {
    await (await route53()).send(new DeleteHostedZoneCommand({ Id: id }));
    redirect("/route53");
  });
}

export async function updateComment(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await route53()).send(new UpdateHostedZoneCommentCommand({ Id: id, Comment: text(form, "comment") }));
    return "Description saved";
  }, { revalidate: ["/route53/zone", "/route53"], fields: { Comment: "comment" } });
}

const int = (form: FormData, name: string, label: string) => {
  const v = required(form, name, label);
  if (!/^-?\d+$/.test(v)) throw new FieldError(name, "A whole number", "format");
  return Number(v);
};

/** The record set the form describes: values or an alias, plus its routing policy. */
function recordFrom(zone: string, form: FormData): ResourceRecordSet {
  const Name = required(form, "name", "Record name");
  const Type = required(form, "type", "Type") as RRType;
  const policy = text(form, "policy") || "simple";
  const alias = form.get("aliasOn") === "on" && policy !== "multivalue";
  const set: ResourceRecordSet = alias
    ? {
        Name,
        Type,
        AliasTarget: {
          DNSName: required(form, "alias", "Alias target"),
          HostedZoneId: text(form, "aliasZone") || zone,
          EvaluateTargetHealth: form.get("evaluate") === "on",
        },
      }
    : {
        Name,
        Type,
        TTL: Number(text(form, "ttl") || 300),
        ResourceRecords: required(form, "values", "Value")
          .split("\n")
          .map((v) => v.trim())
          .filter(Boolean)
          .map((Value) => ({ Value })),
      };
  if (policy !== "simple") set.SetIdentifier = required(form, "setId", "Record ID");
  if (policy === "weighted") set.Weight = int(form, "weight", "Weight");
  if (policy === "latency") set.Region = required(form, "region", "Region") as ResourceRecordSet["Region"];
  if (policy === "failover") set.Failover = (text(form, "failover") || "PRIMARY") as "PRIMARY" | "SECONDARY";
  if (policy === "geo") set.GeoLocation = parseGeo(text(form, "geo") || "*");
  if (policy === "multivalue") set.MultiValueAnswer = true;
  if (policy === "cidr") set.CidrRoutingConfig = { CollectionId: required(form, "cidrCollection", "CIDR collection"), LocationName: required(form, "cidrLocation", "CIDR location") };
  const health = text(form, "healthCheck");
  if (health) set.HealthCheckId = health;
  return set;
}

const same = (a: ResourceRecordSet, b: ResourceRecordSet) =>
  recordName(a.Name).toLowerCase() === recordName(b.Name).toLowerCase() && a.Type === b.Type && (a.SetIdentifier ?? "") === (b.SetIdentifier ?? "");

/** Create a record set, or replace `original`: in place (UPSERT) when its
 * name, type and set identifier stay, else by deleting it and creating the
 * new one in the same batch, so a rename leaves nothing behind. */
export async function saveRecord(zone: string, original: ResourceRecordSet | null, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const set = recordFrom(zone, form);
    const Changes: Change[] =
      original && !same(original, set)
        ? [
            { Action: "DELETE", ResourceRecordSet: original },
            { Action: "CREATE", ResourceRecordSet: set },
          ]
        : [{ Action: original ? "UPSERT" : "CREATE", ResourceRecordSet: set }];
    let status: string | undefined;
    try {
      const out = await (await route53()).send(new ChangeResourceRecordSetsCommand({ HostedZoneId: zone, ChangeBatch: { Changes } }));
      status = out.ChangeInfo?.Status;
    } catch (e) {
      // InvalidChangeBatch names no member; its message says which part.
      const at = e instanceof Error && e.name === "InvalidChangeBatch" ? changeBatchField(e.message) : null;
      throw at ? new FieldError(at.field, at.message) : e;
    }
    return `Saved ${set.Name} ${set.Type}${status ? ` · ${status.toLowerCase()}` : ""}`;
  }, {
    revalidate: ["/route53/zone"],
    fields: {
      Name: "name",
      Type: "type",
      TTL: "ttl",
      "AliasTarget.DNSName": "alias",
      "AliasTarget.HostedZoneId": "aliasZone",
      SetIdentifier: "setId",
      Weight: "weight",
      HealthCheckId: "healthCheck",
      NoSuchHealthCheck: "healthCheck",
      NoSuchCidrCollectionException: "cidrCollection",
      NoSuchCidrLocationException: "cidrLocation",
      InvalidChangeBatch: "values",
    },
  });
}

export async function deleteRecord(zone: string, set: ResourceRecordSet) {
  return act(async () => {
    await (await route53()).send(new ChangeResourceRecordSetsCommand({ HostedZoneId: zone, ChangeBatch: { Changes: [{ Action: "DELETE", ResourceRecordSet: set }] } }));
    return `Deleted ${set.Name} ${set.Type}`;
  }, "/route53/zone");
}

export async function testAnswer(zone: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await route53()).send(
      new TestDNSAnswerCommand({
        HostedZoneId: zone,
        RecordName: required(form, "name", "Record name"),
        RecordType: required(form, "type", "Type") as RRType,
        ResolverIP: text(form, "resolver") || undefined,
        EDNS0ClientSubnetIP: text(form, "subnet") || undefined,
      }),
    );
    const answers = out.RecordData?.length ? out.RecordData.join("\n") : "(no answer)";
    return { ok: true, message: `${out.ResponseCode} · ${out.Protocol}`, detail: answers };
  }, { fields: { RecordName: "name", RecordType: "type", ResolverIP: "resolver", EDNS0ClientSubnetIP: "subnet" } });
}

// ---------------------------------------------------------------------------
// Health checks.

const lines = (v: string) => v.split(/[\s,]+/).filter(Boolean);

/** The health check the form describes (create, or the fields an update may change). */
function healthConfig(form: FormData): HealthCheckConfig {
  // "http" covers HTTP(S), with or without a string to match: the URL and
  // search string say which.
  const Type = (text(form, "kind") || "http") as HealthCheckConfig["Type"] | "http";
  const common = {
    Inverted: form.get("inverted") === "on",
    Disabled: form.get("disabled") === "on",
  };
  if (Type === "CALCULATED") {
    const children = form.getAll("children").filter((v): v is string => typeof v === "string");
    return { Type, ...common, ChildHealthChecks: children, HealthThreshold: Number(text(form, "healthThreshold") || children.length) };
  }
  if (Type === "CLOUDWATCH_METRIC") {
    return {
      Type,
      ...common,
      AlarmIdentifier: { Name: required(form, "alarm", "Alarm"), Region: (text(form, "alarmRegion") || "us-east-1") as never },
      InsufficientDataHealthStatus: (text(form, "insufficient") || "LastKnownStatus") as InsufficientDataHealthStatus,
    };
  }
  const regions = form.getAll("regions").filter((v): v is string => typeof v === "string") as HealthCheckRegion[];
  const base = {
    ...common,
    RequestInterval: Number(text(form, "interval") || 30),
    FailureThreshold: Number(text(form, "threshold") || 3),
    Regions: regions.length ? regions : undefined,
  };
  if (Type === "TCP") {
    const host = required(form, "host", "Domain name or IP");
    const ip = /^[\d.]+$|:/.test(host);
    return { Type, ...base, IPAddress: ip ? host : undefined, FullyQualifiedDomainName: ip ? undefined : host, Port: Number(required(form, "port", "Port")) };
  }
  const raw = required(form, "url", "URL");
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new FieldError("url", "An http(s) URL", "format");
  }
  const https = url.protocol === "https:";
  const match = !!text(form, "search");
  const host = url.hostname.replace(/^\[|\]$/g, "");
  const ip = /^[\d.]+$|:/.test(host);
  return {
    Type: `${https ? "HTTPS" : "HTTP"}${match ? "_STR_MATCH" : ""}` as HealthCheckConfig["Type"],
    ...base,
    FullyQualifiedDomainName: ip ? undefined : host,
    IPAddress: ip ? host : undefined,
    Port: Number(url.port || (https ? 443 : 80)),
    ResourcePath: url.pathname + url.search,
    SearchString: match ? text(form, "search") : undefined,
    EnableSNI: https ? true : undefined,
  };
}

const HEALTH_FIELDS = {
  "HealthCheckConfig.FullyQualifiedDomainName": "url",
  "HealthCheckConfig.IPAddress": "url",
  "HealthCheckConfig.Port": "url",
  "HealthCheckConfig.ResourcePath": "url",
  "HealthCheckConfig.SearchString": "search",
  "HealthCheckConfig.FailureThreshold": "threshold",
  "HealthCheckConfig.RequestInterval": "interval",
  "HealthCheckConfig.HealthThreshold": "healthThreshold",
  "HealthCheckConfig.Regions": "regions",
  FailureThreshold: "threshold",
  SearchString: "search",
  HealthThreshold: "healthThreshold",
  Regions: "regions",
  InvalidInput: "url",
};

async function nameCheck(id: string, name: string) {
  if (!name) return;
  await (await route53()).send(new ChangeTagsForResourceCommand({ ResourceType: "healthcheck", ResourceId: id, AddTags: [{ Key: "Name", Value: name }] }));
}

export async function createHealthCheck(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await route53()).send(new CreateHealthCheckCommand({ CallerReference: `console-${Date.now()}`, HealthCheckConfig: healthConfig(form) }));
    await nameCheck(out.HealthCheck!.Id!, text(form, "checkName"));
    return "Health check created";
  }, { revalidate: ["/route53"], fields: HEALTH_FIELDS });
}

export async function updateHealthCheck(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await route53();
    const current = (await client.send(new GetHealthCheckCommand({ HealthCheckId: id }))).HealthCheck!;
    const c = healthConfig(form);
    await client.send(
      new UpdateHealthCheckCommand({
        HealthCheckId: id,
        HealthCheckVersion: current.HealthCheckVersion,
        IPAddress: c.IPAddress,
        FullyQualifiedDomainName: c.FullyQualifiedDomainName,
        Port: c.Port,
        ResourcePath: c.ResourcePath,
        SearchString: c.SearchString,
        FailureThreshold: c.FailureThreshold,
        Inverted: c.Inverted,
        Disabled: c.Disabled,
        HealthThreshold: c.HealthThreshold,
        ChildHealthChecks: c.ChildHealthChecks,
        Regions: c.Regions,
        AlarmIdentifier: c.AlarmIdentifier,
        InsufficientDataHealthStatus: c.InsufficientDataHealthStatus,
        EnableSNI: c.EnableSNI,
      }),
    );
    await nameCheck(id, text(form, "checkName"));
    return "Health check saved";
  }, { revalidate: ["/route53/health", "/route53"], fields: { ...HEALTH_FIELDS, HealthCheckVersionMismatch: "url" } });
}

export async function deleteHealthCheck(id: string, back?: boolean) {
  return act(async () => {
    await (await route53()).send(new DeleteHealthCheckCommand({ HealthCheckId: id }));
    if (back) redirect("/route53?tab=health");
    return "Health check deleted";
  }, "/route53");
}

// ---------------------------------------------------------------------------
// Tags (zones and health checks).

export async function addTag(type: "hostedzone" | "healthcheck", id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Key = required(form, "key", "Key");
    await (await route53()).send(new ChangeTagsForResourceCommand({ ResourceType: type, ResourceId: id, AddTags: [{ Key, Value: text(form, "value") }] }));
    return `Tagged ${Key}`;
  }, { revalidate: ["/route53/zone", "/route53/health"], fields: { "AddTags.member.Key": "key", "AddTags.member.Value": "value" } });
}

export async function removeTag(type: "hostedzone" | "healthcheck", id: string, key: string) {
  return act(async () => {
    await (await route53()).send(new ChangeTagsForResourceCommand({ ResourceType: type, ResourceId: id, RemoveTagKeys: [key] }));
    return `Removed ${key}`;
  }, "/route53/zone", "/route53/health");
}

// ---------------------------------------------------------------------------
// Private zones: VPC associations and cross-account authorizations.

export async function associateVpc(zone: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const VPCId = required(form, "vpc", "VPC");
    const VPCRegion = (text(form, "region") || (await region())) as VPCRegion;
    await (await route53()).send(new AssociateVPCWithHostedZoneCommand({ HostedZoneId: zone, VPC: { VPCId, VPCRegion } }));
    return `Associated ${VPCId}`;
  }, { revalidate: ["/route53/zone"], fields: { "VPC.VPCId": "vpc", "VPC.VPCRegion": "region", InvalidVPCId: "vpc", ConflictingDomainExists: "vpc", NotAuthorizedException: "vpc" } });
}

export async function disassociateVpc(zone: string, VPCId: string, VPCRegion: string) {
  return act(async () => {
    await (await route53()).send(new DisassociateVPCFromHostedZoneCommand({ HostedZoneId: zone, VPC: { VPCId, VPCRegion: VPCRegion as VPCRegion } }));
    return `Disassociated ${VPCId}`;
  }, "/route53/zone");
}

export async function authorizeVpc(zone: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const VPCId = required(form, "vpc", "VPC ID");
    await (await route53()).send(new CreateVPCAssociationAuthorizationCommand({ HostedZoneId: zone, VPC: { VPCId, VPCRegion: required(form, "region", "Region") as VPCRegion } }));
    return `Authorized ${VPCId}`;
  }, { revalidate: ["/route53/zone"], fields: { "VPC.VPCId": "vpc", "VPC.VPCRegion": "region", InvalidVPCId: "vpc" } });
}

export async function revokeVpc(zone: string, VPCId: string, VPCRegion: string) {
  return act(async () => {
    await (await route53()).send(new DeleteVPCAssociationAuthorizationCommand({ HostedZoneId: zone, VPC: { VPCId, VPCRegion: VPCRegion as VPCRegion } }));
    return `Revoked ${VPCId}`;
  }, "/route53/zone");
}

// ---------------------------------------------------------------------------
// DNSSEC.

/** A KMS key Route 53 can sign with: ECC_NIST_P256 in us-east-1, its policy
 * letting dnssec-route53.amazonaws.com read and sign for this account. */
async function dnssecKey(zone: string): Promise<string> {
  const { account } = await frameInfo();
  const policy = {
    Version: "2012-10-17",
    Statement: [
      { Sid: "Enable IAM User Permissions", Effect: "Allow", Principal: { AWS: `arn:aws:iam::${account}:root` }, Action: "kms:*", Resource: "*" },
      {
        Sid: "Allow Route 53 DNSSEC Service",
        Effect: "Allow",
        Principal: { Service: "dnssec-route53.amazonaws.com" },
        Action: ["kms:DescribeKey", "kms:GetPublicKey", "kms:Sign"],
        Resource: "*",
        Condition: { StringEquals: { "aws:SourceAccount": account } },
      },
    ],
  };
  const out = await (await kmsUsEast1()).send(
    new CreateKeyCommand({ KeySpec: "ECC_NIST_P256", KeyUsage: "SIGN_VERIFY", Description: `Route 53 DNSSEC key for ${zone}`, Policy: JSON.stringify(policy) }),
  );
  return out.KeyMetadata!.Arn!;
}

export async function createKsk(zone: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Name = required(form, "name", "Name");
    const picked = required(form, "kms", "KMS key");
    const kms = picked === AUTO ? await dnssecKey(zone) : picked;
    await (await route53()).send(
      new CreateKeySigningKeyCommand({ HostedZoneId: zone, Name, KeyManagementServiceArn: kms, Status: "ACTIVE", CallerReference: `console-${Date.now()}` }),
    );
    return `Created ${Name}`;
  }, { revalidate: ["/route53/zone"], fields: { Name: "name", KeyManagementServiceArn: "kms", InvalidKMSArn: "kms", InvalidKeySigningKeyName: "name", KeySigningKeyAlreadyExists: "name" } });
}

export async function kskAction(zone: string, name: string, what: "activate" | "deactivate" | "delete") {
  return act(async () => {
    const c = await route53();
    if (what === "activate") await c.send(new ActivateKeySigningKeyCommand({ HostedZoneId: zone, Name: name }));
    else if (what === "deactivate") await c.send(new DeactivateKeySigningKeyCommand({ HostedZoneId: zone, Name: name }));
    else await c.send(new DeleteKeySigningKeyCommand({ HostedZoneId: zone, Name: name }));
    return `${what[0].toUpperCase()}${what.slice(1)}d ${name}`;
  }, "/route53/zone");
}

export async function setSigning(zone: string, on: boolean) {
  return act(async () => {
    const c = await route53();
    if (on) await c.send(new EnableHostedZoneDNSSECCommand({ HostedZoneId: zone }));
    else await c.send(new DisableHostedZoneDNSSECCommand({ HostedZoneId: zone }));
    return on ? "Signing enabled" : "Signing disabled";
  }, "/route53/zone");
}

// ---------------------------------------------------------------------------
// Query logging.

/** A us-east-1 log group Route 53 may write to: made (with the account's
 * Route 53 resource policy) when it does not exist yet. */
async function queryLogGroup(name: string): Promise<string> {
  const logs = await logsUsEast1();
  const { account } = await frameInfo();
  const found = (await logs.send(new DescribeLogGroupsCommand({ logGroupNamePrefix: name }))).logGroups?.find((g) => g.logGroupName === name);
  if (!found) await logs.send(new CreateLogGroupCommand({ logGroupName: name }));
  await logs.send(
    new PutResourcePolicyCommand({
      policyName: "AWSServiceRoleForRoute53-query-logging",
      policyDocument: JSON.stringify({
        Version: "2012-10-17",
        Statement: [
          {
            Sid: "Route53LogsToCloudWatchLogs",
            Effect: "Allow",
            Principal: { Service: "route53.amazonaws.com" },
            Action: ["logs:CreateLogStream", "logs:PutLogEvents"],
            Resource: `arn:aws:logs:us-east-1:${account}:log-group:/aws/route53/*`,
          },
        ],
      }),
    }),
  );
  return `arn:aws:logs:us-east-1:${account}:log-group:${name}`;
}

export async function createQueryLogging(zone: string, domain: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const picked = required(form, "group", "Log group");
    const arn = picked === AUTO ? await queryLogGroup(`/aws/route53/${domain}`) : picked;
    await (await route53()).send(new CreateQueryLoggingConfigCommand({ HostedZoneId: zone, CloudWatchLogsLogGroupArn: arn }));
    return "Query logging on";
  }, {
    revalidate: ["/route53/zone"],
    fields: {
      CloudWatchLogsLogGroupArn: "group",
      NoSuchCloudWatchLogsLogGroup: "group",
      InsufficientCloudWatchLogsResourcePolicy: "group",
      QueryLoggingConfigAlreadyExists: "group",
      InvalidInput: "group",
    },
  });
}

export async function deleteQueryLogging(id: string) {
  return act(async () => {
    await (await route53()).send(new DeleteQueryLoggingConfigCommand({ Id: id }));
    return "Query logging off";
  }, "/route53/zone");
}

