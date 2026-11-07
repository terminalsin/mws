"use server";

import {
  ChangeResourceRecordSetsCommand,
  CreateHealthCheckCommand,
  CreateHostedZoneCommand,
  DeleteHealthCheckCommand,
  DeleteHostedZoneCommand,
  type ResourceRecordSet,
  type VPCRegion,
} from "@aws-sdk/client-route-53";
import { act, region, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { route53 } from "../../lib/clients";

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
      }),
    );
    redirect(`/route53/zone?id=${encodeURIComponent(out.HostedZone!.Id!.split("/").pop()!)}`);
  });
}

export async function deleteZone(id: string) {
  return act(async () => {
    await (await route53()).send(new DeleteHostedZoneCommand({ Id: id }));
    redirect("/route53");
  });
}

export async function saveRecord(zone: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Name = required(form, "name", "Record name");
    const Type = required(form, "type", "Type") as ResourceRecordSet["Type"];
    const alias = text(form, "alias");
    const set: ResourceRecordSet = alias
      ? { Name, Type, AliasTarget: { DNSName: alias, HostedZoneId: text(form, "aliasZone") || zone, EvaluateTargetHealth: false } }
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
    await (await route53()).send(new ChangeResourceRecordSetsCommand({ HostedZoneId: zone, ChangeBatch: { Changes: [{ Action: "UPSERT", ResourceRecordSet: set }] } }));
    return `Saved ${Name} ${Type}`;
  }, "/route53/zone");
}

export async function deleteRecord(zone: string, set: ResourceRecordSet) {
  return act(async () => {
    await (await route53()).send(new ChangeResourceRecordSetsCommand({ HostedZoneId: zone, ChangeBatch: { Changes: [{ Action: "DELETE", ResourceRecordSet: set }] } }));
    return `Deleted ${set.Name} ${set.Type}`;
  }, "/route53/zone");
}

export async function createHealthCheck(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const url = new URL(required(form, "url", "URL"));
    const https = url.protocol === "https:";
    await (await route53()).send(
      new CreateHealthCheckCommand({
        CallerReference: `console-${Date.now()}`,
        HealthCheckConfig: {
          Type: https ? "HTTPS" : "HTTP",
          FullyQualifiedDomainName: url.hostname,
          Port: Number(url.port || (https ? 443 : 80)),
          ResourcePath: url.pathname + url.search,
          RequestInterval: 30,
          FailureThreshold: 3,
        },
      }),
    );
    return "Health check created";
  }, "/route53");
}

export async function deleteHealthCheck(id: string) {
  return act(async () => {
    await (await route53()).send(new DeleteHealthCheckCommand({ HealthCheckId: id }));
    return "Health check deleted";
  }, "/route53");
}
