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
import { act, FieldError, region, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { route53 } from "../../lib/clients";
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
      }),
    );
    redirect(`/route53/zone?id=${encodeURIComponent(out.HostedZone!.Id!.split("/").pop()!)}`);
  }, { fields: { Name: "name", InvalidDomainName: "name", ConflictingDomainExists: "name", "HostedZoneConfig.Comment": "comment", InvalidVPCId: "vpc" } });
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
    try {
      await (await route53()).send(new ChangeResourceRecordSetsCommand({ HostedZoneId: zone, ChangeBatch: { Changes: [{ Action: "UPSERT", ResourceRecordSet: set }] } }));
    } catch (e) {
      // InvalidChangeBatch names no member; its message says which part.
      const at = e instanceof Error && e.name === "InvalidChangeBatch" ? changeBatchField(e.message) : null;
      throw at ? new FieldError(at.field, at.message) : e;
    }
    return `Saved ${Name} ${Type}`;
  }, { revalidate: ["/route53/zone"], fields: { Name: "name", Type: "type", TTL: "ttl", "AliasTarget.DNSName": "alias", InvalidChangeBatch: "values" } });
}

export async function deleteRecord(zone: string, set: ResourceRecordSet) {
  return act(async () => {
    await (await route53()).send(new ChangeResourceRecordSetsCommand({ HostedZoneId: zone, ChangeBatch: { Changes: [{ Action: "DELETE", ResourceRecordSet: set }] } }));
    return `Deleted ${set.Name} ${set.Type}`;
  }, "/route53/zone");
}

export async function createHealthCheck(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const raw = required(form, "url", "URL");
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      throw new FieldError("url", "An http(s) URL", "format");
    }
    const https = url.protocol === "https:";
    await (await route53()).send(
      new CreateHealthCheckCommand({
        CallerReference: `console-${Date.now()}`,
        HealthCheckConfig: {
          Type: https ? "HTTPS" : "HTTP",
          FullyQualifiedDomainName: url.hostname,
          Port: Number(url.port || (https ? 443 : 80)),
          ResourcePath: url.pathname + url.search,
          RequestInterval: Number(text(form, "interval") || 30),
          FailureThreshold: Number(text(form, "threshold") || 3),
        },
      }),
    );
    return "Health check created";
  }, {
    revalidate: ["/route53"],
    fields: {
      "HealthCheckConfig.FullyQualifiedDomainName": "url",
      "HealthCheckConfig.Port": "url",
      "HealthCheckConfig.ResourcePath": "url",
      "HealthCheckConfig.FailureThreshold": "threshold",
      "HealthCheckConfig.RequestInterval": "interval",
      InvalidInput: "url",
    },
  });
}

export async function deleteHealthCheck(id: string) {
  return act(async () => {
    await (await route53()).send(new DeleteHealthCheckCommand({ HealthCheckId: id }));
    return "Health check deleted";
  }, "/route53");
}
