"use server";

import {
  ConfigureHealthCheckCommand,
  CreateLoadBalancerCommand,
  CreateLoadBalancerListenersCommand,
  DeleteLoadBalancerCommand,
  DeleteLoadBalancerListenersCommand,
  DeregisterInstancesFromLoadBalancerCommand,
  ModifyLoadBalancerAttributesCommand,
  RegisterInstancesWithLoadBalancerCommand,
  type Listener,
} from "@aws-sdk/client-elastic-load-balancing";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { classic } from "../../lib/clients";
import { isPublic, network } from "../../lib/vpc";

const href = (name: string) => `/elb/classic?name=${encodeURIComponent(name)}`;

/** "HTTP:80 → HTTP:8080" lines (or "80" for HTTP:80 → HTTP:80). */
function listeners(value: string): Listener[] {
  return value
    .split(/\n|,/)
    .map((l) => l.trim())
    .filter(Boolean)
    .map((line) => {
      const m = line.match(/^(?:(HTTPS?|TCP|SSL):)?(\d{1,5})(?:\s*(?:->|→|=>)\s*(?:(HTTPS?|TCP|SSL):)?(\d{1,5}))?$/i);
      if (!m) throw new FieldError("listeners", `${line}: like HTTP:80 → HTTP:8080`, "format");
      const Protocol = (m[1] ?? "HTTP").toUpperCase();
      return { Protocol, LoadBalancerPort: Number(m[2]), InstanceProtocol: (m[3] ?? Protocol).toUpperCase(), InstancePort: Number(m[4] ?? m[2]) };
    });
}

export async function createClassic(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Name");
    const scheme = text(form, "scheme") || "internet-facing";
    const vpc = required(form, "vpc", "VPC");
    const { subnets, tables } = await network(vpc);
    const wanted = subnets.filter((s) => (scheme === "internet-facing" ? isPublic(s, tables) : !isPublic(s, tables)));
    const byZone = new Map<string, string>();
    for (const s of wanted.length ? wanted : subnets) if (!byZone.has(s.AvailabilityZone!)) byZone.set(s.AvailabilityZone!, s.SubnetId!);
    if (!byZone.size) throw new FieldError("vpc", "This VPC has no subnets");
    await (await classic()).send(
      new CreateLoadBalancerCommand({ LoadBalancerName: name, Scheme: scheme === "internal" ? "internal" : undefined, Subnets: [...byZone.values()], Listeners: listeners(required(form, "listeners", "Listeners")) }),
    );
    redirect(href(name));
  }, { fields: { LoadBalancerName: "name", DuplicateLoadBalancerName: "name", DuplicateAccessPointName: "name", InvalidSubnet: "vpc", SubnetNotFound: "vpc", Listeners: "listeners", InvalidConfigurationRequest: "listeners" } });
}

export async function deleteClassic(name: string) {
  return act(async () => {
    await (await classic()).send(new DeleteLoadBalancerCommand({ LoadBalancerName: name }));
    redirect("/elb?tab=classic");
  });
}

export async function addClassicListeners(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await classic()).send(new CreateLoadBalancerListenersCommand({ LoadBalancerName: name, Listeners: listeners(required(form, "listeners", "Listeners")) }));
    return "Listeners added";
  }, { revalidate: ["/elb/classic"], fields: { DuplicateListener: "listeners", InvalidConfigurationRequest: "listeners" } });
}

export async function deleteClassicListener(name: string, port: number) {
  return act(async () => {
    await (await classic()).send(new DeleteLoadBalancerListenersCommand({ LoadBalancerName: name, LoadBalancerPorts: [port] }));
    return `Listener ${port} deleted`;
  }, "/elb/classic");
}

export async function registerInstances(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const ids = required(form, "instances", "Instances").split(/[\s,]+/).filter(Boolean);
    await (await classic()).send(new RegisterInstancesWithLoadBalancerCommand({ LoadBalancerName: name, Instances: ids.map((InstanceId) => ({ InstanceId })) }));
    return `Registered ${ids.length}`;
  }, { revalidate: ["/elb/classic"], fields: { InvalidInstance: "instances", InvalidEndPoint: "instances" } });
}

export async function deregisterInstance(name: string, id: string) {
  return act(async () => {
    await (await classic()).send(new DeregisterInstancesFromLoadBalancerCommand({ LoadBalancerName: name, Instances: [{ InstanceId: id }] }));
    return `Deregistered ${id}`;
  }, "/elb/classic");
}

export async function configureClassicHealth(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const n = (k: string, label: string) => Number(required(form, k, label));
    await (await classic()).send(
      new ConfigureHealthCheckCommand({
        LoadBalancerName: name,
        HealthCheck: {
          Target: required(form, "target", "Ping target"),
          Interval: n("interval", "Interval"),
          Timeout: n("timeout", "Timeout"),
          HealthyThreshold: n("healthy", "Healthy threshold"),
          UnhealthyThreshold: n("unhealthy", "Unhealthy threshold"),
        },
      }),
    );
    return "Health check saved";
  }, {
    revalidate: ["/elb/classic"],
    fields: { "HealthCheck.Target": "target", "HealthCheck.Interval": "interval", "HealthCheck.Timeout": "timeout", "HealthCheck.HealthyThreshold": "healthy", "HealthCheck.UnhealthyThreshold": "unhealthy", ValidationError: "target" },
  });
}

export async function classicAttributes(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const on = (k: string) => form.get(k) === "on";
    const num = (k: string) => Number(text(form, k) || 0);
    await (await classic()).send(
      new ModifyLoadBalancerAttributesCommand({
        LoadBalancerName: name,
        LoadBalancerAttributes: {
          CrossZoneLoadBalancing: { Enabled: on("crossZone") },
          ConnectionDraining: { Enabled: on("draining"), Timeout: num("drainTimeout") || 300 },
          ConnectionSettings: { IdleTimeout: num("idle") || 60 },
        },
      }),
    );
    return "Attributes saved";
  }, { revalidate: ["/elb/classic"], fields: { "ConnectionSettings.IdleTimeout": "idle", "ConnectionDraining.Timeout": "drainTimeout" } });
}
