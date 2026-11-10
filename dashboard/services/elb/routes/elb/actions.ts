"use server";

import {
  CreateListenerCommand,
  CreateLoadBalancerCommand,
  CreateTargetGroupCommand,
  DeleteListenerCommand,
  DeleteLoadBalancerCommand,
  DeleteTargetGroupCommand,
  DeregisterTargetsCommand,
  RegisterTargetsCommand,
  type ProtocolEnum,
} from "@aws-sdk/client-elastic-load-balancing-v2";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { elb } from "../../lib/clients";
import { isPublic, network } from "../../lib/vpc";

export async function createLoadBalancer(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const Name = required(form, "name", "Name");
    const Type = (text(form, "type") || "application") as "application" | "network" | "gateway";
    const Scheme = (text(form, "scheme") || "internet-facing") as "internet-facing" | "internal";
    const vpc = required(form, "vpc", "VPC");
    // One subnet per Availability Zone, public ones for an internet-facing
    // load balancer, as the console's default mapping does.
    const { subnets, tables } = await network(vpc);
    const wanted = subnets.filter((s) => (Scheme === "internet-facing" ? isPublic(s, tables) : !isPublic(s, tables)));
    const pool = wanted.length ? wanted : subnets;
    const byZone = new Map<string, string>();
    for (const s of pool) if (!byZone.has(s.AvailabilityZone!)) byZone.set(s.AvailabilityZone!, s.SubnetId!);
    const out = await (await elb()).send(new CreateLoadBalancerCommand({ Name, Type, Scheme: Type === "gateway" ? undefined : Scheme, Subnets: [...byZone.values()] }));
    redirect(`/elb/lb?arn=${encodeURIComponent(out.LoadBalancers![0].LoadBalancerArn!)}`);
  });
}

export async function deleteLoadBalancer(arn: string) {
  return act(async () => {
    await (await elb()).send(new DeleteLoadBalancerCommand({ LoadBalancerArn: arn }));
    redirect("/elb");
  });
}

export async function createTargetGroup(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const targetType = (text(form, "targetType") || "instance") as "instance" | "ip" | "lambda" | "alb";
    const lambda = targetType === "lambda";
    const out = await (await elb()).send(
      new CreateTargetGroupCommand({
        Name: required(form, "name", "Name"),
        TargetType: targetType,
        Protocol: lambda ? undefined : ((text(form, "protocol") || "HTTP") as ProtocolEnum),
        Port: lambda ? undefined : Number(text(form, "port") || 80),
        VpcId: lambda ? undefined : required(form, "vpc", "VPC"),
        HealthCheckPath: text(form, "healthPath") || undefined,
      }),
    );
    redirect(`/elb/tg?arn=${encodeURIComponent(out.TargetGroups![0].TargetGroupArn!)}`);
  });
}

export async function deleteTargetGroup(arn: string) {
  return act(async () => {
    await (await elb()).send(new DeleteTargetGroupCommand({ TargetGroupArn: arn }));
    redirect("/elb?tab=targets");
  });
}

export async function registerTargets(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const port = text(form, "port");
    const ids = required(form, "targets", "Targets").split(/[\s,]+/).filter(Boolean);
    await (await elb()).send(new RegisterTargetsCommand({ TargetGroupArn: arn, Targets: ids.map((Id) => ({ Id, Port: port ? Number(port) : undefined })) }));
    return `Registered ${ids.length}`;
  }, "/elb/tg");
}

export async function deregisterTarget(arn: string, id: string, port: number | undefined) {
  return act(async () => {
    await (await elb()).send(new DeregisterTargetsCommand({ TargetGroupArn: arn, Targets: [{ Id: id, Port: port }] }));
    return `Deregistered ${id}`;
  }, "/elb/tg");
}

export async function createListener(lb: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const protocol = (text(form, "protocol") || "HTTP") as ProtocolEnum;
    const certificate = text(form, "certificate");
    const tg = text(form, "targetGroup");
    await (await elb()).send(
      new CreateListenerCommand({
        LoadBalancerArn: lb,
        Protocol: protocol,
        Port: Number(required(form, "port", "Port")),
        Certificates: certificate ? [{ CertificateArn: certificate }] : undefined,
        DefaultActions: tg
          ? [{ Type: "forward", TargetGroupArn: tg }]
          : [{ Type: "fixed-response", FixedResponseConfig: { StatusCode: "404", ContentType: "text/plain", MessageBody: "Not found" } }],
      }),
    );
    return "Listener added";
  }, "/elb/lb");
}

export async function deleteListener(arn: string) {
  return act(async () => {
    await (await elb()).send(new DeleteListenerCommand({ ListenerArn: arn }));
    return "Listener deleted";
  }, "/elb/lb");
}
