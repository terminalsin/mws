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
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { elb } from "../../lib/clients";
import { isPublic, network } from "../../lib/vpc";

/** ELB's validation errors are prose ("Health check path must begin with
 * a '/' character"); point the ones a form field causes at that field. */
async function onFields<T>(call: Promise<T>, fields: [RegExp, string][]): Promise<T> {
  try {
    return await call;
  } catch (e) {
    const message = e instanceof Error ? e.message : "";
    const field = e instanceof Error && /Validation|InvalidConfiguration|InvalidScheme|UnsupportedProtocol|IncompatibleProtocols/.test(e.name) ? fields.find(([re]) => re.test(message))?.[1] : undefined;
    if (field) throw new FieldError(field, message);
    throw e;
  }
}

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
    if (byZone.size === 0) throw new FieldError("vpc", "This VPC has no subnets");
    if (Type === "application" && byZone.size < 2) throw new FieldError("vpc", "An Application Load Balancer needs subnets in two Availability Zones");
    const out = await onFields(
      (await elb()).send(new CreateLoadBalancerCommand({ Name, Type, Scheme: Type === "gateway" ? undefined : Scheme, Subnets: [...byZone.values()] })),
      [
        [/name/i, "name"],
        [/scheme/i, "scheme"],
        [/subnet|Availability Zone/i, "vpc"],
        [/type/i, "type"],
      ],
    );
    redirect(`/elb/lb?arn=${encodeURIComponent(out.LoadBalancers![0].LoadBalancerArn!)}`);
  }, { fields: { Name: "name", Subnets: "vpc", InvalidSubnetException: "vpc", SubnetNotFoundException: "vpc" } });
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
    const out = await onFields(
      (await elb()).send(
        new CreateTargetGroupCommand({
          Name: required(form, "name", "Name"),
          TargetType: targetType,
          Protocol: lambda ? undefined : ((text(form, "protocol") || "HTTP") as ProtocolEnum),
          Port: lambda ? undefined : Number(text(form, "port") || 80),
          VpcId: lambda ? undefined : required(form, "vpc", "VPC"),
          HealthCheckPath: text(form, "healthPath") || undefined,
        }),
      ),
      [
        [/health check/i, "healthPath"],
        [/VPC/, "vpc"],
        [/port/i, "port"],
        [/protocol/i, "protocol"],
        [/target type/i, "targetType"],
        [/name/i, "name"],
      ],
    );
    redirect(`/elb/tg?arn=${encodeURIComponent(out.TargetGroups![0].TargetGroupArn!)}`);
  }, { fields: { Name: "name", Port: "port", VpcId: "vpc", HealthCheckPath: "healthPath" } });
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
    await onFields((await elb()).send(new RegisterTargetsCommand({ TargetGroupArn: arn, Targets: ids.map((Id) => ({ Id, Port: port ? Number(port) : undefined })) })), [
      [/port/i, "port"],
      [/.*/, "targets"],
    ]);
    return `Registered ${ids.length}`;
  }, { revalidate: ["/elb/tg"], fields: { InvalidTargetException: "targets", TooManyTargetsException: "targets" } });
}

export async function deregisterTarget(arn: string, id: string, port: number | undefined) {
  return act(async () => {
    await (await elb()).send(new DeregisterTargetsCommand({ TargetGroupArn: arn, Targets: [{ Id: id, Port: port }] }));
    return `Deregistered ${id}`;
  }, "/elb/tg");
}

export async function createListener(lb: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    // Gateway Load Balancer listeners take neither (the form has no fields).
    const protocol = (text(form, "protocol") || undefined) as ProtocolEnum | undefined;
    const port = form.has("port") ? Number(required(form, "port", "Port")) : undefined;
    const certificate = text(form, "certificate");
    const tg = text(form, "targetGroup");
    if ((protocol === "HTTPS" || protocol === "TLS") && !certificate) throw new FieldError("certificate", `${protocol} listeners need a certificate`, "required");
    await onFields(
      (await elb()).send(
        new CreateListenerCommand({
          LoadBalancerArn: lb,
          Protocol: protocol,
          Port: port,
          Certificates: certificate ? [{ CertificateArn: certificate }] : undefined,
          DefaultActions: tg
            ? [{ Type: "forward", TargetGroupArn: tg }]
            : [{ Type: "fixed-response", FixedResponseConfig: { StatusCode: "404", ContentType: "text/plain", MessageBody: "Not found" } }],
        }),
      ),
      [
        [/certificate/i, "certificate"],
        [/protocol/i, "protocol"],
        [/port/i, "port"],
        [/target group/i, "targetGroup"],
      ],
    );
    return "Listener added";
  }, { revalidate: ["/elb/lb"], fields: { Port: "port", DuplicateListenerException: "port", CertificateNotFoundException: "certificate", TargetGroupNotFoundException: "targetGroup", TargetGroupAssociationLimitException: "targetGroup" } });
}

export async function deleteListener(arn: string) {
  return act(async () => {
    await (await elb()).send(new DeleteListenerCommand({ ListenerArn: arn }));
    return "Listener deleted";
  }, "/elb/lb");
}
