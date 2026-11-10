"use server";

import { PutObjectCommand } from "@aws-sdk/client-s3";
import {
  AddListenerCertificatesCommand,
  AddTagsCommand,
  CreateListenerCommand,
  CreateLoadBalancerCommand,
  CreateRuleCommand,
  CreateTargetGroupCommand,
  CreateTrustStoreCommand,
  DeleteListenerCommand,
  DeleteLoadBalancerCommand,
  DeleteRuleCommand,
  DeleteTargetGroupCommand,
  DeleteTrustStoreCommand,
  DeregisterTargetsCommand,
  ModifyListenerAttributesCommand,
  ModifyListenerCommand,
  ModifyLoadBalancerAttributesCommand,
  ModifyRuleCommand,
  ModifyTargetGroupAttributesCommand,
  ModifyTargetGroupCommand,
  ModifyTrustStoreCommand,
  RegisterTargetsCommand,
  RemoveListenerCertificatesCommand,
  RemoveTagsCommand,
  SetIpAddressTypeCommand,
  SetRulePrioritiesCommand,
  SetSecurityGroupsCommand,
  SetSubnetsCommand,
  type ProtocolEnum,
} from "@aws-sdk/client-elastic-load-balancing-v2";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { ensureBucket } from "@mws-dashboard/aws/auto";
import { redirect } from "next/navigation";

import { elb, s3 } from "../../lib/clients";
import { lbHref, tgHref } from "../../lib/elb";
import { actionFrom, conditionsFrom } from "../../lib/listener";
import { isPublic, network } from "../../lib/vpc";

/** ELB's validation errors are prose ("Health check path must begin with
 * a '/' character"); point the ones a form field causes at that field. */
async function onFields<T>(call: Promise<T>, fields: [RegExp, string][]): Promise<T> {
  try {
    return await call;
  } catch (e) {
    const message = e instanceof Error ? e.message : "";
    const field =
      e instanceof Error && /Validation|InvalidConfiguration|InvalidScheme|UnsupportedProtocol|IncompatibleProtocols|InvalidLoadBalancerAction|PriorityInUse|SSLPolicyNotFound|InvalidSecurityGroup|InvalidSubnet/.test(e.name)
        ? fields.find(([re]) => re.test(message))?.[1]
        : undefined;
    if (field) throw new FieldError(field, message);
    throw e;
  }
}

const values = (form: FormData, name: string) => form.getAll(name).filter((v): v is string => typeof v === "string" && !!v);

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
    const groups = values(form, "securityGroups");
    const ip = text(form, "ipType");
    const out = await onFields(
      (await elb()).send(
        new CreateLoadBalancerCommand({
          Name,
          Type,
          Scheme: Type === "gateway" ? undefined : Scheme,
          Subnets: [...byZone.values()],
          SecurityGroups: Type !== "gateway" && groups.length ? groups : undefined,
          IpAddressType: ip ? (ip as "ipv4" | "dualstack") : undefined,
        }),
      ),
      [
        [/name/i, "name"],
        [/scheme/i, "scheme"],
        [/security group/i, "securityGroups"],
        [/subnet|Availability Zone/i, "vpc"],
        [/IP address type|dualstack/i, "ipType"],
        [/type/i, "type"],
      ],
    );
    redirect(lbHref(out.LoadBalancers![0].LoadBalancerArn));
  }, { fields: { Name: "name", Subnets: "vpc", SecurityGroups: "securityGroups", InvalidSubnetException: "vpc", SubnetNotFoundException: "vpc", InvalidSecurityGroupException: "securityGroups" } });
}

export async function deleteLoadBalancer(arn: string) {
  return act(async () => {
    await (await elb()).send(new DeleteLoadBalancerCommand({ LoadBalancerArn: arn }));
    redirect("/elb");
  });
}

export async function setSecurityGroups(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await onFields((await elb()).send(new SetSecurityGroupsCommand({ LoadBalancerArn: arn, SecurityGroups: values(form, "securityGroups") })), [[/.*/, "securityGroups"]]);
    return "Security groups saved";
  }, { revalidate: ["/elb/lb"], fields: { InvalidSecurityGroupException: "securityGroups", SecurityGroups: "securityGroups" } });
}

export async function setSubnets(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const subnets = values(form, "subnets");
    if (!subnets.length) throw new FieldError("subnets", "Choose at least one subnet", "required");
    await onFields((await elb()).send(new SetSubnetsCommand({ LoadBalancerArn: arn, Subnets: subnets })), [[/.*/, "subnets"]]);
    return "Subnets saved";
  }, { revalidate: ["/elb/lb"], fields: { InvalidSubnetException: "subnets", SubnetNotFoundException: "subnets", Subnets: "subnets" } });
}

export async function setIpAddressType(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await onFields((await elb()).send(new SetIpAddressTypeCommand({ LoadBalancerArn: arn, IpAddressType: required(form, "ipType", "IP address type") as "ipv4" | "dualstack" })), [[/.*/, "ipType"]]);
    return "IP address type saved";
  }, { revalidate: ["/elb/lb"], fields: { IpAddressType: "ipType" } });
}

/** Attribute forms send every attribute (`attr:<key>`) with the value it
 * had (`was:<key>`): only the changed ones are modified. */
function changedAttributes(form: FormData) {
  const out: { Key: string; Value: string }[] = [];
  for (const [k, v] of form.entries()) {
    if (!k.startsWith("attr:") || typeof v !== "string") continue;
    const key = k.slice(5);
    if (v.trim() !== String(form.get(`was:${key}`) ?? "")) out.push({ Key: key, Value: v.trim() });
  }
  return out;
}

async function onAttributes<T>(call: Promise<T>): Promise<T> {
  try {
    return await call;
  } catch (e) {
    const message = e instanceof Error ? e.message : "";
    const key = message.match(/([a-z0-9_]+(?:\.[a-z0-9_]+)+)/i)?.[1];
    if (key) throw new FieldError(`attr:${key}`, message);
    throw e;
  }
}

export async function modifyLbAttributes(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Attributes = changedAttributes(form);
    if (!Attributes.length) return "Nothing changed";
    await onAttributes((await elb()).send(new ModifyLoadBalancerAttributesCommand({ LoadBalancerArn: arn, Attributes })));
    return `Saved ${Attributes.length} attribute${Attributes.length === 1 ? "" : "s"}`;
  }, "/elb/lb");
}

export async function modifyTgAttributes(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Attributes = changedAttributes(form);
    if (!Attributes.length) return "Nothing changed";
    await onAttributes((await elb()).send(new ModifyTargetGroupAttributesCommand({ TargetGroupArn: arn, Attributes })));
    return `Saved ${Attributes.length} attribute${Attributes.length === 1 ? "" : "s"}`;
  }, "/elb/tg");
}

export async function modifyListenerAttributes(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Attributes = changedAttributes(form);
    if (!Attributes.length) return "Nothing changed";
    await onAttributes((await elb()).send(new ModifyListenerAttributesCommand({ ListenerArn: arn, Attributes })));
    return `Saved ${Attributes.length} attribute${Attributes.length === 1 ? "" : "s"}`;
  }, "/elb/listener");
}

export async function createTargetGroup(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const targetType = (text(form, "targetType") || "instance") as "instance" | "ip" | "lambda" | "alb";
    const lambda = targetType === "lambda";
    const protocol = (text(form, "protocol") || "HTTP") as ProtocolEnum;
    const http = protocol === "HTTP" || protocol === "HTTPS";
    const geneve = protocol === "GENEVE";
    const version = text(form, "protocolVersion");
    const matcher = text(form, "matcher");
    const out = await onFields(
      (await elb()).send(
        new CreateTargetGroupCommand({
          Name: required(form, "name", "Name"),
          TargetType: targetType,
          Protocol: lambda ? undefined : protocol,
          ProtocolVersion: !lambda && http && version ? version : undefined,
          Port: lambda ? undefined : geneve ? 6081 : Number(text(form, "port") || 80),
          VpcId: lambda ? undefined : required(form, "vpc", "VPC"),
          IpAddressType: !lambda && text(form, "ipType") ? (text(form, "ipType") as "ipv4" | "ipv6") : undefined,
          HealthCheckProtocol: geneve ? "TCP" : undefined,
          HealthCheckPort: geneve ? "80" : undefined,
          HealthCheckPath: (http || lambda) && text(form, "healthPath") ? text(form, "healthPath") : undefined,
          Matcher: (http || lambda) && matcher ? (version === "GRPC" ? { GrpcCode: matcher } : { HttpCode: matcher }) : undefined,
        }),
      ),
      [
        [/health check/i, "healthPath"],
        [/matcher|http code|grpc/i, "matcher"],
        [/protocol version/i, "protocolVersion"],
        [/VPC/, "vpc"],
        [/port/i, "port"],
        [/protocol/i, "protocol"],
        [/target type/i, "targetType"],
        [/name/i, "name"],
      ],
    );
    redirect(tgHref(out.TargetGroups![0].TargetGroupArn));
  }, { fields: { Name: "name", Port: "port", VpcId: "vpc", HealthCheckPath: "healthPath", "Matcher.HttpCode": "matcher", "Matcher.GrpcCode": "matcher", ProtocolVersion: "protocolVersion" } });
}

export async function modifyHealthCheck(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const protocol = text(form, "hcProtocol") as ProtocolEnum | "";
    const http = protocol === "HTTP" || protocol === "HTTPS";
    const matcher = text(form, "matcher");
    const grpc = text(form, "grpc") === "1";
    const num = (n: string) => (text(form, n) ? Number(text(form, n)) : undefined);
    await onFields(
      (await elb()).send(
        new ModifyTargetGroupCommand({
          TargetGroupArn: arn,
          HealthCheckEnabled: form.has("hcEnabled") ? form.get("hcEnabled") === "on" : undefined,
          HealthCheckProtocol: protocol || undefined,
          HealthCheckPort: text(form, "hcPort") || undefined,
          HealthCheckPath: http || form.has("lambda") ? text(form, "hcPath") || undefined : undefined,
          HealthCheckIntervalSeconds: num("interval"),
          HealthCheckTimeoutSeconds: num("timeout"),
          HealthyThresholdCount: num("healthy"),
          UnhealthyThresholdCount: num("unhealthy"),
          Matcher: matcher && (http || form.has("lambda")) ? (grpc ? { GrpcCode: matcher } : { HttpCode: matcher }) : undefined,
        }),
      ),
      [
        [/path/i, "hcPath"],
        [/timeout/i, "timeout"],
        [/interval/i, "interval"],
        [/unhealthy/i, "unhealthy"],
        [/healthy threshold/i, "healthy"],
        [/matcher|code/i, "matcher"],
        [/port/i, "hcPort"],
        [/protocol/i, "hcProtocol"],
      ],
    );
    return "Health check saved";
  }, {
    revalidate: ["/elb/tg"],
    fields: {
      HealthCheckPath: "hcPath",
      HealthCheckPort: "hcPort",
      HealthCheckIntervalSeconds: "interval",
      HealthCheckTimeoutSeconds: "timeout",
      HealthyThresholdCount: "healthy",
      UnhealthyThresholdCount: "unhealthy",
      "Matcher.HttpCode": "matcher",
    },
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
    const zone = text(form, "zone");
    const ids = required(form, "targets", "Targets").split(/[\s,]+/).filter(Boolean);
    await onFields(
      (await elb()).send(new RegisterTargetsCommand({ TargetGroupArn: arn, Targets: ids.map((Id) => ({ Id, Port: port ? Number(port) : undefined, AvailabilityZone: zone || undefined })) })),
      [
        [/port/i, "port"],
        [/Availability Zone/i, "zone"],
        [/.*/, "targets"],
      ],
    );
    return `Registered ${ids.length}`;
  }, { revalidate: ["/elb/tg"], fields: { InvalidTargetException: "targets", TooManyTargetsException: "targets" } });
}

export async function deregisterTarget(arn: string, id: string, port: number | undefined, zone: string | undefined) {
  return act(async () => {
    await (await elb()).send(new DeregisterTargetsCommand({ TargetGroupArn: arn, Targets: [{ Id: id, Port: port, AvailabilityZone: zone }] }));
    return `Deregistered ${id}`;
  }, "/elb/tg");
}

const LISTENER_FIELDS: [RegExp, string][] = [
  [/certificate/i, "certificate"],
  [/SSL policy|security policy/i, "sslPolicy"],
  [/trust store|mutual/i, "trustStore"],
  [/ALPN/i, "alpn"],
  [/protocol/i, "protocol"],
  [/port/i, "port"],
  [/target group|forward/i, "group"],
  [/redirect/i, "rPort"],
  [/fixed|status code/i, "fStatus"],
];

const LISTENER_ERRORS = {
  Port: "port",
  DuplicateListenerException: "port",
  CertificateNotFoundException: "certificate",
  TargetGroupNotFoundException: "group",
  TargetGroupAssociationLimitException: "group",
  SSLPolicyNotFoundException: "sslPolicy",
  TrustStoreNotFoundException: "trustStore",
  TrustStoreNotReadyException: "trustStore",
  ALPNPolicyNotSupportedException: "alpn",
};

function tlsSettings(form: FormData, protocol: string | undefined) {
  const tls = protocol === "HTTPS" || protocol === "TLS";
  const certificate = text(form, "certificate");
  const store = text(form, "trustStore");
  const mode = text(form, "mtls") as "off" | "passthrough" | "verify" | "";
  return {
    Certificates: tls && certificate ? [{ CertificateArn: certificate }] : undefined,
    SslPolicy: tls ? text(form, "sslPolicy") || undefined : undefined,
    AlpnPolicy: protocol === "TLS" && text(form, "alpn") ? [text(form, "alpn")] : undefined,
    MutualAuthentication: protocol === "HTTPS" && mode ? { Mode: mode, TrustStoreArn: mode === "verify" ? store || undefined : undefined } : undefined,
  };
}

export async function createListener(lb: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    // Gateway Load Balancer listeners take neither (the form has no fields).
    const protocol = (text(form, "protocol") || undefined) as ProtocolEnum | undefined;
    const port = form.has("port") ? Number(required(form, "port", "Port")) : undefined;
    if ((protocol === "HTTPS" || protocol === "TLS") && !text(form, "certificate")) throw new FieldError("certificate", `${protocol} listeners need a certificate`, "required");
    const actions = actionFrom(form);
    if (!Array.isArray(actions)) throw new FieldError(actions.field, actions.message, "required");
    const out = await onFields(
      (await elb()).send(new CreateListenerCommand({ LoadBalancerArn: lb, Protocol: protocol, Port: port, DefaultActions: actions, ...tlsSettings(form, protocol) })),
      LISTENER_FIELDS,
    );
    return `Listener ${out.Listeners?.[0]?.Port ? `:${out.Listeners[0].Port} ` : ""}added`;
  }, { revalidate: ["/elb/lb"], fields: LISTENER_ERRORS });
}

export async function modifyListener(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const protocol = (text(form, "protocol") || undefined) as ProtocolEnum | undefined;
    const port = text(form, "port") ? Number(text(form, "port")) : undefined;
    const actions = actionFrom(form);
    if (!Array.isArray(actions)) throw new FieldError(actions.field, actions.message, "required");
    await onFields((await elb()).send(new ModifyListenerCommand({ ListenerArn: arn, Protocol: protocol, Port: port, DefaultActions: actions, ...tlsSettings(form, protocol) })), LISTENER_FIELDS);
    return "Listener saved";
  }, { revalidate: ["/elb/listener", "/elb/lb"], fields: LISTENER_ERRORS });
}

export async function deleteListener(arn: string, lb?: string) {
  return act(async () => {
    await (await elb()).send(new DeleteListenerCommand({ ListenerArn: arn }));
    if (lb) redirect(lbHref(lb));
    return "Listener deleted";
  }, "/elb/lb");
}

export async function addCertificate(listener: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const arn = required(form, "certificate", "Certificate");
    await (await elb()).send(new AddListenerCertificatesCommand({ ListenerArn: listener, Certificates: [{ CertificateArn: arn }] }));
    return "Certificate added";
  }, { revalidate: ["/elb/listener"], fields: { CertificateNotFoundException: "certificate", TooManyCertificatesException: "certificate" } });
}

export async function removeCertificate(listener: string, arn: string) {
  return act(async () => {
    await (await elb()).send(new RemoveListenerCertificatesCommand({ ListenerArn: listener, Certificates: [{ CertificateArn: arn }] }));
    return "Certificate removed";
  }, "/elb/listener");
}

const RULE_ERRORS = { Priority: "priority", PriorityInUseException: "priority", TargetGroupNotFoundException: "group", TooManyConditionValuesException: "host", TooManyRulesException: "priority" };
const RULE_FIELDS: [RegExp, string][] = [
  [/priority/i, "priority"],
  [/host/i, "host"],
  [/path/i, "path"],
  [/method/i, "method"],
  [/source/i, "sourceIp"],
  [/header/i, "headerName"],
  [/query/i, "query"],
  [/condition/i, "host"],
  [/target group|forward/i, "group"],
  [/redirect/i, "rPort"],
  [/fixed|status code/i, "fStatus"],
];

export async function createRule(listener: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Priority = Number(required(form, "priority", "Priority"));
    const Conditions = conditionsFrom(form);
    if (!Conditions.length) throw new FieldError("host", "Add at least one condition", "required");
    const Actions = actionFrom(form);
    if (!Array.isArray(Actions)) throw new FieldError(Actions.field, Actions.message, "required");
    await onFields((await elb()).send(new CreateRuleCommand({ ListenerArn: listener, Priority, Conditions, Actions })), RULE_FIELDS);
    return `Rule ${Priority} added`;
  }, { revalidate: ["/elb/listener"], fields: RULE_ERRORS });
}

export async function modifyRule(rule: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Conditions = conditionsFrom(form);
    if (!Conditions.length) throw new FieldError("host", "Add at least one condition", "required");
    const Actions = actionFrom(form);
    if (!Array.isArray(Actions)) throw new FieldError(Actions.field, Actions.message, "required");
    const client = await elb();
    await onFields(client.send(new ModifyRuleCommand({ RuleArn: rule, Conditions, Actions })), RULE_FIELDS);
    const priority = text(form, "priority");
    if (priority && priority !== text(form, "wasPriority")) await onFields(client.send(new SetRulePrioritiesCommand({ RulePriorities: [{ RuleArn: rule, Priority: Number(priority) }] })), RULE_FIELDS);
    return "Rule saved";
  }, { revalidate: ["/elb/listener"], fields: RULE_ERRORS });
}

/** Swap a rule's priority with its neighbour's (one SetRulePriorities call). */
export async function swapPriorities(a: string, pa: number, b: string, pb: number) {
  return act(async () => {
    const client = await elb();
    // Priorities are unique: move one out of the way first.
    await client.send(new SetRulePrioritiesCommand({ RulePriorities: [{ RuleArn: a, Priority: 50000 }] }));
    await client.send(new SetRulePrioritiesCommand({ RulePriorities: [{ RuleArn: b, Priority: pa }, { RuleArn: a, Priority: pb }] }));
    return "Reordered";
  }, "/elb/listener");
}

export async function deleteRule(rule: string) {
  return act(async () => {
    await (await elb()).send(new DeleteRuleCommand({ RuleArn: rule }));
    return "Rule deleted";
  }, "/elb/listener");
}

export async function addTag(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Key = required(form, "key", "Key");
    await (await elb()).send(new AddTagsCommand({ ResourceArns: [arn], Tags: [{ Key, Value: text(form, "value") }] }));
    return `Tagged ${Key}`;
  }, { revalidate: ["/elb/lb", "/elb/tg", "/elb/listener"], fields: { DuplicateTagKeysException: "key", TooManyTagsException: "key" } });
}

export async function removeTag(arn: string, key: string) {
  return act(async () => {
    await (await elb()).send(new RemoveTagsCommand({ ResourceArns: [arn], TagKeys: [key] }));
    return `Removed ${key}`;
  }, "/elb/lb", "/elb/tg", "/elb/listener");
}

// ---------------------------------------------------------------------------
// Trust stores: a CA bundle in S3 (pasted bundles go to the console's bucket).

async function bundleLocation(form: FormData): Promise<{ bucket: string; key: string }> {
  const pem = text(form, "bundle");
  if (pem) {
    if (!/-----BEGIN CERTIFICATE-----/.test(pem)) throw new FieldError("bundle", "PEM certificates", "format");
    const bucket = await ensureBucket("elb-trust-stores");
    const key = `${required(form, "name", "Name")}/${Date.now()}.pem`;
    await (await s3()).send(new PutObjectCommand({ Bucket: bucket, Key: key, Body: pem, ContentType: "application/x-pem-file" }));
    return { bucket, key };
  }
  const url = required(form, "s3", "CA bundle");
  const m = url.match(/^s3:\/\/([^/]+)\/(.+)$/);
  if (!m) throw new FieldError("s3", "Like s3://bucket/ca.pem", "format");
  return { bucket: m[1], key: m[2] };
}

export async function createTrustStore(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const Name = required(form, "name", "Name");
    const { bucket, key } = await bundleLocation(form);
    await (await elb()).send(new CreateTrustStoreCommand({ Name, CaCertificatesBundleS3Bucket: bucket, CaCertificatesBundleS3Key: key }));
    return `Created ${Name}`;
  }, { revalidate: ["/elb"], fields: { Name: "name", DuplicateTrustStoreNameException: "name", InvalidCaCertificatesBundleException: "bundle", CaCertificatesBundleNotFoundException: "s3" } });
}

export async function modifyTrustStore(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const { bucket, key } = await bundleLocation(form);
    await (await elb()).send(new ModifyTrustStoreCommand({ TrustStoreArn: arn, CaCertificatesBundleS3Bucket: bucket, CaCertificatesBundleS3Key: key }));
    return "CA bundle replaced";
  }, { revalidate: ["/elb"], fields: { InvalidCaCertificatesBundleException: "bundle", CaCertificatesBundleNotFoundException: "s3" } });
}

export async function deleteTrustStore(arn: string) {
  return act(async () => {
    await (await elb()).send(new DeleteTrustStoreCommand({ TrustStoreArn: arn }));
    return "Trust store deleted";
  }, "/elb");
}
