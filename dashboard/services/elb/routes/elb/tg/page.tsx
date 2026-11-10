import { DescribeInstancesCommand } from "@aws-sdk/client-ec2";
import {
  DescribeLoadBalancersCommand,
  DescribeTagsCommand,
  DescribeTargetGroupAttributesCommand,
  DescribeTargetGroupsCommand,
  DescribeTargetHealthCommand,
  type TargetGroup as TargetGroupT,
} from "@aws-sdk/client-elastic-load-balancing-v2";
import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Section, Segments, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { HeartPulse, Network, Pencil, Plus, Server, X } from "lucide-react";
import { ModifyTargetGroup } from "@mws-dashboard/ui/model/elbv2";
import type { Metadata } from "next";
import Link from "next/link";

import { AttributesForm } from "../../../lib/attributes";
import { ICONS, LB_ICON, ec2, elb } from "../../../lib/clients";
import { HEALTH_TONE, lbHref } from "../../../lib/elb";
import { HEALTH_PATH, TARGET_PORT, targetsRule } from "../../../lib/rules";
import { TagsSection } from "../../../lib/tags";
import { deleteTargetGroup, deregisterTarget, modifyHealthCheck, modifyTgAttributes, registerTargets } from "../actions";

export const metadata: Metadata = { title: "Target group" };

type Props = { searchParams: Promise<{ arn?: string; tab?: string }> };

const TARGET_ICON: Record<string, string> = {
  instance: "resource/AmazonEC2Instance",
  ip: ICONS.eni,
  lambda: "resource/AWSLambdaLambdaFunction",
  alb: ICONS.alb,
};

/** What this group's targets usually are: the VPC's instances (or their
 * addresses), or the Application Load Balancers there. */
async function knownTargets(type: string | undefined, vpc: string | undefined): Promise<string[]> {
  if (type === "lambda" || !vpc) return [];
  if (type === "alb") {
    const lbs = await (await elb()).send(new DescribeLoadBalancersCommand({})).then((r) => r.LoadBalancers ?? [], () => []);
    return lbs.filter((l) => l.Type === "application" && l.VpcId === vpc).map((l) => l.LoadBalancerArn!);
  }
  const out = await (await ec2()).send(new DescribeInstancesCommand({ Filters: [{ Name: "vpc-id", Values: [vpc] }] })).catch(() => null);
  const instances = (out?.Reservations ?? []).flatMap((r) => r.Instances ?? []).filter((i) => i.State?.Name !== "terminated");
  return instances.map((i) => (type === "ip" ? i.PrivateIpAddress : i.InstanceId)).filter((v): v is string => !!v);
}

/** Where a target's own page is. */
function targetHref(id: string): string | undefined {
  if (id.startsWith("i-")) return `/ec2/instance?id=${id}`;
  if (id.startsWith("arn:aws:lambda:")) return `/lambda/${encodeURIComponent(id.split(":")[6] ?? id)}`;
  if (id.includes(":loadbalancer/")) return lbHref(id);
  return undefined;
}

const M = ModifyTargetGroup;

function HealthCheckForm({ g }: { g: TargetGroupT }) {
  const lambda = g.TargetType === "lambda";
  const grpc = g.ProtocolVersion === "GRPC";
  const http = lambda || g.HealthCheckProtocol === "HTTP" || g.HealthCheckProtocol === "HTTPS";
  return (
    <ActionForm action={modifyHealthCheck.bind(null, g.TargetGroupArn!)} submit="Save" testId="edit-health-check">
      {lambda && <input type="hidden" name="lambda" value="1" />}
      {grpc && <input type="hidden" name="grpc" value="1" />}
      <label className="check">
        <input type="checkbox" name="hcEnabled" defaultChecked={g.HealthCheckEnabled !== false} /> Health checks on
      </label>
      {!lambda && (
        <div className="form-row">
          <Field label="Protocol" rule={M.HealthCheckProtocol}>
            <select name="hcProtocol" defaultValue={g.HealthCheckProtocol}>
              {(g.Protocol === "HTTP" || g.Protocol === "HTTPS" ? ["HTTP", "HTTPS"] : ["TCP", "HTTP", "HTTPS"]).map((p) => (
                <option key={p}>{p}</option>
              ))}
            </select>
          </Field>
          <Field label="Port" rule={{ ...M.HealthCheckPort, pattern: "^(traffic-port|\\d{1,5})$", hint: "traffic-port or 1-65535" }}>
            <input name="hcPort" defaultValue={g.HealthCheckPort ?? "traffic-port"} />
          </Field>
        </div>
      )}
      {http && (
        <div className="form-row">
          <Field label="Path" rule={HEALTH_PATH}>
            <input name="hcPath" defaultValue={g.HealthCheckPath} />
          </Field>
          <Field label={grpc ? "Success gRPC codes" : "Success codes"} rule={{ pattern: "^\\d{1,3}([,-]\\d{1,3})*$", hint: "Like 200 or 200-299" }} member="Matcher.HttpCode">
            <input name="matcher" defaultValue={g.Matcher?.GrpcCode ?? g.Matcher?.HttpCode} />
          </Field>
        </div>
      )}
      <div className="form-row">
        <Field label="Interval" rule={{ ...M.HealthCheckIntervalSeconds, unit: "seconds" }}>
          <input name="interval" type="number" defaultValue={g.HealthCheckIntervalSeconds} />
        </Field>
        <Field label="Timeout" rule={{ ...M.HealthCheckTimeoutSeconds, unit: "seconds" }}>
          <input name="timeout" type="number" defaultValue={g.HealthCheckTimeoutSeconds} />
        </Field>
      </div>
      <div className="form-row">
        <Field label="Healthy threshold" rule={M.HealthyThresholdCount}>
          <input name="healthy" type="number" defaultValue={g.HealthyThresholdCount} />
        </Field>
        <Field label="Unhealthy threshold" rule={M.UnhealthyThresholdCount}>
          <input name="unhealthy" type="number" defaultValue={g.UnhealthyThresholdCount} />
        </Field>
      </div>
    </ActionForm>
  );
}

export default async function TargetGroup({ searchParams }: Props) {
  const { arn = "", tab = "targets" } = await searchParams;
  const back = { href: "/elb?tab=targets", label: "Target groups" };
  const data = await load(async () => {
    const client = await elb();
    const [group, targets] = await Promise.all([
      client.send(new DescribeTargetGroupsCommand({ TargetGroupArns: [arn] })).then((r) => r.TargetGroups![0]),
      client.send(new DescribeTargetHealthCommand({ TargetGroupArn: arn })).then((r) => r.TargetHealthDescriptions ?? []),
    ]);
    const lbs = group.LoadBalancerArns?.length
      ? await client.send(new DescribeLoadBalancersCommand({ LoadBalancerArns: group.LoadBalancerArns })).then((r) => r.LoadBalancers ?? [], () => [])
      : [];
    return { group, targets, lbs, known: await knownTargets(group.TargetType, group.VpcId) };
  });
  if (!data.ok) {
    return (
      <Page title="Target group" icon={ICONS.elb} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { group: g, targets, lbs, known } = data.value;
  const [, , , region, account] = (g.TargetGroupArn ?? "").split(":");
  const rule = targetsRule(g.TargetType, `arn:aws:lambda:${region}:${account}:function:{}`);
  const example = known[0] ?? (g.TargetType === "ip" ? "10.0.0.10" : g.TargetType === "lambda" ? "arn:aws:lambda:…" : "i-0123456789abcdef0");
  const href = (t: string) => `/elb/tg?arn=${encodeURIComponent(arn)}${t === "targets" ? "" : `&tab=${t}`}`;
  const tabs = [
    { label: "Targets", href: href("targets"), active: tab === "targets", count: targets.length },
    { label: "Health checks", href: href("health"), active: tab === "health" },
    { label: "Attributes", href: href("attributes"), active: tab === "attributes" },
    { label: "Tags", href: href("tags"), active: tab === "tags" },
  ];
  const settling = targets.some((t) => t.TargetHealth?.State === "initial" || t.TargetHealth?.State === "draining");
  return (
    <Page
      title={g.TargetGroupName}
      icon={ICONS.elb}
      back={back}
      subtitle={g.TargetGroupArn}
      actions={
        <>
          <Sheet title="Register targets" label="Register targets" icon={<Plus size={16} />} testId="register-targets">
            <ActionForm action={registerTargets.bind(null, arn)} submit="Register" testId="register-targets">
              <Field label="Targets" rule={rule} known={known} member="Targets">
                <textarea name="targets" rows={3} required placeholder={example} />
              </Field>
              {g.TargetType !== "lambda" && (
                <div className="form-row">
                  <Field label="Port" rule={TARGET_PORT} format="port">
                    <input name="port" type="number" defaultValue={g.Port} />
                  </Field>
                  {g.TargetType === "ip" && (
                    <Field label="Availability Zone" member="AvailabilityZone" hint="all for addresses outside the VPC">
                      <input name="zone" placeholder="all" />
                    </Field>
                  )}
                </div>
              )}
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteTargetGroup.bind(null, arn)} submit="Delete target group" icon={<X size={16} />} tone="danger" confirm={`Delete ${g.TargetGroupName}?`} testId="delete-target-group" />
        </>
      }
    >
      {settling && <LiveRefresh />}
      <Specs
        items={[
          g.Protocol && { label: "Protocol", icon: <Network size={15} />, value: `${g.Protocol}:${g.Port}${g.ProtocolVersion ? ` · ${g.ProtocolVersion}` : ""}` },
          { label: "Target type", icon: <Server size={15} />, value: g.TargetType },
          g.HealthCheckProtocol && {
            label: "Health check",
            icon: <HeartPulse size={15} />,
            value: `${g.HealthCheckProtocol} ${g.HealthCheckPath ?? ""}${g.HealthCheckPort && g.HealthCheckPort !== "traffic-port" ? `:${g.HealthCheckPort}` : ""} · ${g.HealthCheckIntervalSeconds}s`,
          },
          g.VpcId && { label: "VPC", icon: <AwsIcon icon={ICONS.vpc} size={16} />, value: <Link href={`/vpc/${g.VpcId}`}>{g.VpcId}</Link> },
          ...lbs.map((l) => ({ label: `Load balancer ${l.LoadBalancerName}`, icon: <AwsIcon icon={LB_ICON[l.Type ?? "application"] ?? ICONS.alb} size={16} />, value: <Link href={lbHref(l.LoadBalancerArn)}>{l.LoadBalancerName}</Link> })),
        ]}
      />
      <Segments label="Target group" items={tabs} />
      {tab === "targets" && (
        <List
          label="Targets"
          empty={<Empty icon={TARGET_ICON[g.TargetType ?? "instance"]} />}
          rows={targets.map((t) => {
            const id = t.Target!.Id!;
            const state = t.TargetHealth?.State ?? "unknown";
            return {
              key: `${id}:${t.Target?.Port}`,
              icon: <AwsIcon icon={TARGET_ICON[g.TargetType ?? "instance"]} size={22} />,
              title: id.startsWith("arn:") ? id.split(/[:/]/).slice(-2).join("/") : id,
              subtitle: [t.TargetHealth?.Reason, t.TargetHealth?.Description, t.Target?.AvailabilityZone].filter(Boolean).join(" · ") || undefined,
              href: targetHref(id),
              meta: (
                <>
                  {t.Target?.Port && <span>:{t.Target.Port}</span>}
                  {t.AnomalyDetection?.Result === "anomalous" && <Status tone="bad">anomalous</Status>}
                  <Status tone={HEALTH_TONE[state] ?? "neutral"}>{state}</Status>
                </>
              ),
              actions: <ActionForm action={deregisterTarget.bind(null, arn, id, t.Target?.Port, t.Target?.AvailabilityZone)} submit={`Deregister ${id}`} icon={<X size={15} />} tone="danger" />,
            };
          })}
        />
      )}
      {tab === "health" && (
        <Section
          title="Health check settings"
          plain
          actions={
            <Sheet title="Edit health check" label="Edit health check" icon={<Pencil size={16} />} testId="edit-health-check">
              <HealthCheckForm g={g} />
            </Sheet>
          }
        >
          <Specs
            items={[
              { label: "Enabled", icon: <HeartPulse size={15} />, value: g.HealthCheckEnabled === false ? "Off" : "On" },
              g.HealthCheckProtocol && { label: "Protocol", icon: <Network size={15} />, value: `${g.HealthCheckProtocol} ${g.HealthCheckPort ?? ""}` },
              g.HealthCheckPath && { label: "Path", icon: <Network size={15} />, value: g.HealthCheckPath },
              { label: "Interval / timeout", icon: <HeartPulse size={15} />, value: `${g.HealthCheckIntervalSeconds}s / ${g.HealthCheckTimeoutSeconds}s` },
              { label: "Thresholds", icon: <HeartPulse size={15} />, value: `${g.HealthyThresholdCount} healthy · ${g.UnhealthyThresholdCount} unhealthy` },
              (g.Matcher?.HttpCode || g.Matcher?.GrpcCode) && { label: "Success codes", icon: <HeartPulse size={15} />, value: g.Matcher.HttpCode ?? g.Matcher.GrpcCode },
            ]}
          />
        </Section>
      )}
      {tab === "attributes" && <Attributes arn={arn} />}
      {tab === "tags" && <TgTags arn={arn} />}
    </Page>
  );
}

async function Attributes({ arn }: { arn: string }) {
  const attrs = await load(async () => (await (await elb()).send(new DescribeTargetGroupAttributesCommand({ TargetGroupArn: arn }))).Attributes ?? []);
  if (!attrs.ok) return <ErrorNotice error={attrs.error} />;
  return <AttributesForm attributes={attrs.value} action={modifyTgAttributes.bind(null, arn)} testId="tg-attributes" />;
}

async function TgTags({ arn }: { arn: string }) {
  const tags = await load(async () => (await (await elb()).send(new DescribeTagsCommand({ ResourceArns: [arn] }))).TagDescriptions?.[0]?.Tags ?? []);
  if (!tags.ok) return <ErrorNotice error={tags.error} />;
  return <TagsSection arn={arn} tags={tags.value} testId="add-tg-tag" />;
}
