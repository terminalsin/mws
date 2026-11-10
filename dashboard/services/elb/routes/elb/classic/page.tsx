import { DescribeInstanceHealthCommand, DescribeLoadBalancerAttributesCommand, DescribeLoadBalancersCommand } from "@aws-sdk/client-elastic-load-balancing";
import { DescribeInstancesCommand } from "@aws-sdk/client-ec2";
import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Field, List, Page, Pill, Section, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { Globe, HeartPulse, Lock, Pencil, Plus, Settings, Trash2, X } from "lucide-react";
import { ConfigureHealthCheck } from "@mws-dashboard/ui/model/elb";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, classic, ec2 } from "../../../lib/clients";
import { addClassicListeners, classicAttributes, configureClassicHealth, deleteClassic, deleteClassicListener, deregisterInstance, registerInstances } from "../classic-actions";

export const metadata: Metadata = { title: "Classic Load Balancer" };

type Props = { searchParams: Promise<{ name?: string }> };

const HC = ConfigureHealthCheck.HealthCheck.fields!;
const LISTENERS = { required: true, pattern: "^\\s*((HTTPS?|TCP|SSL):)?\\d{1,5}(\\s*(->|→|=>)\\s*((HTTPS?|TCP|SSL):)?\\d{1,5})?\\s*([,\\n]\\s*((HTTPS?|TCP|SSL):)?\\d{1,5}(\\s*(->|→|=>)\\s*((HTTPS?|TCP|SSL):)?\\d{1,5})?\\s*)*$", hint: "Like HTTP:80 → HTTP:8080, one per line" };

export default async function ClassicLoadBalancer({ searchParams }: Props) {
  const { name = "" } = await searchParams;
  const back = { href: "/elb?tab=classic", label: "Classic Load Balancers" };
  const data = await load(async () => {
    const client = await classic();
    const [lb, health, attrs] = await Promise.all([
      client.send(new DescribeLoadBalancersCommand({ LoadBalancerNames: [name] })).then((r) => r.LoadBalancerDescriptions![0]),
      client.send(new DescribeInstanceHealthCommand({ LoadBalancerName: name })).then((r) => r.InstanceStates ?? [], () => []),
      client.send(new DescribeLoadBalancerAttributesCommand({ LoadBalancerName: name })).then((r) => r.LoadBalancerAttributes, () => undefined),
    ]);
    const instances = lb.VPCId
      ? await (await ec2())
          .send(new DescribeInstancesCommand({ Filters: [{ Name: "vpc-id", Values: [lb.VPCId] }, { Name: "instance-state-name", Values: ["running", "pending", "stopped"] }] }))
          .then((r) => (r.Reservations ?? []).flatMap((x) => x.Instances ?? []).map((i) => i.InstanceId!), () => [])
      : [];
    return { lb, health, attrs, instances };
  });
  if (!data.ok) {
    return (
      <Page title={name} icon={ICONS.classic} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { lb, health, attrs, instances } = data.value;
  const hc = lb.HealthCheck;
  const registered = new Set(lb.Instances?.map((i) => i.InstanceId));
  return (
    <Page
      title={name}
      icon={ICONS.classic}
      back={back}
      actions={
        <>
          <Sheet title="Register instances" label="Register instances" icon={<Plus size={16} />} testId="register-instances">
            <ActionForm action={registerInstances.bind(null, name)} submit="Register" testId="register-instances">
              <Field label="Instances" rule={{ required: true, pattern: "^i-[0-9a-f]{8,17}([\\s,]+i-[0-9a-f]{8,17})*$", hint: "Instance IDs" }} known={instances.filter((i) => !registered.has(i))}>
                <textarea name="instances" rows={2} placeholder={instances[0] ?? "i-0123456789abcdef0"} />
              </Field>
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteClassic.bind(null, name)} submit="Delete load balancer" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name}?`} testId="delete-classic" />
        </>
      }
    >
      {health.some((h) => h.State === "Unknown") && <LiveRefresh />}
      <Specs
        items={[
          { label: "Scheme", icon: lb.Scheme === "internal" ? <Lock size={15} /> : <Globe size={15} />, value: lb.Scheme },
          lb.VPCId && { label: "VPC", icon: <AwsIcon icon={ICONS.vpc} size={16} />, value: <Link href={`/vpc/${lb.VPCId}`}>{lb.VPCId}</Link> },
          { label: "Availability Zones", icon: <AwsIcon icon={ICONS.publicSubnet} size={16} />, value: lb.AvailabilityZones?.join(", ") },
          lb.CanonicalHostedZoneNameID && { label: "Hosted zone (for Route 53 aliases)", icon: <AwsIcon icon="resource/AmazonRoute53HostedZone" size={16} />, value: <code>{lb.CanonicalHostedZoneNameID}</code> },
          hc && { label: "Health check", icon: <HeartPulse size={15} />, value: `${hc.Target} · ${hc.Interval}s` },
        ]}
      />
      {lb.DNSName && <CodeBlock value={lb.DNSName} label="DNS name" />}
      <Section
        title="Listeners"
        count={lb.ListenerDescriptions?.length}
        plain
        actions={
          <Sheet title="Add listeners" label="Add listeners" testId="add-classic-listener">
            <ActionForm action={addClassicListeners.bind(null, name)} submit="Add" testId="add-classic-listener">
              <Field label="Listeners" rule={LISTENERS}>
                <textarea name="listeners" rows={2} placeholder="HTTP:8080 → HTTP:80" />
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        <List
          label="Listeners"
          rows={(lb.ListenerDescriptions ?? []).map((d) => {
            const l = d.Listener!;
            return {
              key: String(l.LoadBalancerPort),
              icon: <Pill>{l.Protocol}</Pill>,
              title: `:${l.LoadBalancerPort}`,
              subtitle: `→ ${l.InstanceProtocol}:${l.InstancePort}`,
              meta: l.SSLCertificateId ? <Lock size={14} aria-label="TLS" /> : undefined,
              actions: <ActionForm action={deleteClassicListener.bind(null, name, l.LoadBalancerPort!)} submit={`Delete listener ${l.LoadBalancerPort}`} icon={<Trash2 size={15} />} tone="danger" />,
            };
          })}
        />
      </Section>
      <Section title="Instances" count={health.length} plain>
        <List
          label="Instances"
          empty={<Empty icon="resource/AmazonEC2Instance" />}
          rows={health.map((h) => ({
            key: h.InstanceId!,
            icon: <AwsIcon icon="resource/AmazonEC2Instance" size={22} />,
            title: h.InstanceId,
            subtitle: h.Description !== "N/A" ? h.Description : h.ReasonCode,
            href: `/ec2/instance?id=${h.InstanceId}`,
            meta: <Status tone={h.State === "InService" ? "good" : h.State === "OutOfService" ? "bad" : "neutral"}>{h.State}</Status>,
            actions: <ActionForm action={deregisterInstance.bind(null, name, h.InstanceId!)} submit={`Deregister ${h.InstanceId}`} icon={<X size={15} />} tone="danger" />,
          }))}
        />
      </Section>
      <Section
        title="Health check"
        plain
        actions={
          <Sheet title="Edit health check" label="Edit health check" icon={<Pencil size={16} />} testId="classic-health">
            <ActionForm action={configureClassicHealth.bind(null, name)} submit="Save" testId="classic-health">
              <Field label="Ping target" rule={{ ...HC.Target, pattern: "^(HTTPS?:\\d{1,5}/\\S*|(TCP|SSL):\\d{1,5})$", hint: "Like HTTP:80/health or TCP:22" }}>
                <input name="target" defaultValue={hc?.Target ?? "TCP:80"} />
              </Field>
              <div className="form-row">
                <Field label="Interval" rule={{ ...HC.Interval, unit: "seconds" }}>
                  <input name="interval" type="number" defaultValue={hc?.Interval ?? 30} />
                </Field>
                <Field label="Timeout" rule={{ ...HC.Timeout, unit: "seconds" }}>
                  <input name="timeout" type="number" defaultValue={hc?.Timeout ?? 5} />
                </Field>
              </div>
              <div className="form-row">
                <Field label="Healthy threshold" rule={HC.HealthyThreshold}>
                  <input name="healthy" type="number" defaultValue={hc?.HealthyThreshold ?? 10} />
                </Field>
                <Field label="Unhealthy threshold" rule={HC.UnhealthyThreshold}>
                  <input name="unhealthy" type="number" defaultValue={hc?.UnhealthyThreshold ?? 2} />
                </Field>
              </div>
            </ActionForm>
          </Sheet>
        }
      >
        {hc && (
          <Specs
            items={[
              { label: "Target", icon: <HeartPulse size={15} />, value: hc.Target },
              { label: "Interval / timeout", icon: <HeartPulse size={15} />, value: `${hc.Interval}s / ${hc.Timeout}s` },
              { label: "Thresholds", icon: <HeartPulse size={15} />, value: `${hc.HealthyThreshold} healthy · ${hc.UnhealthyThreshold} unhealthy` },
            ]}
          />
        )}
      </Section>
      {attrs && (
        <Section title="Attributes" plain icon={<Settings size={15} />}>
          <ActionForm action={classicAttributes.bind(null, name)} submit="Save attributes" testId="classic-attributes">
            <label className="check">
              <input type="checkbox" name="crossZone" defaultChecked={attrs.CrossZoneLoadBalancing?.Enabled} /> Cross-zone load balancing
            </label>
            <label className="check">
              <input type="checkbox" name="draining" defaultChecked={attrs.ConnectionDraining?.Enabled} /> Connection draining
            </label>
            <div className="form-row">
              <Field label="Draining timeout" rule={{ type: "integer", min: 1, max: 3600, unit: "seconds" }}>
                <input name="drainTimeout" type="number" defaultValue={attrs.ConnectionDraining?.Timeout ?? 300} />
              </Field>
              <Field label="Idle timeout" rule={{ type: "integer", min: 1, max: 4000, unit: "seconds" }}>
                <input name="idle" type="number" defaultValue={attrs.ConnectionSettings?.IdleTimeout ?? 60} />
              </Field>
            </div>
          </ActionForm>
        </Section>
      )}
    </Page>
  );
}
