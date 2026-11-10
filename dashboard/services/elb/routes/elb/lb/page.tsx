import { DescribeSecurityGroupsCommand } from "@aws-sdk/client-ec2";
import {
  DescribeListenersCommand,
  DescribeLoadBalancerAttributesCommand,
  DescribeLoadBalancersCommand,
  DescribeRulesCommand,
  DescribeTagsCommand,
  DescribeTargetHealthCommand,
  type LoadBalancer as LoadBalancerT,
} from "@aws-sdk/client-elastic-load-balancing-v2";
import { all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Field, List, Page, Pill, Section, Segments, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { TagsSection } from "../../../lib/tags";
import { Clock, Globe, Lock, Network, Plus, Route, Shield, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { AttributesForm } from "../../../lib/attributes";
import { ICONS, LB_ICON, ec2, elb, nameTag } from "../../../lib/clients";
import { HEALTH_TONE, allTargetGroups, healthCounts, listenerHref, tgHref } from "../../../lib/elb";
import { describeAction } from "../../../lib/listener";
import { ListenerFields, listenerChoices } from "../../../lib/listener-form";
import { network } from "../../../lib/vpc";
import { createListener, deleteListener, deleteLoadBalancer, modifyLbAttributes, setIpAddressType, setSecurityGroups, setSubnets } from "../actions";

export const metadata: Metadata = { title: "Load balancer" };

type Props = { searchParams: Promise<{ arn?: string; tab?: string }> };

export default async function LoadBalancer({ searchParams }: Props) {
  const { arn = "", tab = "listeners" } = await searchParams;
  const back = { href: "/elb", label: "Load balancers" };
  const data = await load(async () => {
    const client = await elb();
    const [lb, listeners, groups, choices] = await Promise.all([
      client.send(new DescribeLoadBalancersCommand({ LoadBalancerArns: [arn] })).then((r) => r.LoadBalancers![0]),
      all(
        (Marker) => client.send(new DescribeListenersCommand({ LoadBalancerArn: arn, Marker })),
        (r) => r.Listeners,
        (r) => r.NextMarker,
      ),
      allTargetGroups(),
      listenerChoices(),
    ]);
    const rules = await Promise.all(listeners.map((l) => client.send(new DescribeRulesCommand({ ListenerArn: l.ListenerArn })).then((r) => r.Rules ?? [], () => [])));
    return { lb, listeners, groups, choices, rules };
  });
  if (!data.ok) {
    return (
      <Page title="Load balancer" icon={ICONS.alb} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { lb, listeners, groups, choices, rules } = data.value;
  const groupName = (a: string | undefined) => groups.find((g) => g.TargetGroupArn === a)?.TargetGroupName ?? a?.split("/")[1];
  const ports = listeners.map((l) => String(l.Port));
  const href = (t: string) => `/elb/lb?arn=${encodeURIComponent(arn)}${t === "listeners" ? "" : `&tab=${t}`}`;
  const tabs = [
    { label: "Listeners and rules", href: href("listeners"), active: tab === "listeners", count: listeners.length },
    { label: "Network mapping", href: href("network"), active: tab === "network" },
    lb.Type !== "gateway" && { label: "Security", href: href("security"), active: tab === "security", count: lb.SecurityGroups?.length },
    { label: "Attributes", href: href("attributes"), active: tab === "attributes" },
    { label: "Tags", href: href("tags"), active: tab === "tags" },
  ].filter((t): t is { label: string; href: string; active: boolean; count?: number } => !!t);
  const mine = groups.filter((g) => g.LoadBalancerArns?.includes(arn));
  return (
    <Page
      title={lb.LoadBalancerName}
      icon={LB_ICON[lb.Type ?? "application"]}
      back={back}
      subtitle={lb.LoadBalancerArn}
      actions={
        <>
          <Sheet title="Add listener" label="Add listener" icon={<Plus size={16} />} testId="add-listener">
            <ActionForm action={createListener.bind(null, arn)} submit="Add listener" testId="add-listener">
              <ListenerFields lb={lb} groups={groups} choices={choices} taken={ports} />
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteLoadBalancer.bind(null, arn)} submit="Delete load balancer" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${lb.LoadBalancerName}?`} testId="delete-load-balancer" />
        </>
      }
    >
      <Specs
        items={[
          { label: "State", icon: <Network size={15} />, value: <Status tone={lb.State?.Code === "active" ? "good" : lb.State?.Code === "failed" ? "bad" : "warn"}>{lb.State?.Code}</Status> },
          lb.Scheme && { label: "Scheme", icon: lb.Scheme === "internet-facing" ? <Globe size={15} /> : <Lock size={15} />, value: lb.Scheme },
          { label: "VPC", icon: <AwsIcon icon={ICONS.vpc} size={16} />, value: <Link href={`/vpc/${lb.VpcId}`}>{lb.VpcId}</Link> },
          lb.IpAddressType && lb.IpAddressType !== "ipv4" && { label: "IP address type", icon: <Network size={15} />, value: lb.IpAddressType },
          lb.CanonicalHostedZoneId && { label: "Hosted zone (for Route 53 aliases)", icon: <AwsIcon icon="resource/AmazonRoute53HostedZone" size={16} />, value: <code>{lb.CanonicalHostedZoneId}</code> },
          { label: "Created", icon: <Clock size={15} />, value: lb.CreatedTime?.toISOString().slice(0, 10) },
        ]}
      />
      {lb.DNSName && <CodeBlock value={lb.DNSName} label="DNS name" />}
      <Segments label="Load balancer" items={tabs} />
      {tab === "listeners" && (
        <>
          <Section title="Listeners" count={listeners.length} plain>
            <List
              label="Listeners"
              empty={<div className="empty">No listeners</div>}
              rows={listeners.map((l, i) => {
                const extra = rules[i].filter((r) => !r.IsDefault).length;
                return {
                  key: l.ListenerArn!,
                  icon: <Pill tone={l.Protocol === "HTTPS" || l.Protocol === "TLS" ? "good" : "neutral"}>{l.Protocol ?? "GENEVE"}</Pill>,
                  title: l.Port ? `:${l.Port}` : "All traffic",
                  subtitle: (l.DefaultActions ?? []).map((a) => describeAction(a, groupName)).join(" · "),
                  href: listenerHref(l.ListenerArn),
                  meta: (
                    <>
                      {extra > 0 && (
                        <span title="Rules">
                          <Route size={13} aria-hidden /> {extra}
                        </span>
                      )}
                      {l.Certificates?.length ? <Lock size={14} aria-label="TLS" /> : null}
                      {l.MutualAuthentication?.Mode && l.MutualAuthentication.Mode !== "off" && <Pill>mTLS</Pill>}
                    </>
                  ),
                  actions: <ActionForm action={deleteListener.bind(null, l.ListenerArn!, undefined)} submit={`Delete listener ${l.Port ?? ""}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete the :${l.Port} listener?`} />,
                };
              })}
            />
          </Section>
          {mine.length > 0 && <TargetGroupsHealth groups={mine} />}
        </>
      )}
      {tab === "network" && <NetworkTab lb={lb} />}
      {tab === "security" && <SecurityTab lb={lb} />}
      {tab === "attributes" && <AttributesTab arn={arn} />}
      {tab === "tags" && <TagsTab arn={arn} />}
    </Page>
  );
}

async function TargetGroupsHealth({ groups }: { groups: Awaited<ReturnType<typeof allTargetGroups>> }) {
  const client = await elb();
  const health = await Promise.all(groups.map((g) => client.send(new DescribeTargetHealthCommand({ TargetGroupArn: g.TargetGroupArn })).then((r) => r.TargetHealthDescriptions ?? [], () => [])));
  return (
    <Section title="Target groups" count={groups.length} plain>
      <List
        label="Target groups"
        rows={groups.map((g, i) => {
          const { healthy, total } = healthCounts(health[i]);
          return {
            key: g.TargetGroupArn!,
            icon: <AwsIcon icon={ICONS.elb} size={20} />,
            title: g.TargetGroupName,
            subtitle: g.Protocol ? `${g.Protocol}:${g.Port}` : g.TargetType,
            href: tgHref(g.TargetGroupArn),
            meta: <Status tone={total === 0 ? "neutral" : healthy === total ? "good" : healthy === 0 ? "bad" : HEALTH_TONE.initial}>{`${healthy}/${total} healthy`}</Status>,
          };
        })}
      />
    </Section>
  );
}

async function NetworkTab({ lb }: { lb: LoadBalancerT }) {
  const net = await load(() => network(lb.VpcId));
  const inUse = new Set(lb.AvailabilityZones?.map((z) => z.SubnetId));
  return (
    <>
      <Section
        title="Availability Zones"
        count={lb.AvailabilityZones?.length}
        plain
        actions={
          net.ok && (
            <Sheet title="Edit subnets" label="Edit subnets" testId="edit-subnets">
              <ActionForm action={setSubnets.bind(null, lb.LoadBalancerArn!)} submit="Save" testId="edit-subnets">
                <fieldset className="checks" aria-label="Subnets">
                  {net.value.subnets.map((s) => (
                    <label key={s.SubnetId} className="check">
                      <input type="checkbox" name="subnets" value={s.SubnetId} defaultChecked={inUse.has(s.SubnetId)} /> {nameTag(s) ?? s.SubnetId} · {s.AvailabilityZone}
                    </label>
                  ))}
                </fieldset>
              </ActionForm>
            </Sheet>
          )
        }
      >
        <List
          label="Availability Zones"
          rows={(lb.AvailabilityZones ?? []).map((z) => ({
            key: z.SubnetId ?? z.ZoneName!,
            icon: <AwsIcon icon={ICONS.publicSubnet} size={20} />,
            title: z.ZoneName,
            subtitle: [z.SubnetId, ...(z.LoadBalancerAddresses ?? []).map((a) => a.IpAddress ?? a.PrivateIPv4Address).filter(Boolean)].join(" · "),
            href: z.SubnetId ? `/vpc/subnet?id=${z.SubnetId}` : undefined,
          }))}
        />
      </Section>
      {lb.Type !== "gateway" && (
        <Section title="IP address type" plain>
          <ActionForm action={setIpAddressType.bind(null, lb.LoadBalancerArn!)} submit="Save" testId="set-ip-type" inline>
            <Field label="IP address type" member="IpAddressType">
              <select name="ipType" defaultValue={lb.IpAddressType ?? "ipv4"}>
                <option value="ipv4">IPv4</option>
                <option value="dualstack">Dualstack</option>
                {lb.Type === "application" && <option value="dualstack-without-public-ipv4">Dualstack without public IPv4</option>}
              </select>
            </Field>
          </ActionForm>
        </Section>
      )}
    </>
  );
}

async function SecurityTab({ lb }: { lb: LoadBalancerT }) {
  const groups = await load(async () => (await (await ec2()).send(new DescribeSecurityGroupsCommand({ Filters: [{ Name: "vpc-id", Values: [lb.VpcId!] }] }))).SecurityGroups ?? []);
  if (!groups.ok) return <ErrorNotice error={groups.error} />;
  const on = new Set(lb.SecurityGroups ?? []);
  return (
    <Section
      title="Security groups"
      count={on.size}
      plain
      actions={
        <Sheet title="Edit security groups" label="Edit security groups" testId="edit-security-groups">
          <ActionForm action={setSecurityGroups.bind(null, lb.LoadBalancerArn!)} submit="Save" testId="edit-security-groups">
            <fieldset className="checks" aria-label="Security groups">
              {groups.value.map((g) => (
                <label key={g.GroupId} className="check">
                  <input type="checkbox" name="securityGroups" value={g.GroupId} defaultChecked={on.has(g.GroupId!)} /> {g.GroupName}
                </label>
              ))}
            </fieldset>
          </ActionForm>
        </Sheet>
      }
    >
      <List
        label="Security groups"
        empty={<Empty icon={ICONS.sg} />}
        rows={groups.value
          .filter((g) => on.has(g.GroupId!))
          .map((g) => ({
            key: g.GroupId!,
            icon: <Shield size={18} />,
            title: g.GroupName,
            subtitle: g.GroupId,
            href: `/ec2/group?id=${g.GroupId}`,
          }))}
      />
    </Section>
  );
}

async function AttributesTab({ arn }: { arn: string }) {
  const attrs = await load(async () => (await (await elb()).send(new DescribeLoadBalancerAttributesCommand({ LoadBalancerArn: arn }))).Attributes ?? []);
  if (!attrs.ok) return <ErrorNotice error={attrs.error} />;
  return <AttributesForm attributes={attrs.value} action={modifyLbAttributes.bind(null, arn)} testId="lb-attributes" />;
}

async function TagsTab({ arn }: { arn: string }) {
  const tags = await load(async () => (await (await elb()).send(new DescribeTagsCommand({ ResourceArns: [arn] }))).TagDescriptions?.[0]?.Tags ?? []);
  if (!tags.ok) return <ErrorNotice error={tags.error} />;
  return <TagsSection arn={arn} tags={tags.value} testId="add-lb-tag" />;
}
