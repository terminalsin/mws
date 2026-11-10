import {
  DescribeListenerAttributesCommand,
  DescribeListenerCertificatesCommand,
  DescribeListenersCommand,
  DescribeLoadBalancersCommand,
  DescribeRulesCommand,
  DescribeTagsCommand,
} from "@aws-sdk/client-elastic-load-balancing-v2";
import { all, load } from "@mws-dashboard/aws";
import { ActionForm, Empty, ErrorNotice, Field, List, Page, Pill, Section, Segments, Sheet, Specs } from "@mws-dashboard/ui";
import { ArrowDown, ArrowUp, Lock, Network, Pencil, Plus, Route, ShieldCheck, Trash2, X } from "lucide-react";
import { CreateRule } from "@mws-dashboard/ui/model/elbv2";
import type { Metadata } from "next";
import Link from "next/link";

import { ActionFields, ConditionFields } from "../../../lib/action-fields";
import { AttributesForm } from "../../../lib/attributes";
import { ICONS, LB_ICON, elb } from "../../../lib/clients";
import { allTargetGroups, lbHref, tgHref } from "../../../lib/elb";
import { actionDefaults, actionKinds, conditionDefaults, describeAction, describeConditions, forwardGroups } from "../../../lib/listener";
import { ListenerFields, compatibleGroups, listenerChoices } from "../../../lib/listener-form";
import { TagsSection } from "../../../lib/tags";
import { addCertificate, createRule, deleteListener, deleteRule, modifyListener, modifyListenerAttributes, modifyRule, removeCertificate, swapPriorities } from "../actions";

export const metadata: Metadata = { title: "Listener" };

type Props = { searchParams: Promise<{ arn?: string; tab?: string }> };

const PRIORITY = CreateRule.Priority;

export default async function Listener({ searchParams }: Props) {
  const { arn = "", tab = "rules" } = await searchParams;
  const data = await load(async () => {
    const client = await elb();
    const listener = (await client.send(new DescribeListenersCommand({ ListenerArns: [arn] }))).Listeners![0];
    const [lb, siblings, rules, groups, choices] = await Promise.all([
      client.send(new DescribeLoadBalancersCommand({ LoadBalancerArns: [listener.LoadBalancerArn!] })).then((r) => r.LoadBalancers![0]),
      client.send(new DescribeListenersCommand({ LoadBalancerArn: listener.LoadBalancerArn })).then((r) => r.Listeners ?? []),
      all(
        (Marker) => client.send(new DescribeRulesCommand({ ListenerArn: arn, Marker })),
        (r) => r.Rules,
        (r) => r.NextMarker,
      ),
      allTargetGroups(),
      listenerChoices(),
    ]);
    return { listener, lb, siblings, rules, groups, choices };
  });
  if (!data.ok) {
    return (
      <Page title="Listener" icon={ICONS.alb} back={{ href: "/elb", label: "Load balancers" }}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { listener: l, lb, siblings, rules, groups, choices } = data.value;
  const back = { href: lbHref(lb.LoadBalancerArn), label: lb.LoadBalancerName ?? "Load balancer" };
  const groupName = (a: string | undefined) => groups.find((g) => g.TargetGroupArn === a)?.TargetGroupName ?? a?.split("/")[1];
  const application = lb.Type === "application";
  const tls = l.Protocol === "HTTPS" || l.Protocol === "TLS";
  const ordered = rules.filter((r) => !r.IsDefault).sort((a, b) => Number(a.Priority) - Number(b.Priority));
  const used = ordered.map((r) => r.Priority!);
  const nextPriority = String((ordered.length ? Number(ordered[ordered.length - 1].Priority) : 0) + 10);
  const options = compatibleGroups(lb, groups);
  const href = (t: string) => `/elb/listener?arn=${encodeURIComponent(arn)}${t === "rules" ? "" : `&tab=${t}`}`;
  const tabs = [
    { label: "Rules", href: href("rules"), active: tab === "rules", count: rules.length },
    tls && { label: "Certificates", href: href("certificates"), active: tab === "certificates", count: l.Certificates?.length },
    { label: "Attributes", href: href("attributes"), active: tab === "attributes" },
    { label: "Tags", href: href("tags"), active: tab === "tags" },
  ].filter((t): t is { label: string; href: string; active: boolean; count?: number } => !!t);
  const linked = forwardGroups(l.DefaultActions);
  return (
    <Page
      title={l.Port ? `${l.Protocol}:${l.Port}` : "GENEVE listener"}
      icon={LB_ICON[lb.Type ?? "application"]}
      back={back}
      subtitle={arn}
      actions={
        <>
          <Sheet title="Edit listener" label="Edit listener" icon={<Pencil size={16} />} testId="edit-listener">
            <ActionForm action={modifyListener.bind(null, arn)} submit="Save" testId="edit-listener">
              <ListenerFields lb={lb} groups={groups} choices={choices} listener={l} taken={siblings.filter((s) => s.ListenerArn !== arn).map((s) => String(s.Port))} />
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteListener.bind(null, arn, lb.LoadBalancerArn)} submit="Delete listener" icon={<Trash2 size={16} />} tone="danger" confirm="Delete this listener?" testId="delete-listener" />
        </>
      }
    >
      <Specs
        items={[
          { label: "Default action", icon: <Network size={15} />, value: (l.DefaultActions ?? []).map((a) => describeAction(a, groupName)).join(" · ") },
          ...linked.map((g) => ({ label: `Target group ${groupName(g)}`, icon: <Route size={15} />, value: <Link href={tgHref(g)}>{groupName(g)}</Link> })),
          l.SslPolicy && { label: "Security policy", icon: <Lock size={15} />, value: l.SslPolicy },
          l.MutualAuthentication?.Mode && l.MutualAuthentication.Mode !== "off" && { label: "Mutual TLS", icon: <ShieldCheck size={15} />, value: l.MutualAuthentication.Mode },
          l.AlpnPolicy?.length && { label: "ALPN", icon: <Lock size={15} />, value: l.AlpnPolicy.join(", ") },
        ]}
      />
      <Segments label="Listener" items={tabs} />
      {tab === "rules" && (
        <Section
          title="Rules"
          count={rules.length}
          plain
          actions={
            application && (
              <Sheet title="Add rule" label="Add rule" icon={<Plus size={16} />} testId="add-rule">
                <ActionForm action={createRule.bind(null, arn)} submit="Add rule" testId="add-rule">
                  <Field label="Priority" rule={PRIORITY} taken={used} member="Priority">
                    <input name="priority" type="number" required defaultValue={nextPriority} />
                  </Field>
                  <ConditionFields defaults={{}} />
                  <ActionFields groups={options} kinds={actionKinds(lb.Type)} defaults={{ type: "forward" }} />
                </ActionForm>
              </Sheet>
            )
          }
        >
          <List
            label="Rules"
            empty={<Empty icon={ICONS.elb} />}
            rows={[...ordered, ...rules.filter((r) => r.IsDefault)].map((r) => {
              const i = ordered.indexOf(r);
              const prev = i > 0 ? ordered[i - 1] : undefined;
              const next = i >= 0 && i < ordered.length - 1 ? ordered[i + 1] : undefined;
              return {
                key: r.RuleArn!,
                icon: <Pill tone={r.IsDefault ? "neutral" : "info"}>{r.IsDefault ? "default" : r.Priority}</Pill>,
                title: r.IsDefault ? "Otherwise" : describeConditions(r.Conditions) || "Any request",
                subtitle: (r.Actions ?? []).map((a) => describeAction(a, groupName)).join(" · "),
                actions: r.IsDefault ? undefined : (
                  <>
                    {prev && <ActionForm action={swapPriorities.bind(null, r.RuleArn!, Number(r.Priority), prev.RuleArn!, Number(prev.Priority))} submit={`Move rule ${r.Priority} up`} icon={<ArrowUp size={15} />} />}
                    {next && <ActionForm action={swapPriorities.bind(null, r.RuleArn!, Number(r.Priority), next.RuleArn!, Number(next.Priority))} submit={`Move rule ${r.Priority} down`} icon={<ArrowDown size={15} />} />}
                    <Sheet title={`Edit rule ${r.Priority}`} label={`Edit rule ${r.Priority}`} icon={<Pencil size={15} />} testId={`edit-rule-${r.Priority}`}>
                      <ActionForm action={modifyRule.bind(null, r.RuleArn!)} submit="Save rule" testId={`edit-rule-${r.Priority}`}>
                        <input type="hidden" name="wasPriority" value={r.Priority} />
                        <Field label="Priority" rule={PRIORITY} taken={used.filter((p) => p !== r.Priority)} member="Priority">
                          <input name="priority" type="number" required defaultValue={r.Priority} />
                        </Field>
                        <ConditionFields defaults={conditionDefaults(r.Conditions)} />
                        <ActionFields groups={options} kinds={actionKinds(lb.Type)} defaults={actionDefaults(r.Actions)} />
                      </ActionForm>
                    </Sheet>
                    <ActionForm action={deleteRule.bind(null, r.RuleArn!)} submit={`Delete rule ${r.Priority}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete rule ${r.Priority}?`} />
                  </>
                ),
              };
            })}
          />
        </Section>
      )}
      {tab === "certificates" && tls && <Certificates arn={arn} certs={choices.certs} />}
      {tab === "attributes" && <Attributes arn={arn} />}
      {tab === "tags" && <ListenerTags arn={arn} />}
    </Page>
  );
}

async function Certificates({ arn, certs }: { arn: string; certs: { arn: string; domain: string }[] }) {
  const list = await load(async () => {
    const client = await elb();
    return all(
      (Marker) => client.send(new DescribeListenerCertificatesCommand({ ListenerArn: arn, Marker })),
      (r) => r.Certificates,
      (r) => r.NextMarker,
    );
  });
  if (!list.ok) return <ErrorNotice error={list.error} />;
  const domain = (a: string | undefined) => certs.find((c) => c.arn === a)?.domain ?? a?.split("/").pop();
  const attached = new Set(list.value.map((c) => c.CertificateArn));
  const free = certs.filter((c) => !attached.has(c.arn));
  return (
    <Section
      title="Certificates (SNI)"
      count={list.value.length}
      plain
      actions={
        <Sheet title="Add certificate" label="Add certificate" testId="add-certificate">
          <ActionForm action={addCertificate.bind(null, arn)} submit="Add" testId="add-certificate">
            <Field label="Certificate" member="Certificates" hint={free.length ? undefined : <Link href="/acm">Request a certificate</Link>}>
              <select name="certificate" required>
                {free.map((c) => (
                  <option key={c.arn} value={c.arn}>
                    {c.domain}
                  </option>
                ))}
              </select>
            </Field>
          </ActionForm>
        </Sheet>
      }
    >
      <List
        label="Certificates"
        rows={list.value.map((c) => ({
          key: c.CertificateArn!,
          icon: <Lock size={18} />,
          title: domain(c.CertificateArn),
          subtitle: c.CertificateArn,
          href: `/acm/cert?arn=${encodeURIComponent(c.CertificateArn!)}`,
          meta: c.IsDefault ? <Pill tone="info">Default</Pill> : undefined,
          actions: c.IsDefault ? undefined : <ActionForm action={removeCertificate.bind(null, arn, c.CertificateArn!)} submit={`Remove ${domain(c.CertificateArn)}`} icon={<X size={15} />} tone="danger" />,
        }))}
      />
    </Section>
  );
}

async function Attributes({ arn }: { arn: string }) {
  const attrs = await load(async () => (await (await elb()).send(new DescribeListenerAttributesCommand({ ListenerArn: arn }))).Attributes ?? []);
  if (!attrs.ok) return <ErrorNotice error={attrs.error} />;
  if (!attrs.value.length) return <Empty icon={ICONS.elb} />;
  return <AttributesForm attributes={attrs.value} action={modifyListenerAttributes.bind(null, arn)} testId="listener-attributes" />;
}

async function ListenerTags({ arn }: { arn: string }) {
  const tags = await load(async () => (await (await elb()).send(new DescribeTagsCommand({ ResourceArns: [arn] }))).TagDescriptions?.[0]?.Tags ?? []);
  if (!tags.ok) return <ErrorNotice error={tags.error} />;
  return <TagsSection arn={arn} tags={tags.value} testId="add-listener-tag" />;
}
