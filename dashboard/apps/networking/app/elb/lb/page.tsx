import { ListCertificatesCommand } from "@aws-sdk/client-acm";
import { DescribeListenersCommand, DescribeLoadBalancersCommand, DescribeRulesCommand, DescribeTargetGroupsCommand, type Action } from "@aws-sdk/client-elastic-load-balancing-v2";
import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, ErrorNotice, Field, List, Page, Pill, Section, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { ArrowRight, Clock, Globe, Lock, Network, Plus, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, LB_ICON, acm, elb } from "../../../lib/clients";
import { createListener, deleteListener, deleteLoadBalancer } from "../actions";

export const metadata: Metadata = { title: "Load balancer" };

type Props = { searchParams: Promise<{ arn?: string }> };

function describeAction(a: Action, groupName: (arn: string | undefined) => string | undefined) {
  if (a.Type === "forward") {
    const groups = a.ForwardConfig?.TargetGroups?.map((g) => g.TargetGroupArn) ?? [a.TargetGroupArn];
    return `→ ${groups.map(groupName).join(", ")}`;
  }
  if (a.Type === "redirect") return `↪ ${a.RedirectConfig?.Protocol ?? "#{protocol}"}:${a.RedirectConfig?.Port ?? "#{port}"} ${a.RedirectConfig?.StatusCode ?? ""}`;
  if (a.Type === "fixed-response") return `${a.FixedResponseConfig?.StatusCode} ${a.FixedResponseConfig?.MessageBody ?? ""}`;
  return a.Type ?? "";
}

export default async function LoadBalancer({ searchParams }: Props) {
  const { arn = "" } = await searchParams;
  const back = { href: "/elb", label: "Load balancers" };
  const data = await load(async () => {
    const client = await elb();
    const [lb, listeners, groups, certs] = await Promise.all([
      client.send(new DescribeLoadBalancersCommand({ LoadBalancerArns: [arn] })).then((r) => r.LoadBalancers![0]),
      client.send(new DescribeListenersCommand({ LoadBalancerArn: arn })).then((r) => r.Listeners ?? []),
      client.send(new DescribeTargetGroupsCommand({})).then((r) => r.TargetGroups ?? []),
      (await acm()).send(new ListCertificatesCommand({ CertificateStatuses: ["ISSUED"] })).then((r) => r.CertificateSummaryList ?? [], () => []),
    ]);
    const rules = await Promise.all(listeners.map((l) => client.send(new DescribeRulesCommand({ ListenerArn: l.ListenerArn })).then((r) => r.Rules ?? [], () => [])));
    return { lb, listeners, groups, certs, rules };
  });
  if (!data.ok) {
    return (
      <Page title="Load balancer" icon={ICONS.alb} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { lb, listeners, groups, certs, rules } = data.value;
  const groupName = (a: string | undefined) => groups.find((g) => g.TargetGroupArn === a)?.TargetGroupName ?? a?.split("/")[1];
  const mine = groups.filter((g) => g.VpcId === lb.VpcId || g.TargetType === "lambda");
  const application = lb.Type === "application";
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
              <div className="form-row">
                <Field label="Protocol">
                  <select name="protocol" defaultValue={application ? "HTTP" : "TCP"}>
                    {(application ? ["HTTP", "HTTPS"] : lb.Type === "gateway" ? ["GENEVE"] : ["TCP", "TLS", "UDP", "TCP_UDP"]).map((p) => (
                      <option key={p}>{p}</option>
                    ))}
                  </select>
                </Field>
                <Field label="Port">
                  <input name="port" type="number" min={1} max={65535} defaultValue={80} required />
                </Field>
              </div>
              <Field label="Forward to">
                <select name="targetGroup" defaultValue={mine[0]?.TargetGroupArn ?? ""}>
                  <option value="">Fixed 404 response</option>
                  {mine.map((g) => (
                    <option key={g.TargetGroupArn} value={g.TargetGroupArn}>
                      {g.TargetGroupName}
                    </option>
                  ))}
                </select>
              </Field>
              {certs.length > 0 && (
                <Field label="Certificate (HTTPS, TLS)">
                  <select name="certificate" defaultValue="">
                    <option value="">—</option>
                    {certs.map((c) => (
                      <option key={c.CertificateArn} value={c.CertificateArn}>
                        {c.DomainName}
                      </option>
                    ))}
                  </select>
                </Field>
              )}
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteLoadBalancer.bind(null, arn)} submit="Delete load balancer" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${lb.LoadBalancerName}?`} testId="delete-load-balancer" />
        </>
      }
    >
      <Specs
        items={[
          { label: "State", icon: <Network size={15} />, value: <Status tone={lb.State?.Code === "active" ? "good" : lb.State?.Code === "failed" ? "bad" : "warn"}>{lb.State?.Code}</Status> },
          { label: "Scheme", icon: lb.Scheme === "internet-facing" ? <Globe size={15} /> : <Lock size={15} />, value: lb.Scheme },
          { label: "VPC", icon: <AwsIcon icon={ICONS.vpc} size={16} />, value: <a href={`/networking/vpc/${lb.VpcId}`}>{lb.VpcId}</a> },
          { label: "Availability Zones", icon: <AwsIcon icon={ICONS.publicSubnet} size={16} />, value: lb.AvailabilityZones?.map((z) => z.ZoneName).join(", ") },
          lb.IpAddressType && lb.IpAddressType !== "ipv4" && { label: "IP address type", icon: <Network size={15} />, value: lb.IpAddressType },
          { label: "Created", icon: <Clock size={15} />, value: lb.CreatedTime?.toISOString().slice(0, 10) },
        ]}
      />
      <CodeBlock value={lb.DNSName} label="DNS name" />
      <Section title="Listeners" count={listeners.length} plain>
        <List
          label="Listeners"
          empty={<div className="empty">No listeners</div>}
          rows={listeners.map((l, i) => ({
            key: l.ListenerArn!,
            icon: <Pill tone={l.Protocol === "HTTPS" || l.Protocol === "TLS" ? "good" : "neutral"}>{l.Protocol}</Pill>,
            title: `:${l.Port}`,
            subtitle: (
              <>
                {(l.DefaultActions ?? []).map((a) => describeAction(a, groupName)).join(" · ")}
                {rules[i].filter((r) => !r.IsDefault).length > 0 && ` · ${rules[i].filter((r) => !r.IsDefault).length} rules`}
              </>
            ),
            meta: l.Certificates?.length ? <Lock size={14} aria-label="TLS" /> : undefined,
            actions: <ActionForm action={deleteListener.bind(null, l.ListenerArn!)} submit={`Delete listener ${l.Port}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete the :${l.Port} listener?`} />,
          }))}
        />
      </Section>
      {groups.some((g) => g.LoadBalancerArns?.includes(arn)) && (
        <Section title="Target groups" plain>
          <List
            label="Target groups"
            rows={groups
              .filter((g) => g.LoadBalancerArns?.includes(arn))
              .map((g) => ({
                key: g.TargetGroupArn!,
                icon: <ArrowRight size={18} />,
                title: g.TargetGroupName,
                subtitle: g.Protocol ? `${g.Protocol}:${g.Port}` : g.TargetType,
                href: `/elb/tg?arn=${encodeURIComponent(g.TargetGroupArn!)}`,
              }))}
          />
        </Section>
      )}
    </Page>
  );
}
