import { DescribeVpcsCommand } from "@aws-sdk/client-ec2";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, List, Page, Pill, Sheet, Status } from "@mws-dashboard/ui";
import { CreateLoadBalancer, CreateTargetGroup } from "@mws-dashboard/ui/model/elbv2";
import type { Metadata } from "next";

import { ICONS, LB_ICON, ec2, nameTag } from "../../lib/clients";
import { healthCounts, listLoadBalancers, listTargetGroups } from "../../lib/elb";
import { HEALTH_PATH, LB_NAME, PORT, TG_NAME } from "../../lib/rules";
import { createLoadBalancer, createTargetGroup } from "./actions";

export const metadata: Metadata = { title: "Load balancers" };

type Props = { searchParams: Promise<{ tab?: string }> };

export default async function LoadBalancers({ searchParams }: Props) {
  const { tab = "lbs" } = await searchParams;
  const vpcs = await load(async () => (await (await ec2()).send(new DescribeVpcsCommand({}))).Vpcs ?? []);
  const vpcOptions = vpcs.ok
    ? vpcs.value.map((v) => (
        <option key={v.VpcId} value={v.VpcId}>
          {nameTag(v) ?? v.VpcId} · {v.CidrBlock}
        </option>
      ))
    : null;

  if (tab === "targets") {
    const groups = await load(listTargetGroups);
    const names = groups.ok ? groups.value.map((g) => g.group.TargetGroupName!) : [];
    const create = (
      <Sheet title="Create target group" label="Create target group" testId="create-target-group">
        <ActionForm action={createTargetGroup} submit="Create target group" testId="create-target-group">
          <Field label="Name" rule={TG_NAME} taken={names} unique>
            <input name="name" required maxLength={32} autoFocus />
          </Field>
          <Field label="Target type" rule={CreateTargetGroup.TargetType}>
            <select name="targetType" defaultValue="instance">
              <option value="instance">Instances</option>
              <option value="ip">IP addresses</option>
              <option value="lambda">Lambda function</option>
              <option value="alb">Application Load Balancer</option>
            </select>
          </Field>
          <div className="form-row">
            <Field label="Protocol" rule={CreateTargetGroup.Protocol}>
              <select name="protocol" defaultValue="HTTP">
                {["HTTP", "HTTPS", "TCP", "UDP", "TLS", "TCP_UDP"].map((p) => (
                  <option key={p}>{p}</option>
                ))}
              </select>
            </Field>
            <Field label="Port" rule={PORT} format="port">
              <input name="port" type="number" defaultValue={80} />
            </Field>
          </div>
          <Field label="VPC" member="VpcId">
            <select name="vpc">{vpcOptions}</select>
          </Field>
          <Field label="Health check path" rule={HEALTH_PATH}>
            <input name="healthPath" placeholder="/" />
          </Field>
        </ActionForm>
      </Sheet>
    );
    return (
      <Page title="Target groups" actions={create}>
        {groups.ok ? (
          <List
            label="Target groups"
            empty={<Empty icon={ICONS.elb} action={create} />}
            rows={groups.value.map(({ group: g, targets }) => {
              const { healthy, total } = healthCounts(targets);
              return {
                key: g.TargetGroupArn!,
                icon: <AwsIcon icon={g.TargetType === "lambda" ? "resource/AWSLambdaLambdaFunction" : ICONS.elb} size={24} />,
                title: g.TargetGroupName,
                subtitle: g.Protocol ? `${g.Protocol}:${g.Port} · ${g.TargetType}` : g.TargetType,
                href: `/elb/tg?arn=${encodeURIComponent(g.TargetGroupArn!)}`,
                meta: (
                  <>
                    {g.LoadBalancerArns?.length === 0 && <Pill>Unused</Pill>}
                    <Status tone={total === 0 ? "neutral" : healthy === total ? "good" : healthy === 0 ? "bad" : "warn"}>
                      {healthy}/{total} healthy
                    </Status>
                  </>
                ),
              };
            })}
          />
        ) : (
          <ErrorNotice error={groups.error} />
        )}
      </Page>
    );
  }

  const lbs = await load(listLoadBalancers);
  const names = lbs.ok ? lbs.value.map((l) => l.LoadBalancerName!) : [];
  const create = (
    <Sheet title="Create load balancer" label="Create load balancer" testId="create-load-balancer">
      <ActionForm action={createLoadBalancer} submit="Create load balancer" testId="create-load-balancer">
        <Field label="Name" rule={LB_NAME} taken={names} unique>
          <input name="name" required maxLength={32} autoFocus />
        </Field>
        <div className="form-row">
          <Field label="Type" rule={CreateLoadBalancer.Type}>
            <select name="type" defaultValue="application">
              <option value="application">Application</option>
              <option value="network">Network</option>
              <option value="gateway">Gateway</option>
            </select>
          </Field>
          <Field label="Scheme" rule={CreateLoadBalancer.Scheme}>
            <select name="scheme" defaultValue="internet-facing">
              <option value="internet-facing">Internet-facing</option>
              <option value="internal">Internal</option>
            </select>
          </Field>
        </div>
        <Field label="VPC" member="Subnets">
          <select name="vpc" required>
            {vpcOptions}
          </select>
        </Field>
      </ActionForm>
    </Sheet>
  );
  if (!lbs.ok) {
    return (
      <Page title="Load balancers" actions={create}>
        <ErrorNotice error={lbs.error} />
      </Page>
    );
  }
  return (
    <Page title="Load balancers" actions={create}>
      <Curated
        label="Load balancers"
        sections={[
          { id: "internet", title: "Internet-facing", items: lbs.value.filter((l) => l.Scheme === "internet-facing") },
          { id: "internal", title: "Internal", items: lbs.value.filter((l) => l.Scheme !== "internet-facing") },
        ]}
        empty={<Empty icon={ICONS.alb} action={create} />}
        row={(l) => ({
          key: l.LoadBalancerArn!,
          icon: <AwsIcon icon={LB_ICON[l.Type ?? "application"] ?? ICONS.alb} size={24} />,
          title: l.LoadBalancerName,
          subtitle: <code className="clip">{l.DNSName}</code>,
          href: `/elb/lb?arn=${encodeURIComponent(l.LoadBalancerArn!)}`,
          meta: (
            <>
              <Pill>{l.Type}</Pill>
              <Status tone={l.State?.Code === "active" ? "good" : l.State?.Code === "failed" ? "bad" : "warn"}>{l.State?.Code}</Status>
              <span>{ago(l.CreatedTime)}</span>
            </>
          ),
        })}
      />
    </Page>
  );
}
