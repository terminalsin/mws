import { DescribeTargetGroupsCommand, DescribeTargetHealthCommand } from "@aws-sdk/client-elastic-load-balancing-v2";
import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { HeartPulse, Network, Plus, Server, X } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, elb } from "../../../lib/clients";
import { HEALTH_TONE } from "../../../lib/elb";
import { deleteTargetGroup, deregisterTarget, registerTargets } from "../actions";

export const metadata: Metadata = { title: "Target group" };

type Props = { searchParams: Promise<{ arn?: string }> };

const TARGET_ICON: Record<string, string> = {
  instance: "resource/AmazonEC2Instance",
  ip: ICONS.eni,
  lambda: "resource/AWSLambdaLambdaFunction",
  alb: ICONS.alb,
};

export default async function TargetGroup({ searchParams }: Props) {
  const { arn = "" } = await searchParams;
  const back = { href: "/elb?tab=targets", label: "Target groups" };
  const data = await load(async () => {
    const client = await elb();
    const [group, targets] = await Promise.all([
      client.send(new DescribeTargetGroupsCommand({ TargetGroupArns: [arn] })).then((r) => r.TargetGroups![0]),
      client.send(new DescribeTargetHealthCommand({ TargetGroupArn: arn })).then((r) => r.TargetHealthDescriptions ?? []),
    ]);
    return { group, targets };
  });
  if (!data.ok) {
    return (
      <Page title="Target group" icon={ICONS.elb} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { group: g, targets } = data.value;
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
              <textarea name="targets" rows={3} aria-label="Targets" required placeholder={g.TargetType === "ip" ? "10.0.0.10" : g.TargetType === "lambda" ? "arn:aws:lambda:…" : "i-0123456789abcdef0"} />
              {g.TargetType !== "lambda" && (
                <Field label="Port">
                  <input name="port" type="number" min={1} max={65535} defaultValue={g.Port} />
                </Field>
              )}
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteTargetGroup.bind(null, arn)} submit="Delete target group" icon={<X size={16} />} tone="danger" confirm={`Delete ${g.TargetGroupName}?`} testId="delete-target-group" />
        </>
      }
    >
      <Specs
        items={[
          g.Protocol && { label: "Protocol", icon: <Network size={15} />, value: `${g.Protocol}:${g.Port}` },
          { label: "Target type", icon: <Server size={15} />, value: g.TargetType },
          g.HealthCheckProtocol && { label: "Health check", icon: <HeartPulse size={15} />, value: `${g.HealthCheckProtocol} ${g.HealthCheckPath ?? `:${g.HealthCheckPort}`}` },
          g.VpcId && { label: "VPC", icon: <AwsIcon icon={ICONS.vpc} size={16} />, value: <a href={`/networking/vpc/${g.VpcId}`}>{g.VpcId}</a> },
        ]}
      />
      <List
        label="Targets"
        empty={<Empty icon={TARGET_ICON[g.TargetType ?? "instance"]} />}
        rows={targets.map((t) => {
          const id = t.Target!.Id!;
          const state = t.TargetHealth?.State ?? "unknown";
          return {
            key: `${id}:${t.Target?.Port}`,
            icon: <AwsIcon icon={TARGET_ICON[g.TargetType ?? "instance"]} size={22} />,
            title: id.startsWith("arn:") ? id.split(":").pop() : id,
            subtitle: t.TargetHealth?.Description,
            href: id.startsWith("i-") ? `/compute/ec2/instance?id=${id}` : undefined,
            external: true,
            meta: (
              <>
                {t.Target?.Port && <span>:{t.Target.Port}</span>}
                <Status tone={HEALTH_TONE[state] ?? "neutral"}>{state}</Status>
              </>
            ),
            actions: <ActionForm action={deregisterTarget.bind(null, arn, id, t.Target?.Port)} submit={`Deregister ${id}`} icon={<X size={15} />} tone="danger" />,
          };
        })}
      />
    </Page>
  );
}
