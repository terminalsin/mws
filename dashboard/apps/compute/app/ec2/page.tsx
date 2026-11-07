import { DescribeInstancesCommand, DescribeVpcsCommand, type Instance } from "@aws-sdk/client-ec2";
import { collect, load, when } from "@mws-dashboard/aws";
import { ActionForm, Badge, ErrorNotice, Field, PageHeader, Section, Table, type Tone } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { ec2 } from "../../lib/clients";
import { changeState, launch } from "./actions";

export const metadata: Metadata = { title: "EC2 instances" };

const STATE_TONE: Record<string, Tone> = {
  running: "good",
  pending: "warn",
  stopping: "warn",
  "shutting-down": "warn",
  stopped: "neutral",
  terminated: "bad",
};

const nameTag = (i: { Tags?: { Key?: string; Value?: string }[] }) => i.Tags?.find((t) => t.Key === "Name")?.Value;

function Actions({ instance }: { instance: Instance }) {
  const state = instance.State?.Name;
  const id = instance.InstanceId!;
  if (state === "terminated" || state === "shutting-down") return null;
  return (
    <div className="actions-cell">
      {state === "stopped" && <ActionForm action={changeState.bind(null, id, "start")} submit="Start" inline />}
      {state === "running" && <ActionForm action={changeState.bind(null, id, "reboot")} submit="Reboot" inline />}
      {state === "running" && <ActionForm action={changeState.bind(null, id, "stop")} submit="Stop" tone="danger" inline />}
      <ActionForm action={changeState.bind(null, id, "terminate")} submit="Terminate" tone="danger" confirm={`Terminate ${id}?`} inline />
    </div>
  );
}

export default async function Instances() {
  const client = await ec2();
  const [instances, vpcs] = await Promise.all([
    load(async () =>
      (
        await collect(
          (NextToken) => client.send(new DescribeInstancesCommand({ NextToken })),
          (r) => r.Reservations,
          (r) => r.NextToken,
        )
      ).flatMap((r) => r.Instances ?? []),
    ),
    load(async () => (await client.send(new DescribeVpcsCommand({}))).Vpcs ?? []),
  ]);
  return (
    <>
      <PageHeader
        title="EC2 instances"
        description="Instances in the selected region. With Docker available MWS runs each one as a container; otherwise they are metadata only."
      />
      <Section title={instances.ok ? `Instances (${instances.value.length})` : "Instances"}>
        {instances.ok ? (
          <Table
            label="Instances"
            rows={instances.value}
            rowKey={(i) => i.InstanceId!}
            empty="No instances in this region."
            columns={[
              {
                header: "Instance",
                cell: (i) => (
                  <>
                    <div>{nameTag(i) ?? <span className="muted">unnamed</span>}</div>
                    <code className="muted">{i.InstanceId}</code>
                  </>
                ),
              },
              { header: "State", cell: (i) => <Badge tone={STATE_TONE[i.State?.Name ?? ""] ?? "neutral"}>{i.State?.Name}</Badge> },
              { header: "Type", cell: (i) => i.InstanceType },
              { header: "Image", cell: (i) => <code>{i.ImageId}</code> },
              { header: "Private IP", cell: (i) => i.PrivateIpAddress ?? "—" },
              { header: "Subnet", cell: (i) => <code>{i.SubnetId}</code> },
              { header: "Launched", cell: (i) => when(i.LaunchTime) },
              { header: "", cell: (i) => <Actions instance={i} /> },
            ]}
          />
        ) : (
          <ErrorNotice error={instances.error} />
        )}
      </Section>
      <Section title="Launch an instance">
        <ActionForm action={launch} submit="Launch" inline testId="launch-instance">
          <Field label="Image ID">
            <input name="image" required placeholder="ami-..." />
          </Field>
          <Field label="Instance type">
            <input name="type" defaultValue="t3.micro" />
          </Field>
          <Field label="Name">
            <input name="name" />
          </Field>
        </ActionForm>
      </Section>
      <Section title="VPCs">
        {vpcs.ok ? (
          <Table
            label="VPCs"
            rows={vpcs.value}
            rowKey={(v) => v.VpcId!}
            empty="No VPCs."
            columns={[
              { header: "VPC", cell: (v) => <code>{v.VpcId}</code> },
              { header: "Name", cell: (v) => nameTag(v) ?? "" },
              { header: "CIDR", cell: (v) => <code>{v.CidrBlock}</code> },
              { header: "Default", cell: (v) => (v.IsDefault ? <Badge tone="info">default</Badge> : "") },
              { header: "State", cell: (v) => v.State },
            ]}
          />
        ) : (
          <ErrorNotice error={vpcs.error} />
        )}
      </Section>
    </>
  );
}
