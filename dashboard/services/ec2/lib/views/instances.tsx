import "server-only";

import { DescribeInstanceTypesCommand, type Instance } from "@aws-sdk/client-ec2";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Metric, Metrics, Sheet, Status } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { Play, RotateCcw, Square, Trash2 } from "lucide-react";

import { changeState, launch } from "../../routes/ec2/actions";
import { launchChoices } from "../choices";
import { ICONS, LINKS, ec2, nameTag } from "../clients";
import { STATE_TONE, listInstances } from "../ec2";
import { LaunchFields } from "../launch-fields";

const STATES = [
  { id: "running", title: "Running", states: ["running", "pending"] },
  { id: "stopped", title: "Stopped", states: ["stopped", "stopping"] },
  { id: "terminated", title: "Terminated", states: ["terminated", "shutting-down"] },
];

const IN_TRANSIT = new Set(["pending", "stopping", "shutting-down"]);

export function InstanceActions({ instance }: { instance: Instance }) {
  const state = instance.State?.Name;
  const id = instance.InstanceId!;
  if (state === "terminated" || state === "shutting-down") return null;
  return (
    <>
      {state === "stopped" && <ActionForm action={changeState.bind(null, id, "start")} submit={`Start ${id}`} icon={<Play size={15} />} />}
      {state === "running" && <ActionForm action={changeState.bind(null, id, "reboot")} submit={`Reboot ${id}`} icon={<RotateCcw size={15} />} />}
      {state === "running" && <ActionForm action={changeState.bind(null, id, "stop")} submit={`Stop ${id}`} icon={<Square size={15} />} />}
      <ActionForm action={changeState.bind(null, id, "terminate")} submit={`Terminate ${id}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Terminate ${id}?`} />
    </>
  );
}

/** "Launch instance": the full launch form, optionally from one template. */
export async function LaunchSheet({ template, image }: { template?: string; image?: string }) {
  const choices = await launchChoices();
  return (
    <Sheet title="Launch instance" label="Launch instance" testId="launch-instance">
      <ActionForm action={launch} submit="Launch" testId="launch-instance">
        <LaunchFields choices={choices} mode="launch" template={template} image={image} />
      </ActionForm>
    </Sheet>
  );
}

/** vCPUs per instance: CpuOptions when EC2 reports them, else the type's default. */
async function vcpuCounts(instances: Instance[]) {
  const types = [...new Set(instances.filter((i) => !i.CpuOptions?.CoreCount).map((i) => i.InstanceType!))];
  if (!types.length) return {} as Record<string, number>;
  const out = await load(async () => (await (await ec2()).send(new DescribeInstanceTypesCommand({ InstanceTypes: types as never }))).InstanceTypes ?? []);
  return Object.fromEntries((out.ok ? out.value : []).map((t) => [t.InstanceType!, t.VCpuInfo?.DefaultVCpus ?? 0]));
}

export async function InstancesView() {
  const instances = await load(() => listInstances());
  if (!instances.ok) return { body: <ErrorNotice error={instances.error} />, actions: <LaunchSheet /> };
  const all = instances.value;
  const live = all.filter((i) => ["running", "pending"].includes(i.State?.Name ?? ""));
  const vcpus = await vcpuCounts(live);
  const vcpu = (i: Instance) => (i.CpuOptions?.CoreCount ? i.CpuOptions.CoreCount * (i.CpuOptions.ThreadsPerCore ?? 1) : (vcpus[i.InstanceType!] ?? 0));
  const body = (
    <>
      {all.length > 0 && (
        <Metrics>
          <Metric label="Running" value={live.length} tone="good" />
          <Metric label="Stopped" value={all.filter((i) => i.State?.Name === "stopped").length} />
          <Metric label="vCPUs" value={live.reduce((n, i) => n + vcpu(i), 0)} />
        </Metrics>
      )}
      <LiveRefresh when={all.some((i) => IN_TRANSIT.has(i.State?.Name ?? ""))} />
      <Curated
        label="Instances"
        sections={STATES.map((s) => ({ id: s.id, title: s.title, items: all.filter((i) => s.states.includes(i.State?.Name ?? "")) }))}
        empty={<Empty icon={ICONS.instance} />}
        row={(i) => ({
          key: i.InstanceId!,
          icon: <AwsIcon icon={ICONS.instance} size={24} />,
          title: nameTag(i) ?? i.InstanceId,
          subtitle: [nameTag(i) ? i.InstanceId : null, i.InstanceType, i.Placement?.AvailabilityZone, i.PrivateIpAddress, i.PublicIpAddress].filter(Boolean).join(" · "),
          href: LINKS.instance(i.InstanceId!),
          meta: <Status tone={STATE_TONE[i.State?.Name ?? ""] ?? "neutral"}>{i.State?.Name === "running" ? ago(i.LaunchTime) : (i.State?.Name ?? "")}</Status>,
          actions: <InstanceActions instance={i} />,
        })}
      />
    </>
  );
  return { body, actions: <LaunchSheet /> };
}
