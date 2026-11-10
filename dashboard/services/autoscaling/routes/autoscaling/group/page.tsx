import { DescribeAutoScalingGroupsCommand } from "@aws-sdk/client-auto-scaling";
import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, ErrorNotice, Page, Pill, Segments, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { Ban, FileStack, Gauge, HeartPulse, MapPin, Minus, Network, Pause, Plus, RotateCcw, Settings2, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { Capacity } from "../../../lib/capacity";
import { autoscaling, ICONS, words } from "../../../lib/clients";
import { GroupSize } from "../../../lib/sizes";
import { deleteGroup, editCapacity, scale } from "../actions";
import { cancelRefresh, rollbackRefresh } from "../group-actions";
import { activeRefresh, activityTab, detailsTab, instancesTab, integrationsTab, refreshes, refreshTab, scalingTab } from "./tabs";

export const metadata: Metadata = { title: "Auto Scaling group" };

type Props = { searchParams: Promise<{ name?: string; tab?: string; token?: string }> };

const TABS = { details: detailsTab, activity: activityTab, scaling: scalingTab, instances: instancesTab, refresh: refreshTab, integrations: integrationsTab };

export default async function Group({ searchParams }: Props) {
  const { name = "", tab: asked = "instances", token } = await searchParams;
  const tab = (asked in TABS ? asked : "instances") as keyof typeof TABS;
  const base = `/autoscaling/group?name=${encodeURIComponent(name)}`;
  const back = { href: "/autoscaling", label: "Auto Scaling groups" };
  const data = await load(async () => {
    const client = await autoscaling();
    const [group, refs] = await Promise.all([
      client.send(new DescribeAutoScalingGroupsCommand({ AutoScalingGroupNames: [name] })).then((r) => r.AutoScalingGroups?.[0]),
      refreshes(name),
    ]);
    if (!group) throw new Error(`AutoScalingGroup name not found - ${name}`);
    return { group, refs };
  });
  if (!data.ok) {
    return (
      <Page title={name} icon={ICONS.asg} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { group: g, refs } = data.value;
  const { body, live } = await TABS[tab]({ g, name, base, token });
  const instances = g.Instances ?? [];
  const running = instances.filter((i) => i.LifecycleState === "InService").length;
  const standby = instances.filter((i) => i.LifecycleState === "Standby").length;
  const waiting = instances.filter((i) => i.LifecycleState?.endsWith(":Wait")).length;
  const desired = g.DesiredCapacity ?? 0;
  const min = g.MinSize ?? 0;
  const max = g.MaxSize ?? 0;
  const lt = g.LaunchTemplate ?? g.MixedInstancesPolicy?.LaunchTemplate?.LaunchTemplateSpecification;
  const sources = [...(g.TrafficSources ?? []).map((t) => t.Identifier!), ...(g.TargetGroupARNs ?? [])].filter((v, i, a) => a.indexOf(v) === i);
  const subnets = (g.VPCZoneIdentifier ?? "").split(",").filter(Boolean);
  const refresh = activeRefresh(refs);
  const changing = !!g.Status || instances.some((i) => i.LifecycleState !== "InService" && i.LifecycleState !== "Standby") || instances.length !== desired;

  return (
    <Page
      title={name}
      icon={ICONS.asg}
      back={back}
      subtitle={g.AutoScalingGroupARN}
      actions={
        <>
          {desired > min && <ActionForm action={scale.bind(null, name, desired - 1)} submit="Scale in" icon={<Minus size={16} />} />}
          {desired < max && <ActionForm action={scale.bind(null, name, desired + 1)} submit="Scale out" icon={<Plus size={16} />} testId="scale-out" />}
          <Sheet title="Group size" label="Edit capacity" icon={<Settings2 size={15} />} testId="edit-capacity">
            <ActionForm action={editCapacity.bind(null, name)} submit="Update" testId="edit-capacity">
              <GroupSize min={g.MinSize} desired={desired} max={g.MaxSize} />
            </ActionForm>
          </Sheet>
          {refresh && refresh.Status !== "Cancelling" && refresh.Status !== "RollbackInProgress" && (
            <>
              <ActionForm action={cancelRefresh.bind(null, name)} submit="Cancel instance refresh" icon={<Ban size={16} />} confirm="Cancel the instance refresh? Replaced instances stay." testId="cancel-refresh" />
              <ActionForm action={rollbackRefresh.bind(null, name)} submit="Roll back instance refresh" icon={<RotateCcw size={16} />} confirm="Roll back the instance refresh to the previous configuration?" testId="rollback-refresh" />
            </>
          )}
          <ActionForm action={deleteGroup.bind(null, name)} submit="Delete group" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name} and terminate its instances?`} />
        </>
      }
    >
      <LiveRefresh when={changing || !!refresh || !!live} />
      <Specs
        items={[
          { label: "Capacity", icon: <Gauge size={15} />, value: <Capacity running={running} desired={desired} min={min} max={max} /> },
          g.Status && { label: "Status", icon: <Gauge size={15} />, value: <Status tone="warn">{g.Status.toLowerCase()}</Status> },
          (standby > 0 || waiting > 0) && {
            label: "Held instances",
            icon: <Pause size={15} />,
            value: [standby > 0 && `${standby} standby`, waiting > 0 && `${waiting} waiting on a lifecycle hook`].filter(Boolean).join(" · "),
          },
          refresh && {
            label: "Instance refresh",
            icon: <RotateCcw size={15} />,
            value: (
              <Link href={`${base}&tab=refresh`}>
                <Status tone="warn">{words(refresh.Status)}</Status> {refresh.PercentageComplete ?? 0}%
              </Link>
            ),
          },
          lt && { label: "Launch template", icon: <FileStack size={15} />, value: `${lt.LaunchTemplateName ?? lt.LaunchTemplateId} (${lt.Version ?? "$Default"})` },
          !lt && g.LaunchConfigurationName && { label: "Launch configuration", icon: <FileStack size={15} />, value: g.LaunchConfigurationName },
          { label: "Availability Zones", icon: <MapPin size={15} />, value: (g.AvailabilityZones ?? []).join(", ") },
          subnets.length > 0 && {
            label: "Subnets",
            icon: <Network size={15} />,
            value: subnets.map((s, i) => (
              <span key={s}>
                {i > 0 && " "}
                <Link href={`/vpc/subnet?id=${s}`}>{s}</Link>
              </span>
            )),
          },
          { label: "Health check", icon: <HeartPulse size={15} />, value: `${g.HealthCheckType} · ${g.HealthCheckGracePeriod ?? 0}s` },
          sources.length > 0 && {
            label: "Load balancing",
            icon: <AwsIcon icon="service/ElasticLoadBalancing" size={16} />,
            value: sources.map((t, i) => (
              <span key={t}>
                {i > 0 && ", "}
                {t.includes(":targetgroup/") ? <Link href={`/elb/tg?arn=${encodeURIComponent(t)}`}>{t.split("/")[1]}</Link> : t}
              </span>
            )),
          },
          (g.SuspendedProcesses ?? []).length > 0 && {
            label: "Suspended processes",
            icon: <Pause size={15} />,
            value: (
              <Link href={`${base}&tab=details`}>
                <Pill tone="warn">{`${g.SuspendedProcesses!.length} suspended`}</Pill>
              </Link>
            ),
          },
        ]}
      />
      <Segments
        items={[
          { label: "Details", href: `${base}&tab=details`, active: tab === "details" },
          { label: "Activity", href: `${base}&tab=activity`, active: tab === "activity" },
          { label: "Automatic scaling", href: `${base}&tab=scaling`, active: tab === "scaling" },
          { label: "Instance management", href: base, active: tab === "instances", count: instances.length },
          { label: "Instance refresh", href: `${base}&tab=refresh`, active: tab === "refresh", count: refs.length || undefined },
          { label: "Integrations", href: `${base}&tab=integrations`, active: tab === "integrations", count: sources.length || undefined },
        ]}
      />
      {body}
    </Page>
  );
}
