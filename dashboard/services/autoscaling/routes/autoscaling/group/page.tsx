import { DescribeAutoScalingGroupsCommand, DescribePoliciesCommand, DescribeScalingActivitiesCommand } from "@aws-sdk/client-auto-scaling";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Section, Segments, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { Activity, FileStack, Gauge, HeartPulse, MapPin, Minus, Plus, RefreshCw, Settings2, Trash2, TrendingUp, X } from "lucide-react";
import { PutScalingPolicy } from "@mws-dashboard/ui/model/autoscaling";
import type { Metadata } from "next";

import { Capacity } from "../../../lib/capacity";
import { autoscaling, ICONS, tone } from "../../../lib/clients";
import { METRICS } from "../../../lib/metrics";
import { GroupSize, PolicyTarget } from "../../../lib/sizes";
import { addPolicy, deleteGroup, deletePolicy, editCapacity, refresh, scale, terminate } from "../actions";

export const metadata: Metadata = { title: "Auto Scaling group" };

type Props = { searchParams: Promise<{ name?: string; tab?: string }> };

export default async function Group({ searchParams }: Props) {
  const { name = "", tab = "instances" } = await searchParams;
  const base = `/autoscaling/group?name=${encodeURIComponent(name)}`;
  const back = { href: "/autoscaling", label: "Auto Scaling groups" };
  const data = await load(async () => {
    const client = await autoscaling();
    const [group, activities, policies] = await Promise.all([
      client.send(new DescribeAutoScalingGroupsCommand({ AutoScalingGroupNames: [name] })).then((r) => r.AutoScalingGroups?.[0]),
      client.send(new DescribeScalingActivitiesCommand({ AutoScalingGroupName: name, MaxRecords: 50 })).then((r) => r.Activities ?? [], () => []),
      client.send(new DescribePoliciesCommand({ AutoScalingGroupName: name })).then((r) => r.ScalingPolicies ?? [], () => []),
    ]);
    if (!group) throw new Error(`AutoScalingGroup name not found - ${name}`);
    return { group, activities, policies };
  });
  if (!data.ok) {
    return (
      <Page title={name} icon={ICONS.asg} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { group: g, activities, policies } = data.value;
  const instances = g.Instances ?? [];
  const running = instances.filter((i) => i.LifecycleState === "InService").length;
  const desired = g.DesiredCapacity ?? 0;
  const lt = g.LaunchTemplate ?? g.MixedInstancesPolicy?.LaunchTemplate?.LaunchTemplateSpecification;
  const targetGroups = g.TargetGroupARNs ?? [];

  let body;
  if (tab === "activity") {
    body = (
      <List
        label="Activity"
        empty={<Empty icon={ICONS.autoscaling} />}
        rows={activities.map((a) => ({
          key: a.ActivityId!,
          icon: <Activity size={18} />,
          title: a.Description,
          subtitle: a.StatusMessage || a.Cause?.replace(/^At \S+ /, ""),
          meta: (
            <>
              <Status tone={tone(a.StatusCode === "Successful" ? "SUCCEEDED" : a.StatusCode)}>{a.StatusCode?.toLowerCase()}</Status>
              <span>{ago(a.StartTime)}</span>
            </>
          ),
        }))}
      />
    );
  } else if (tab === "scaling") {
    body = (
      <Section
        title="Dynamic scaling policies"
        count={policies.length}
        plain
        actions={
          <Sheet title="Create dynamic scaling policy" label="Create dynamic scaling policy" icon={<Plus size={15} />} testId="add-policy">
            <ActionForm action={addPolicy.bind(null, name)} submit="Create" testId="add-policy">
              <Field label="Policy name" rule={PutScalingPolicy.PolicyName} generate={{ prefix: "target-tracking" }}>
                <input name="policy" required autoFocus defaultValue="target-tracking" />
              </Field>
              <PolicyTarget />
            </ActionForm>
          </Sheet>
        }
      >
        <List
          label="Scaling policies"
          empty={<Empty icon={ICONS.autoscaling} />}
          rows={policies.map((p) => {
            const tt = p.TargetTrackingConfiguration;
            const metric = tt?.PredefinedMetricSpecification?.PredefinedMetricType ?? tt?.CustomizedMetricSpecification?.MetricName;
            return {
              key: p.PolicyARN!,
              icon: <TrendingUp size={18} />,
              title: p.PolicyName,
              subtitle: tt ? `${METRICS.find(([v]) => v === metric)?.[1] ?? metric} → ${tt.TargetValue}` : p.AdjustmentType,
              meta: (
                <>
                  <Pill>{p.PolicyType?.replace(/([a-z])([A-Z])/g, "$1 $2").toLowerCase()}</Pill>
                  {(p.Alarms ?? []).length > 0 && <span title={p.Alarms!.map((a) => a.AlarmName).join(", ")}>{p.Alarms!.length} alarms</span>}
                </>
              ),
              actions: <ActionForm action={deletePolicy.bind(null, name, p.PolicyName!)} submit={`Delete ${p.PolicyName}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${p.PolicyName}?`} />,
            };
          })}
        />
      </Section>
    );
  } else {
    body = (
      <List
        label="Instances"
        empty={<Empty icon={ICONS.instance} />}
        rows={instances.map((i) => ({
          key: i.InstanceId!,
          icon: <AwsIcon icon={ICONS.instance} size={22} />,
          title: i.InstanceId,
          href: `/ec2/instance?id=${i.InstanceId}`,
          subtitle: i.InstanceType,
          meta: (
            <>
              <span>{i.AvailabilityZone}</span>
              {i.ProtectedFromScaleIn && <Pill>protected</Pill>}
              {i.HealthStatus !== "Healthy" && <Pill tone="bad" icon={<HeartPulse size={11} />}>{i.HealthStatus}</Pill>}
              <Status tone={i.LifecycleState === "InService" ? "good" : tone(i.LifecycleState)}>{i.LifecycleState?.replace(/([a-z])([A-Z])/g, "$1 $2").toLowerCase()}</Status>
            </>
          ),
          actions: <ActionForm action={terminate.bind(null, i.InstanceId!, true)} submit={`Terminate ${i.InstanceId}`} icon={<X size={15} />} tone="danger" confirm={`Terminate ${i.InstanceId} and decrement desired capacity?`} />,
        }))}
      />
    );
  }

  return (
    <Page
      title={name}
      icon={ICONS.asg}
      back={back}
      subtitle={g.AutoScalingGroupARN}
      actions={
        <>
          <ActionForm action={scale.bind(null, name, Math.max(desired - 1, g.MinSize ?? 0))} submit="Scale in" icon={<Minus size={16} />} />
          <ActionForm action={scale.bind(null, name, Math.min(desired + 1, g.MaxSize ?? desired + 1))} submit="Scale out" icon={<Plus size={16} />} testId="scale-out" />
          <Sheet title="Group size" label="Edit capacity" icon={<Settings2 size={15} />} testId="edit-capacity">
            <ActionForm action={editCapacity.bind(null, name)} submit="Update" testId="edit-capacity">
              <GroupSize min={g.MinSize} desired={desired} max={g.MaxSize} />
            </ActionForm>
          </Sheet>
          <ActionForm action={refresh.bind(null, name)} submit="Start instance refresh" icon={<RefreshCw size={16} />} />
          <ActionForm action={deleteGroup.bind(null, name)} submit="Delete group" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name} and terminate its instances?`} />
        </>
      }
    >
      <Specs
        items={[
          { label: "Capacity", icon: <Gauge size={15} />, value: <Capacity running={running} desired={desired} min={g.MinSize ?? 0} max={g.MaxSize ?? 0} /> },
          lt && { label: "Launch template", icon: <FileStack size={15} />, value: `${lt.LaunchTemplateName ?? lt.LaunchTemplateId} (${lt.Version ?? "$Default"})` },
          { label: "Availability Zones", icon: <MapPin size={15} />, value: (g.AvailabilityZones ?? []).map((z) => z.slice(-2)).join(" ") },
          { label: "Health check", icon: <HeartPulse size={15} />, value: `${g.HealthCheckType} · ${g.HealthCheckGracePeriod ?? 0}s` },
          targetGroups.length > 0 && {
            label: "Target groups",
            icon: <AwsIcon icon="service/ElasticLoadBalancing" size={16} />,
            value: targetGroups.map((t) => t.split("/")[1]).join(", "),
          },
        ]}
      />
      <Segments
        items={[
          { label: "Instance management", href: base, active: tab === "instances", count: instances.length },
          { label: "Automatic scaling", href: `${base}&tab=scaling`, active: tab === "scaling", count: policies.length || undefined },
          { label: "Activity", href: `${base}&tab=activity`, active: tab === "activity" },
        ]}
      />
      {body}
    </Page>
  );
}
