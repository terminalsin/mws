import {
  DescribeAutoScalingNotificationTypesCommand,
  DescribeInstanceRefreshesCommand,
  DescribeLifecycleHooksCommand,
  DescribeNotificationConfigurationsCommand,
  DescribePoliciesCommand,
  DescribeScalingActivitiesCommand,
  DescribeScalingProcessTypesCommand,
  DescribeScheduledActionsCommand,
  DescribeTerminationPolicyTypesCommand,
  DescribeTrafficSourcesCommand,
  DescribeWarmPoolCommand,
  type AutoScalingGroup,
  type InstanceRefresh,
  type LifecycleHook,
} from "@aws-sdk/client-auto-scaling";
import { DescribeInstancesCommand } from "@aws-sdk/client-ec2";
import { ago, all, load, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Facts, Field, List, More, Pill, Section, Sheet, Status, Tags } from "@mws-dashboard/ui";
import { CreateLaunchTemplate } from "@mws-dashboard/ui/model/ec2";
import { PutLifecycleHook, PutScheduledUpdateGroupAction, PutWarmPool, StartInstanceRefresh, UpdateAutoScalingGroup } from "@mws-dashboard/ui/model/autoscaling";
import {
  Activity,
  Anchor,
  BarChart3,
  Bell,
  CalendarClock,
  Check,
  Flame,
  HeartOff,
  HeartPulse,
  Pause,
  Play,
  Plus,
  RefreshCw,
  Settings2,
  Shield,
  ShieldOff,
  Tag,
  Trash2,
  TrendingUp,
  Undo2,
  Unlink,
  X,
  Zap,
} from "lucide-react";
import type { ReactNode } from "react";

import { autoscaling, ec2, ICONS, tone, words } from "../../../lib/clients";
import { NetworkFields, PolicyFields, ScheduleFields } from "../../../lib/forms";
import { METRICS } from "../../../lib/metrics";
import { launchTemplates, targetGroups, templateVersions, vpcNetwork } from "../../../lib/network";
import { GroupSize } from "../../../lib/sizes";
import { addPolicy, deletePolicy } from "../actions";
import {
  attachInstances,
  attachTargetGroups,
  completeAction,
  deleteHook,
  deleteNotification,
  deleteSchedule,
  deleteTag,
  deleteWarmPool,
  detachInstance,
  detachTrafficSource,
  editSettings,
  executePolicy,
  heartbeat,
  protect,
  putHook,
  putNotification,
  putSchedule,
  putTag,
  putWarmPool,
  setHealth,
  setMetrics,
  setProcess,
  standby,
  startRefresh,
  terminateInstance,
} from "../group-actions";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";

export interface Ctx {
  g: AutoScalingGroup;
  name: string;
  base: string;
  token?: string;
}

type Tab = (ctx: Ctx) => Promise<{ body: ReactNode; live?: boolean }>;

const REFRESH_LIVE = new Set(["Pending", "InProgress", "Cancelling", "RollbackInProgress", "Baking"]);

export async function refreshes(name: string) {
  const client = await autoscaling();
  return all((NextToken) => client.send(new DescribeInstanceRefreshesCommand({ AutoScalingGroupName: name, NextToken })), (r) => r.InstanceRefreshes, (r) => r.NextToken, 50).catch(
    () => [] as InstanceRefresh[],
  );
}

export const activeRefresh = (list: InstanceRefresh[]) => list.find((r) => REFRESH_LIVE.has(r.Status ?? ""));

// --- Activity -------------------------------------------------------------------

export const activityTab: Tab = async ({ name, base, token }) => {
  const page = await load(() => autoscaling().then((c) => c.send(new DescribeScalingActivitiesCommand({ AutoScalingGroupName: name, MaxRecords: 50, NextToken: token }))));
  if (!page.ok) return { body: <ErrorNotice error={page.error} /> };
  const activities = page.value.Activities ?? [];
  const next = page.value.NextToken;
  return {
    live: activities.some((a) => !["Successful", "Failed", "Cancelled"].includes(a.StatusCode ?? "")),
    body: (
      <>
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
                {a.Progress !== undefined && a.Progress < 100 && <span>{a.Progress}%</span>}
                <Status tone={tone(a.StatusCode === "Successful" ? "SUCCEEDED" : a.StatusCode)}>{words(a.StatusCode)}</Status>
                <span title={when(a.StartTime)}>{ago(a.StartTime)}</span>
              </>
            ),
          }))}
        />
        <More shown={activities.length} href={next ? `${base}&tab=activity&token=${encodeURIComponent(next)}` : undefined} noun="activities" />
      </>
    ),
  };
};

// --- Automatic scaling ------------------------------------------------------------

export const scalingTab: Tab = async ({ g, name }) => {
  const client = await autoscaling();
  const [policies, schedules] = await Promise.all([
    load(() => all((NextToken) => client.send(new DescribePoliciesCommand({ AutoScalingGroupName: name, NextToken })), (r) => r.ScalingPolicies, (r) => r.NextToken)),
    load(() => all((NextToken) => client.send(new DescribeScheduledActionsCommand({ AutoScalingGroupName: name, NextToken })), (r) => r.ScheduledUpdateGroupActions, (r) => r.NextToken)),
  ]);
  return {
    body: (
      <>
        <Section
          title="Dynamic scaling policies"
          count={policies.ok ? policies.value.length : undefined}
          plain
          actions={
            <Sheet title="Create dynamic scaling policy" label="Create dynamic scaling policy" icon={<Plus size={15} />} testId="add-policy">
              <ActionForm action={addPolicy.bind(null, name)} submit="Create" testId="add-policy">
                <PolicyFields taken={policies.ok ? policies.value.map((p) => p.PolicyName!) : []} />
              </ActionForm>
            </Sheet>
          }
        >
          {policies.ok ? (
            <List
              label="Scaling policies"
              empty={<Empty icon={ICONS.autoscaling} />}
              rows={policies.value.map((p) => {
                const tt = p.TargetTrackingConfiguration;
                const metric = tt?.PredefinedMetricSpecification?.PredefinedMetricType ?? tt?.CustomizedMetricSpecification?.MetricName;
                const adjust =
                  p.PolicyType === "StepScaling"
                    ? (p.StepAdjustments ?? []).map((s) => `${s.MetricIntervalLowerBound ?? "-∞"}…${s.MetricIntervalUpperBound ?? "∞"}: ${s.ScalingAdjustment! > 0 ? "+" : ""}${s.ScalingAdjustment}`).join(", ")
                    : p.PolicyType === "SimpleScaling"
                      ? `${p.ScalingAdjustment! > 0 && p.AdjustmentType !== "ExactCapacity" ? "+" : ""}${p.ScalingAdjustment}${p.AdjustmentType === "PercentChangeInCapacity" ? "%" : p.AdjustmentType === "ExactCapacity" ? " instances" : ""}`
                      : undefined;
                return {
                  key: p.PolicyARN!,
                  icon: <TrendingUp size={18} />,
                  title: p.PolicyName,
                  subtitle: tt ? `${METRICS.find(([v]) => v === metric)?.[1] ?? metric} → ${tt.TargetValue}${tt.DisableScaleIn ? " · no scale in" : ""}` : adjust,
                  meta: (
                    <>
                      {p.Enabled === false && <Pill tone="warn">Disabled</Pill>}
                      <Pill>{words(p.PolicyType)}</Pill>
                      {(p.Alarms ?? []).map((a) => (
                        <a key={a.AlarmARN} href={`/alarms/alarm?name=${encodeURIComponent(a.AlarmName!)}`} title={a.AlarmName} className="pill neutral">
                          <Bell size={11} />
                        </a>
                      ))}
                    </>
                  ),
                  actions: (
                    <>
                      {p.PolicyType !== "TargetTrackingScaling" && p.PolicyType !== "PredictiveScaling" && (
                        <ActionForm action={executePolicy.bind(null, name, p.PolicyName!)} submit={`Execute ${p.PolicyName}`} icon={<Zap size={15} />} confirm={`Run ${p.PolicyName} now?`} />
                      )}
                      <ActionForm action={deletePolicy.bind(null, name, p.PolicyName!)} submit={`Delete ${p.PolicyName}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${p.PolicyName}?`} />
                    </>
                  ),
                };
              })}
            />
          ) : (
            <ErrorNotice error={policies.error} />
          )}
        </Section>
        <Section
          title="Scheduled actions"
          count={schedules.ok ? schedules.value.length : undefined}
          plain
          actions={
            <Sheet title="Create scheduled action" label="Create scheduled action" icon={<CalendarClock size={15} />} testId="add-schedule">
              <ActionForm action={putSchedule.bind(null, name)} submit="Create" testId="add-schedule">
                <Field label="Name" rule={PutScheduledUpdateGroupAction.ScheduledActionName} member="ScheduledActionName" generate={{ prefix: "scale" }} taken={schedules.ok ? schedules.value.map((s) => s.ScheduledActionName!) : []} unique>
                  <input name="action" required autoFocus />
                </Field>
                <GroupSize min={g.MinSize} desired={g.DesiredCapacity} max={g.MaxSize} />
                <ScheduleFields />
              </ActionForm>
            </Sheet>
          }
        >
          {schedules.ok ? (
            <List
              label="Scheduled actions"
              empty={<Empty icon={ICONS.autoscaling} />}
              rows={schedules.value.map((s) => ({
                key: s.ScheduledActionARN ?? s.ScheduledActionName!,
                icon: <CalendarClock size={18} />,
                title: s.ScheduledActionName,
                subtitle: [s.Recurrence ? <code key="r">{s.Recurrence}</code> : null, s.StartTime && ` ${s.Recurrence ? "from" : "at"} ${when(s.StartTime)}`, s.EndTime && ` until ${when(s.EndTime)}`],
                meta: (
                  <>
                    {[s.MinSize !== undefined && `min ${s.MinSize}`, s.DesiredCapacity !== undefined && `desired ${s.DesiredCapacity}`, s.MaxSize !== undefined && `max ${s.MaxSize}`].filter(Boolean).join(" · ")}
                    {s.TimeZone && <Pill>{s.TimeZone}</Pill>}
                  </>
                ),
                actions: (
                  <ActionForm action={deleteSchedule.bind(null, name, s.ScheduledActionName!)} submit={`Delete ${s.ScheduledActionName}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${s.ScheduledActionName}?`} />
                ),
              }))}
            />
          ) : (
            <ErrorNotice error={schedules.error} />
          )}
        </Section>
      </>
    ),
  };
};

// --- Instance management ------------------------------------------------------------

const TRANSITIONS: [string, string][] = [
  ["autoscaling:EC2_INSTANCE_LAUNCHING", "Instance launch"],
  ["autoscaling:EC2_INSTANCE_TERMINATING", "Instance terminate"],
];

function hookFor(state: string | undefined, hooks: LifecycleHook[]) {
  if (!state?.endsWith(":Wait")) return undefined;
  const launching = state.includes("Pending");
  return hooks.find((h) => h.LifecycleTransition === (launching ? TRANSITIONS[0][0] : TRANSITIONS[1][0]));
}

function InstanceActions({ name, i, hooks }: { name: string; i: NonNullable<AutoScalingGroup["Instances"]>[number]; hooks: LifecycleHook[] }) {
  const id = i.InstanceId!;
  const state = i.LifecycleState;
  const hook = hookFor(state, hooks);
  return (
    <>
      {hook && (
        <>
          <ActionForm action={completeAction.bind(null, name, hook.LifecycleHookName!, id, "CONTINUE")} submit={`Continue ${id}`} icon={<Check size={15} />} tone="primary" />
          <ActionForm action={completeAction.bind(null, name, hook.LifecycleHookName!, id, "ABANDON")} submit={`Abandon ${id}`} icon={<X size={15} />} confirm={`Abandon the lifecycle action of ${id}?`} />
          <ActionForm action={heartbeat.bind(null, name, hook.LifecycleHookName!, id)} submit={`Record heartbeat for ${id}`} icon={<HeartPulse size={15} />} />
        </>
      )}
      {state === "InService" && <ActionForm action={standby.bind(null, name, id, true, true)} submit={`Set ${id} to standby`} icon={<Pause size={15} />} />}
      {state === "Standby" && <ActionForm action={standby.bind(null, name, id, false, true)} submit={`Return ${id} to service`} icon={<Play size={15} />} />}
      {(state === "InService" || state === "Pending") && (
        <ActionForm
          action={protect.bind(null, name, id, !i.ProtectedFromScaleIn)}
          submit={i.ProtectedFromScaleIn ? `Remove scale-in protection from ${id}` : `Protect ${id} from scale in`}
          icon={i.ProtectedFromScaleIn ? <ShieldOff size={15} /> : <Shield size={15} />}
        />
      )}
      {state === "InService" && (
        <ActionForm
          action={setHealth.bind(null, id, i.HealthStatus !== "Healthy")}
          submit={i.HealthStatus === "Healthy" ? `Set ${id} unhealthy` : `Set ${id} healthy`}
          icon={i.HealthStatus === "Healthy" ? <HeartOff size={15} /> : <HeartPulse size={15} />}
          confirm={i.HealthStatus === "Healthy" ? `Mark ${id} unhealthy? Auto Scaling replaces it.` : undefined}
        />
      )}
      {(state === "InService" || state === "Standby") && (
        <Sheet title={`Detach ${id}`} label={`Detach ${id}`} icon={<Unlink size={15} />} testId={`detach-${id}`}>
          <ActionForm action={detachInstance.bind(null, name, id)} submit="Detach" testId={`detach-${id}`}>
            <label className="check">
              <input type="checkbox" name="decrement" defaultChecked /> Decrement desired capacity
            </label>
          </ActionForm>
        </Sheet>
      )}
      {!state?.startsWith("Terminat") && (
        <Sheet title={`Terminate ${id}`} label={`Terminate ${id}`} icon={<Trash2 size={15} />} testId={`terminate-${id}`}>
          <ActionForm action={terminateInstance.bind(null, id)} submit="Terminate" tone="danger" testId={`terminate-${id}`}>
            <label className="check">
              <input type="checkbox" name="decrement" defaultChecked /> Decrement desired capacity
            </label>
          </ActionForm>
        </Sheet>
      )}
    </>
  );
}

export const instancesTab: Tab = async ({ g, name }) => {
  const client = await autoscaling();
  const [hooks, warm, free] = await Promise.all([
    client.send(new DescribeLifecycleHooksCommand({ AutoScalingGroupName: name })).then((r) => r.LifecycleHooks ?? [], () => [] as LifecycleHook[]),
    all((NextToken) => client.send(new DescribeWarmPoolCommand({ AutoScalingGroupName: name, NextToken })), (r) => [r], (r) => r.NextToken).then(
      (pages) => ({ config: pages[0]?.WarmPoolConfiguration, instances: pages.flatMap((p) => p.Instances ?? []) }),
      () => ({ config: undefined, instances: [] }),
    ),
    attachable(g),
  ]);
  const instances = g.Instances ?? [];
  const live = instances.some((i) => i.LifecycleState !== "InService" && i.LifecycleState !== "Standby") || warm.instances.some((i) => !/^Warmed:(Stopped|Running|Hibernated)$/.test(i.LifecycleState ?? "")) || warm.config?.Status === "PendingDelete";
  return {
    live,
    body: (
      <>
        <Section
          title="Instances"
          count={instances.length}
          plain
          actions={
            free.length > 0 ? (
              <Sheet title="Attach instances" label="Attach instances" icon={<Anchor size={15} />} testId="attach-instances">
                <ActionForm action={attachInstances.bind(null, name)} submit="Attach" testId="attach-instances">
                  <fieldset className="checks">
                    <legend>Running instances in the group's subnets</legend>
                    {free.map((i) => (
                      <label key={i.id} className="check">
                        <input type="checkbox" name="instance" value={i.id} /> {i.label}
                      </label>
                    ))}
                  </fieldset>
                </ActionForm>
              </Sheet>
            ) : undefined
          }
        >
          <List
            label="Instances"
            empty={<Empty icon={ICONS.instance} />}
            rows={instances.map((i) => ({
              key: i.InstanceId!,
              icon: <AwsIcon icon={ICONS.instance} size={22} />,
              title: i.InstanceId,
              href: `/ec2/instance?id=${i.InstanceId}`,
              subtitle: [i.InstanceType, i.AvailabilityZone, i.LaunchTemplate && `${i.LaunchTemplate.LaunchTemplateName} v${i.LaunchTemplate.Version}`].filter(Boolean).join(" · "),
              meta: (
                <>
                  {i.ProtectedFromScaleIn && <Pill icon={<Shield size={11} />}>protected</Pill>}
                  {i.HealthStatus !== "Healthy" && (
                    <Pill tone="bad" icon={<HeartPulse size={11} />}>
                      {i.HealthStatus}
                    </Pill>
                  )}
                  <Status tone={i.LifecycleState === "InService" ? "good" : i.LifecycleState === "Standby" ? "info" : tone(i.LifecycleState)}>{words(i.LifecycleState)}</Status>
                </>
              ),
              actions: <InstanceActions name={name} i={i} hooks={hooks} />,
            }))}
          />
        </Section>

        <Section
          title="Lifecycle hooks"
          count={hooks.length}
          plain
          actions={
            <Sheet title="Create lifecycle hook" label="Create lifecycle hook" icon={<Plus size={15} />} testId="add-hook">
              <ActionForm action={putHook.bind(null, name)} submit="Create" testId="add-hook">
                <Field label="Name" rule={PutLifecycleHook.LifecycleHookName} member="LifecycleHookName" taken={hooks.map((h) => h.LifecycleHookName!)} generate={{ prefix: "launch-hook" }}>
                  <input name="hook" required autoFocus />
                </Field>
                <div className="form-row">
                  <Field label="Lifecycle transition" member="LifecycleTransition">
                    <select name="transition">
                      {TRANSITIONS.map(([v, l]) => (
                        <option key={v} value={v}>
                          {l}
                        </option>
                      ))}
                    </select>
                  </Field>
                  <Field label="Default result" member="DefaultResult">
                    <select name="result" defaultValue="ABANDON">
                      <option>ABANDON</option>
                      <option>CONTINUE</option>
                    </select>
                  </Field>
                </div>
                <Field label="Heartbeat timeout" rule={{ ...PutLifecycleHook.HeartbeatTimeout, min: 30, max: 7200, unit: "seconds" }} member="HeartbeatTimeout">
                  <input name="timeout" defaultValue={3600} />
                </Field>
                <Field label="Notification target" rule={PutLifecycleHook.NotificationTargetARN} format="arn" member="NotificationTargetARN" hint="An SNS topic or SQS queue ARN">
                  <ResourcePicker kind={["sns-topic", "sqs-queue"]} use="arn" name="target" />
                </Field>
                <Field label="Role" rule={PutLifecycleHook.RoleARN} format="arn" member="RoleARN" hint="Needed with a notification target">
                  <ResourcePicker kind="iam-role" name="role" service="autoscaling.amazonaws.com" />
                </Field>
                <Field label="Notification metadata" rule={PutLifecycleHook.NotificationMetadata} member="NotificationMetadata">
                  <input name="metadata" />
                </Field>
              </ActionForm>
            </Sheet>
          }
        >
          <List
            label="Lifecycle hooks"
            rows={hooks.map((h) => ({
              key: h.LifecycleHookName!,
              icon: <Anchor size={18} />,
              title: h.LifecycleHookName,
              subtitle: [TRANSITIONS.find(([v]) => v === h.LifecycleTransition)?.[1] ?? h.LifecycleTransition, h.NotificationTargetARN].filter(Boolean).join(" · "),
              meta: (
                <>
                  <span>{h.HeartbeatTimeout}s</span>
                  <Pill>{h.DefaultResult}</Pill>
                </>
              ),
              actions: <ActionForm action={deleteHook.bind(null, name, h.LifecycleHookName!)} submit={`Delete ${h.LifecycleHookName}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${h.LifecycleHookName}?`} />,
            }))}
          />
        </Section>

        <Section
          title="Warm pool"
          count={warm.config ? warm.instances.length : undefined}
          plain
          actions={
            <>
              <Sheet title={warm.config ? "Edit warm pool" : "Create warm pool"} label={warm.config ? "Edit warm pool" : "Create warm pool"} icon={<Flame size={15} />} testId="warm-pool">
                <ActionForm action={putWarmPool.bind(null, name)} submit="Save" testId="warm-pool">
                  <Field label="Instance state" rule={PutWarmPool.PoolState} member="PoolState">
                    <select name="state" defaultValue={warm.config?.PoolState ?? "Stopped"}>
                      <option>Stopped</option>
                      <option>Running</option>
                      <option>Hibernated</option>
                    </select>
                  </Field>
                  <div className="form-row">
                    <Field label="Minimum warm pool size" rule={PutWarmPool.MinSize} member="MinSize">
                      <input name="min" type="number" min={0} defaultValue={warm.config?.MinSize ?? 0} />
                    </Field>
                    <Field label="Max prepared capacity" rule={PutWarmPool.MaxGroupPreparedCapacity} member="MaxGroupPreparedCapacity" hint="The group's max when empty">
                      <input name="maxPrepared" type="number" defaultValue={warm.config?.MaxGroupPreparedCapacity === -1 ? undefined : warm.config?.MaxGroupPreparedCapacity} />
                    </Field>
                  </div>
                  <label className="check">
                    <input type="checkbox" name="reuse" defaultChecked={!!warm.config?.InstanceReusePolicy?.ReuseOnScaleIn} /> Reuse instances on scale in
                  </label>
                </ActionForm>
              </Sheet>
              {warm.config && warm.config.Status !== "PendingDelete" && (
                <ActionForm action={deleteWarmPool.bind(null, name)} submit="Delete warm pool" icon={<Trash2 size={15} />} tone="danger" confirm="Delete the warm pool and terminate its instances?" />
              )}
            </>
          }
        >
          {warm.config ? (
            <>
              <Facts
                items={[
                  ["State", warm.config.PoolState],
                  ["Minimum size", warm.config.MinSize ?? 0],
                  ["Max prepared capacity", warm.config.MaxGroupPreparedCapacity === -1 || warm.config.MaxGroupPreparedCapacity === undefined ? "Group max" : warm.config.MaxGroupPreparedCapacity],
                  warm.config.InstanceReusePolicy?.ReuseOnScaleIn && ["Reuse on scale in", "Yes"],
                  warm.config.Status && ["Status", <Status key="s" tone="warn">{words(warm.config.Status)}</Status>],
                ]}
              />
              <List
                label="Warm pool instances"
                rows={warm.instances.map((i) => ({
                  key: i.InstanceId!,
                  icon: <AwsIcon icon={ICONS.instance} size={20} />,
                  title: i.InstanceId,
                  href: `/ec2/instance?id=${i.InstanceId}`,
                  subtitle: [i.InstanceType, i.AvailabilityZone].filter(Boolean).join(" · "),
                  meta: <Status tone={/Wait|Pending/.test(i.LifecycleState ?? "") ? "warn" : "info"}>{words(i.LifecycleState)}</Status>,
                }))}
              />
            </>
          ) : null}
        </Section>
      </>
    ),
  };
};

/** Running instances in the group's subnets that belong to no group. */
async function attachable(g: AutoScalingGroup) {
  const subnets = (g.VPCZoneIdentifier ?? "").split(",").filter(Boolean);
  if (!subnets.length) return [];
  const c = await ec2();
  const list = await all(
    (NextToken) => c.send(new DescribeInstancesCommand({ Filters: [{ Name: "subnet-id", Values: subnets }, { Name: "instance-state-name", Values: ["running"] }], NextToken })),
    (r) => (r.Reservations ?? []).flatMap((x) => x.Instances ?? []),
    (r) => r.NextToken,
  ).catch(() => []);
  return list
    .filter((i) => !i.Tags?.some((t) => t.Key === "aws:autoscaling:groupName"))
    .map((i) => ({ id: i.InstanceId!, label: `${i.Tags?.find((t) => t.Key === "Name")?.Value ?? i.InstanceId} · ${i.InstanceType} · ${i.Placement?.AvailabilityZone ?? ""}` }));
}

// --- Instance refresh ---------------------------------------------------------------

export const refreshTab: Tab = async ({ g, name }) => {
  const list = await refreshes(name);
  const lt = g.LaunchTemplate ?? g.MixedInstancesPolicy?.LaunchTemplate?.LaunchTemplateSpecification;
  const versions = lt?.LaunchTemplateName ? await templateVersions(lt.LaunchTemplateName).catch(() => []) : [];
  const rule = StartInstanceRefresh.Preferences?.fields ?? {};
  return {
    live: !!activeRefresh(list),
    body: (
      <Section
        title="Instance refreshes"
        count={list.length}
        plain
        actions={
          <Sheet title="Start instance refresh" label="Start instance refresh" icon={<RefreshCw size={15} />} testId="start-refresh">
            <ActionForm action={startRefresh.bind(null, name)} submit="Start instance refresh" testId="start-refresh">
              <div className="form-row">
                <Field label="Min healthy %" rule={rule.MinHealthyPercentage} member="Preferences.MinHealthyPercentage">
                  <input name="minHealthy" type="number" defaultValue={90} />
                </Field>
                <Field label="Max healthy %" rule={rule.MaxHealthyPercentage} member="Preferences.MaxHealthyPercentage">
                  <input name="maxHealthy" type="number" defaultValue={100} />
                </Field>
              </div>
              <Field label="Instance warmup" rule={{ ...rule.InstanceWarmup, unit: "seconds" }} member="Preferences.InstanceWarmup" hint="The group's default warmup when empty">
                <input name="warmup" />
              </Field>
              <div className="form-row">
                <Field label="Checkpoints (%)" rule={{ type: "list", item: rule.CheckpointPercentages?.item ?? { type: "integer", min: 1, max: 100 } }} member="Preferences.CheckpointPercentages" hint="e.g. 20, 50, 100">
                  <input name="checkpoints" spellCheck={false} />
                </Field>
                <Field label="Checkpoint delay" rule={{ ...rule.CheckpointDelay, unit: "seconds" }} member="Preferences.CheckpointDelay">
                  <input name="checkpointDelay" defaultValue={3600} />
                </Field>
              </div>
              <div className="form-row">
                <Field label="Scale-in protected instances" rule={rule.ScaleInProtectedInstances} member="Preferences.ScaleInProtectedInstances">
                  <select name="protected" defaultValue="Ignore">
                    <option>Ignore</option>
                    <option>Refresh</option>
                    <option>Wait</option>
                  </select>
                </Field>
                <Field label="Standby instances" rule={rule.StandbyInstances} member="Preferences.StandbyInstances">
                  <select name="standby" defaultValue="Ignore">
                    <option>Ignore</option>
                    <option>Terminate</option>
                    <option>Wait</option>
                  </select>
                </Field>
              </div>
              <label className="check">
                <input type="checkbox" name="skipMatching" /> Skip matching instances
              </label>
              <label className="check">
                <input type="checkbox" name="autoRollback" /> Roll back on failure
              </label>
              {lt?.LaunchTemplateName && versions.length > 0 && (
                <Field label={`Desired configuration: ${lt.LaunchTemplateName}`} member="DesiredConfiguration.LaunchTemplate.Version">
                  <input type="hidden" name="template" value={lt.LaunchTemplateName} />
                  <select name="version" defaultValue="">
                    <option value="">Keep the group's ({lt.Version ?? "$Default"})</option>
                    <option value="$Latest">$Latest</option>
                    <option value="$Default">$Default</option>
                    {versions.map((v) => (
                      <option key={v.VersionNumber} value={String(v.VersionNumber)}>
                        Version {v.VersionNumber}
                        {v.VersionDescription ? ` · ${v.VersionDescription}` : ""}
                        {v.DefaultVersion ? " · default" : ""}
                      </option>
                    ))}
                  </select>
                </Field>
              )}
            </ActionForm>
          </Sheet>
        }
      >
        <List
          label="Instance refreshes"
          empty={<Empty icon={ICONS.autoscaling} />}
          rows={list.map((r) => {
            const p = r.Preferences;
            const desired = r.DesiredConfiguration?.LaunchTemplate;
            return {
              key: r.InstanceRefreshId!,
              icon: <RefreshCw size={18} />,
              title: r.InstanceRefreshId,
              subtitle: [
                r.StatusReason,
                p && `min ${p.MinHealthyPercentage ?? 90}%${p.MaxHealthyPercentage ? `–${p.MaxHealthyPercentage}%` : ""} healthy`,
                p?.InstanceWarmup !== undefined && `warmup ${p.InstanceWarmup}s`,
                p?.SkipMatching && "skip matching",
                p?.CheckpointPercentages?.length && `checkpoints ${p.CheckpointPercentages.join("/")}%`,
                desired && `→ ${desired.LaunchTemplateName ?? desired.LaunchTemplateId} ${desired.Version ?? ""}`,
              ]
                .filter(Boolean)
                .join(" · "),
              meta: (
                <>
                  {r.Status !== "Successful" && r.InstancesToUpdate !== undefined && r.InstancesToUpdate > 0 && <span>{r.InstancesToUpdate} to update</span>}
                  <span className="capacity" title={`${r.PercentageComplete ?? 0}% complete`}>
                    <b>{r.PercentageComplete ?? 0}%</b>
                  </span>
                  <Status tone={r.Status === "Successful" ? "good" : r.Status === "RollbackSuccessful" ? "info" : tone(r.Status)}>{words(r.Status)}</Status>
                  <span title={when(r.StartTime)}>{ago(r.StartTime)}</span>
                </>
              ),
            };
          })}
        />
      </Section>
    ),
  };
};

// --- Integrations -------------------------------------------------------------------

export const integrationsTab: Tab = async ({ g, name }) => {
  const client = await autoscaling();
  const [sources, tgs, net] = await Promise.all([
    all((NextToken) => client.send(new DescribeTrafficSourcesCommand({ AutoScalingGroupName: name, NextToken })), (r) => r.TrafficSources, (r) => r.NextToken).catch(() => []),
    targetGroups().catch(() => []),
    vpcNetwork().catch(() => ({ vpcs: [], subnets: [] })),
  ]);
  const subnets = (g.VPCZoneIdentifier ?? "").split(",").filter(Boolean);
  const vpc = net.subnets.find((s) => subnets.includes(s.id))?.vpc;
  const attached = new Set(sources.map((s) => s.Identifier));
  const free = tgs.filter((t) => !attached.has(t.TargetGroupArn) && (!vpc || t.VpcId === vpc));
  return {
    live: sources.some((s) => s.State === "Adding" || s.State === "Removing"),
    body: (
      <Section
        title="Load balancing"
        count={sources.length}
        plain
        actions={
          free.length > 0 ? (
            <Sheet title="Attach target groups" label="Attach target groups" icon={<Plus size={15} />} testId="attach-tg">
              <ActionForm action={attachTargetGroups.bind(null, name)} submit="Attach" testId="attach-tg">
                <fieldset className="checks">
                  <legend>Target groups</legend>
                  {free.map((t) => (
                    <label key={t.TargetGroupArn} className="check">
                      <input type="checkbox" name="tg" value={t.TargetGroupArn} /> {t.TargetGroupName} · {t.Protocol}:{t.Port}
                    </label>
                  ))}
                </fieldset>
              </ActionForm>
            </Sheet>
          ) : undefined
        }
      >
        <List
          label="Traffic sources"
          empty={<Empty icon="service/ElasticLoadBalancing" />}
          rows={sources.map((s) => {
            const tg = tgs.find((t) => t.TargetGroupArn === s.Identifier);
            const isTg = s.Identifier?.includes(":targetgroup/");
            return {
              key: s.Identifier!,
              icon: <AwsIcon icon={isTg ? ICONS.targetGroup : "service/ElasticLoadBalancing"} size={22} />,
              title: tg?.TargetGroupName ?? s.Identifier?.split("/")[1] ?? s.Identifier,
              subtitle: tg ? `${tg.Protocol}:${tg.Port}` : s.Type,
              href: isTg ? `/elb/tg?arn=${encodeURIComponent(s.Identifier!)}` : undefined,
              meta: <Status tone={s.State === "InService" ? "good" : s.State === "Added" ? "info" : "warn"}>{s.State ? words(s.State) : ""}</Status>,
              actions:
                s.State === "Removing" || s.State === "Removed" ? undefined : (
                  <ActionForm action={detachTrafficSource.bind(null, name, s.Identifier!, s.Type)} submit={`Detach ${tg?.TargetGroupName ?? s.Identifier}`} icon={<Unlink size={15} />} confirm={`Detach ${tg?.TargetGroupName ?? s.Identifier}?`} />
                ),
            };
          })}
        />
      </Section>
    ),
  };
};

// --- Details -----------------------------------------------------------------------

export const detailsTab: Tab = async ({ g, name }) => {
  const client = await autoscaling();
  const lt = g.LaunchTemplate ?? g.MixedInstancesPolicy?.LaunchTemplate?.LaunchTemplateSpecification;
  const [processes, terminations, notifications, notificationTypes, net, templates, versions] = await Promise.all([
    client.send(new DescribeScalingProcessTypesCommand({})).then((r) => (r.Processes ?? []).map((p) => p.ProcessName!), () => [] as string[]),
    client.send(new DescribeTerminationPolicyTypesCommand({})).then((r) => r.TerminationPolicyTypes ?? [], () => [] as string[]),
    all((NextToken) => client.send(new DescribeNotificationConfigurationsCommand({ AutoScalingGroupNames: [name], NextToken })), (r) => r.NotificationConfigurations, (r) => r.NextToken).catch(() => []),
    client.send(new DescribeAutoScalingNotificationTypesCommand({})).then((r) => r.AutoScalingNotificationTypes ?? [], () => [] as string[]),
    vpcNetwork().catch(() => ({ vpcs: [], subnets: [] })),
    launchTemplates().catch(() => []),
    lt?.LaunchTemplateName ? templateVersions(lt.LaunchTemplateName).catch(() => []) : Promise.resolve([]),
  ]);
  const subnets = (g.VPCZoneIdentifier ?? "").split(",").filter(Boolean);
  const vpc = net.subnets.find((s) => subnets.includes(s.id))?.vpc;
  const suspended = new Map((g.SuspendedProcesses ?? []).map((p) => [p.ProcessName, p.SuspensionReason]));
  const metricsOn = (g.EnabledMetrics ?? []).length > 0;
  const topics = [...new Set(notifications.map((n) => n.TopicARN!))];
  const settings = (
    <Sheet title="Edit group settings" label="Edit group settings" icon={<Settings2 size={15} />} testId="edit-settings">
      <ActionForm action={editSettings.bind(null, name)} submit="Save" testId="edit-settings">
        {lt?.LaunchTemplateName && (
          <div className="form-row">
            <Field label="Launch template" rule={CreateLaunchTemplate.LaunchTemplateName} member="LaunchTemplate.LaunchTemplateName">
              <select name="template" defaultValue={lt.LaunchTemplateName}>
                {templates.map((t) => (
                  <option key={t.LaunchTemplateId}>{t.LaunchTemplateName}</option>
                ))}
              </select>
            </Field>
            <Field label="Version" member="LaunchTemplate.Version">
              <select name="version" defaultValue={lt.Version ?? "$Default"}>
                <option>$Default</option>
                <option>$Latest</option>
                {versions.map((v) => (
                  <option key={v.VersionNumber} value={String(v.VersionNumber)}>
                    {v.VersionNumber}
                  </option>
                ))}
              </select>
            </Field>
          </div>
        )}
        {net.vpcs.length > 0 && <NetworkFields vpcs={net.vpcs} subnets={net.subnets} vpc={vpc} checked={subnets} />}
        <div className="form-row">
          <Field label="Health check type" rule={UpdateAutoScalingGroup.HealthCheckType} member="HealthCheckType">
            <select name="health" defaultValue={g.HealthCheckType ?? "EC2"}>
              <option>EC2</option>
              <option>ELB</option>
              <option>EBS</option>
              <option>VPC_LATTICE</option>
            </select>
          </Field>
          <Field label="Health check grace period" rule={{ ...UpdateAutoScalingGroup.HealthCheckGracePeriod, min: 0, unit: "seconds" }} member="HealthCheckGracePeriod">
            <input name="grace" defaultValue={g.HealthCheckGracePeriod ?? 0} />
          </Field>
        </div>
        <div className="form-row">
          <Field label="Default cooldown" rule={{ ...UpdateAutoScalingGroup.DefaultCooldown, min: 0, unit: "seconds" }} member="DefaultCooldown">
            <input name="cooldown" defaultValue={g.DefaultCooldown ?? 300} />
          </Field>
          <Field label="Default instance warmup" rule={{ ...UpdateAutoScalingGroup.DefaultInstanceWarmup, min: 0, unit: "seconds" }} member="DefaultInstanceWarmup">
            <input name="warmup" defaultValue={g.DefaultInstanceWarmup} />
          </Field>
        </div>
        <Field label="Maximum instance lifetime" rule={{ ...UpdateAutoScalingGroup.MaxInstanceLifetime, min: 0, unit: "seconds" }} member="MaxInstanceLifetime" hint="0 or at least 1 day; empty for none">
          <input name="lifetime" defaultValue={g.MaxInstanceLifetime || undefined} />
        </Field>
        {terminations.length > 0 && (
          <fieldset className="checks">
            <legend>Termination policies</legend>
            {terminations.map((t) => (
              <label key={t} className="check">
                <input type="checkbox" name="termination" value={t} defaultChecked={(g.TerminationPolicies ?? ["Default"]).includes(t)} /> {t}
              </label>
            ))}
          </fieldset>
        )}
        <label className="check">
          <input type="checkbox" name="rebalance" defaultChecked={!!g.CapacityRebalance} /> Capacity rebalancing
        </label>
        <label className="check">
          <input type="checkbox" name="protect" defaultChecked={!!g.NewInstancesProtectedFromScaleIn} /> Protect new instances from scale in
        </label>
      </ActionForm>
    </Sheet>
  );
  return {
    body: (
      <>
        <Section title="Group details" actions={settings}>
          <Facts
            items={[
              ["Launch template", lt ? `${lt.LaunchTemplateName ?? lt.LaunchTemplateId} (${lt.Version ?? "$Default"})` : g.LaunchConfigurationName],
              ["Subnets", subnets.map((s) => <a key={s} href={`/vpc/subnet?id=${s}`}>{net.subnets.find((x) => x.id === s)?.label ?? s} </a>)],
              ["Availability Zones", (g.AvailabilityZones ?? []).join(", ")],
              ["Health check", `${g.HealthCheckType} · ${g.HealthCheckGracePeriod ?? 0}s grace`],
              ["Default cooldown", `${g.DefaultCooldown ?? 300}s`],
              g.DefaultInstanceWarmup !== undefined && ["Default instance warmup", `${g.DefaultInstanceWarmup}s`],
              !!g.MaxInstanceLifetime && ["Maximum instance lifetime", `${g.MaxInstanceLifetime}s`],
              ["Termination policies", (g.TerminationPolicies ?? ["Default"]).join(", ")],
              g.CapacityRebalance && ["Capacity rebalancing", "On"],
              g.NewInstancesProtectedFromScaleIn && ["Scale-in protection", "New instances protected"],
              g.ServiceLinkedRoleARN && ["Service-linked role", <a key="r" href={`/iam/roles/${g.ServiceLinkedRoleARN.split("/").pop()}`}>{g.ServiceLinkedRoleARN.split("/").pop()}</a>],
              ["Created", when(g.CreatedTime)],
            ]}
          />
        </Section>
        <Section
          title="Advanced configurations"
          plain
          actions={
            <ActionForm action={setMetrics.bind(null, name, !metricsOn)} submit={metricsOn ? "Disable group metrics collection" : "Enable group metrics collection"} icon={<BarChart3 size={15} />} testId="metrics-collection" />
          }
        >
          <List
            label="Processes"
            rows={processes.map((p) => {
              const off = suspended.has(p);
              return {
                key: p,
                icon: off ? <Pause size={18} /> : <Play size={18} />,
                title: p,
                subtitle: off ? suspended.get(p) : undefined,
                meta: <Pill tone={off ? "warn" : "good"}>{off ? "Suspended" : "Active"}</Pill>,
                actions: <ActionForm action={setProcess.bind(null, name, p, !off)} submit={off ? `Resume ${p}` : `Suspend ${p}`} icon={off ? <Play size={15} /> : <Pause size={15} />} />,
              };
            })}
          />
          {metricsOn && <p className="muted">Group metrics: {(g.EnabledMetrics ?? []).map((m) => m.Metric).join(", ")}</p>}
        </Section>
        <Section
          title="Notifications"
          count={topics.length}
          plain
          actions={
            <Sheet title="Create notification" label="Create notification" icon={<Bell size={15} />} testId="add-notification">
              <ActionForm action={putNotification.bind(null, name)} submit="Create" testId="add-notification">
                <Field label="SNS topic ARN" format="arn" member="TopicARN">
                  <ResourcePicker kind="sns-topic" name="topic" required />
                </Field>
                <fieldset className="checks">
                  <legend>Event types</legend>
                  {notificationTypes.map((t) => (
                    <label key={t} className="check">
                      <input type="checkbox" name="type" value={t} defaultChecked={!t.includes("TEST")} /> {t.replace("autoscaling:", "")}
                    </label>
                  ))}
                </fieldset>
              </ActionForm>
            </Sheet>
          }
        >
          <List
            label="Notifications"
            rows={topics.map((t) => ({
              key: t,
              icon: <AwsIcon icon="resource/AmazonSimpleNotificationServiceTopic" size={20} />,
              title: t.split(":").pop(),
              subtitle: notifications
                .filter((n) => n.TopicARN === t)
                .map((n) => n.NotificationType?.replace("autoscaling:", ""))
                .join(", "),
              href: `/sns/topic?arn=${encodeURIComponent(t)}`,
              actions: <ActionForm action={deleteNotification.bind(null, name, t)} submit={`Delete notification to ${t}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Stop notifying ${t}?`} />,
            }))}
          />
        </Section>
        <Section
          title="Tags"
          count={g.Tags?.length}
          plain
          actions={
            <Sheet title="Add tag" label="Add tag" icon={<Tag size={15} />} testId="add-tag">
              <ActionForm action={putTag.bind(null, name)} submit="Save" testId="add-tag">
                <div className="form-row">
                  <Field label="Key" rule={{ minLength: 1, maxLength: 128, reserved: ["aws:"] }} member="Key">
                    <input name="key" required />
                  </Field>
                  <Field label="Value" rule={{ maxLength: 256 }} member="Value">
                    <input name="value" />
                  </Field>
                </div>
                <label className="check">
                  <input type="checkbox" name="propagate" defaultChecked /> Tag new instances
                </label>
              </ActionForm>
            </Sheet>
          }
        >
          <List
            label="Tags"
            rows={(g.Tags ?? []).map((t) => ({
              key: t.Key!,
              icon: <Tag size={16} />,
              title: t.Key,
              subtitle: t.Value,
              meta: t.PropagateAtLaunch ? <Pill>propagates</Pill> : undefined,
              actions: t.Key?.startsWith("aws:") ? undefined : <ActionForm action={deleteTag.bind(null, name, t.Key!)} submit={`Delete tag ${t.Key}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete tag ${t.Key}?`} />,
            }))}
          />
        </Section>
      </>
    ),
  };
};


