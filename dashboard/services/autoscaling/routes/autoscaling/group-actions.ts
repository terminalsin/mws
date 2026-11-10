"use server";

import {
  AttachInstancesCommand,
  AttachTrafficSourcesCommand,
  CancelInstanceRefreshCommand,
  CompleteLifecycleActionCommand,
  CreateOrUpdateTagsCommand,
  DeleteLifecycleHookCommand,
  DeleteNotificationConfigurationCommand,
  DeleteScheduledActionCommand,
  DeleteTagsCommand,
  DeleteWarmPoolCommand,
  DetachInstancesCommand,
  DetachTrafficSourcesCommand,
  DisableMetricsCollectionCommand,
  EnableMetricsCollectionCommand,
  EnterStandbyCommand,
  ExecutePolicyCommand,
  ExitStandbyCommand,
  PutLifecycleHookCommand,
  PutNotificationConfigurationCommand,
  PutScheduledUpdateGroupActionCommand,
  PutWarmPoolCommand,
  RecordLifecycleActionHeartbeatCommand,
  ResumeProcessesCommand,
  RollbackInstanceRefreshCommand,
  SetInstanceHealthCommand,
  SetInstanceProtectionCommand,
  StartInstanceRefreshCommand,
  SuspendProcessesCommand,
  TerminateInstanceInAutoScalingGroupCommand,
  UpdateAutoScalingGroupCommand,
  type RefreshPreferences,
  type WarmPoolState,
} from "@aws-sdk/client-auto-scaling";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";

import { autoscaling } from "../../lib/clients";

const PAGES = ["/autoscaling/group", "/autoscaling"];

const int = (form: FormData, name: string) => {
  const v = text(form, name);
  return v === "" ? undefined : Number(v);
};
const on = (form: FormData, name: string) => form.get(name) === "on";
const values = (form: FormData, name: string) => form.getAll(name).map(String).filter(Boolean);

// --- Instance refresh ---------------------------------------------------------

export async function startRefresh(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const checkpoints = text(form, "checkpoints")
      .split(/[\s,]+/)
      .filter(Boolean)
      .map(Number);
    const Preferences: RefreshPreferences = {
      MinHealthyPercentage: int(form, "minHealthy"),
      MaxHealthyPercentage: int(form, "maxHealthy"),
      InstanceWarmup: int(form, "warmup"),
      SkipMatching: on(form, "skipMatching"),
      AutoRollback: on(form, "autoRollback") || undefined,
      ScaleInProtectedInstances: (text(form, "protected") || undefined) as RefreshPreferences["ScaleInProtectedInstances"],
      StandbyInstances: (text(form, "standby") || undefined) as RefreshPreferences["StandbyInstances"],
      ...(checkpoints.length ? { CheckpointPercentages: checkpoints, CheckpointDelay: int(form, "checkpointDelay") } : {}),
    };
    const template = text(form, "template");
    const version = text(form, "version");
    const out = await (await autoscaling()).send(
      new StartInstanceRefreshCommand({
        AutoScalingGroupName: name,
        Preferences,
        DesiredConfiguration: template && version ? { LaunchTemplate: { LaunchTemplateName: template, Version: version } } : undefined,
      }),
    );
    return `Refresh ${out.InstanceRefreshId?.slice(0, 8)} started`;
  }, {
    revalidate: PAGES,
    fields: {
      "Preferences.MinHealthyPercentage": "minHealthy",
      "Preferences.MaxHealthyPercentage": "maxHealthy",
      "Preferences.InstanceWarmup": "warmup",
      "Preferences.CheckpointPercentages": "checkpoints",
      "Preferences.CheckpointDelay": "checkpointDelay",
      InstanceRefreshInProgress: "minHealthy",
    },
  });
}

export async function cancelRefresh(name: string) {
  return act(async () => {
    await (await autoscaling()).send(new CancelInstanceRefreshCommand({ AutoScalingGroupName: name }));
    return "Cancelling refresh";
  }, ...PAGES);
}

export async function rollbackRefresh(name: string) {
  return act(async () => {
    await (await autoscaling()).send(new RollbackInstanceRefreshCommand({ AutoScalingGroupName: name }));
    return "Rolling back";
  }, ...PAGES);
}

// --- Instances ----------------------------------------------------------------

export async function terminateInstance(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await autoscaling()).send(new TerminateInstanceInAutoScalingGroupCommand({ InstanceId: id, ShouldDecrementDesiredCapacity: on(form, "decrement") }));
    return "Terminating";
  }, ...PAGES);
}

export async function standby(name: string, id: string, enter: boolean, decrement = true) {
  return act(async () => {
    const client = await autoscaling();
    if (enter) await client.send(new EnterStandbyCommand({ AutoScalingGroupName: name, InstanceIds: [id], ShouldDecrementDesiredCapacity: decrement }));
    else await client.send(new ExitStandbyCommand({ AutoScalingGroupName: name, InstanceIds: [id] }));
    return enter ? "Entering standby" : "Leaving standby";
  }, ...PAGES);
}

export async function protect(name: string, id: string, protectedFromScaleIn: boolean) {
  return act(async () => {
    await (await autoscaling()).send(new SetInstanceProtectionCommand({ AutoScalingGroupName: name, InstanceIds: [id], ProtectedFromScaleIn: protectedFromScaleIn }));
    return protectedFromScaleIn ? "Protected from scale in" : "Protection removed";
  }, ...PAGES);
}

export async function setHealth(id: string, healthy: boolean) {
  return act(async () => {
    await (await autoscaling()).send(new SetInstanceHealthCommand({ InstanceId: id, HealthStatus: healthy ? "Healthy" : "Unhealthy" }));
    return healthy ? "Marked healthy" : "Marked unhealthy";
  }, ...PAGES);
}

export async function detachInstance(name: string, id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await autoscaling()).send(new DetachInstancesCommand({ AutoScalingGroupName: name, InstanceIds: [id], ShouldDecrementDesiredCapacity: on(form, "decrement") }));
    return "Detaching";
  }, ...PAGES);
}

export async function attachInstances(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const InstanceIds = values(form, "instance");
    if (!InstanceIds.length) throw new FieldError("instance", "Pick at least one instance", "required");
    await (await autoscaling()).send(new AttachInstancesCommand({ AutoScalingGroupName: name, InstanceIds }));
    return `${InstanceIds.length} attached`;
  }, { revalidate: PAGES, fields: { InstanceIds: "instance" } });
}

// --- Lifecycle hooks ----------------------------------------------------------

export async function putHook(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const LifecycleHookName = required(form, "hook", "Name");
    await (await autoscaling()).send(
      new PutLifecycleHookCommand({
        AutoScalingGroupName: name,
        LifecycleHookName,
        LifecycleTransition: text(form, "transition") || "autoscaling:EC2_INSTANCE_LAUNCHING",
        HeartbeatTimeout: int(form, "timeout"),
        DefaultResult: text(form, "result") || "ABANDON",
        NotificationTargetARN: text(form, "target") || undefined,
        RoleARN: text(form, "role") || undefined,
        NotificationMetadata: text(form, "metadata") || undefined,
      }),
    );
    return `Hook ${LifecycleHookName} saved`;
  }, {
    revalidate: PAGES,
    fields: { LifecycleHookName: "hook", HeartbeatTimeout: "timeout", NotificationTargetARN: "target", RoleARN: "role", NotificationMetadata: "metadata", LimitExceeded: "hook" },
  });
}

export async function deleteHook(name: string, hook: string) {
  return act(async () => {
    await (await autoscaling()).send(new DeleteLifecycleHookCommand({ AutoScalingGroupName: name, LifecycleHookName: hook }));
    return "Hook deleted";
  }, ...PAGES);
}

/** Release an instance a hook holds (`Pending:Wait`, `Terminating:Wait`). */
export async function completeAction(name: string, hook: string, instance: string, result: "CONTINUE" | "ABANDON") {
  return act(async () => {
    await (await autoscaling()).send(new CompleteLifecycleActionCommand({ AutoScalingGroupName: name, LifecycleHookName: hook, InstanceId: instance, LifecycleActionResult: result }));
    return result === "CONTINUE" ? "Continued" : "Abandoned";
  }, ...PAGES);
}

export async function heartbeat(name: string, hook: string, instance: string) {
  return act(async () => {
    await (await autoscaling()).send(new RecordLifecycleActionHeartbeatCommand({ AutoScalingGroupName: name, LifecycleHookName: hook, InstanceId: instance }));
    return "Heartbeat recorded";
  }, ...PAGES);
}

// --- Scheduled actions --------------------------------------------------------

const utc = (v: string) => (v ? new Date(`${v}${v.length === 16 ? ":00" : ""}Z`) : undefined);

export async function putSchedule(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const ScheduledActionName = required(form, "action", "Name");
    const recurring = text(form, "kind") === "cron";
    const MinSize = int(form, "min");
    const MaxSize = int(form, "max");
    const DesiredCapacity = int(form, "desired");
    if (MinSize === undefined && MaxSize === undefined && DesiredCapacity === undefined) throw new FieldError("desired", "Set at least one of min, desired or max", "required");
    await (await autoscaling()).send(
      new PutScheduledUpdateGroupActionCommand({
        AutoScalingGroupName: name,
        ScheduledActionName,
        Recurrence: recurring ? required(form, "recurrence", "Cron expression") : undefined,
        StartTime: utc(text(form, "start")),
        EndTime: recurring ? utc(text(form, "end")) : undefined,
        MinSize,
        MaxSize,
        DesiredCapacity,
        TimeZone: text(form, "zone") || undefined,
      }),
    );
    return `${ScheduledActionName} scheduled`;
  }, {
    revalidate: PAGES,
    fields: { ScheduledActionName: "action", Recurrence: "recurrence", StartTime: "start", EndTime: "end", MinSize: "min", MaxSize: "max", DesiredCapacity: "desired", AlreadyExists: "action" },
  });
}

export async function deleteSchedule(name: string, action: string) {
  return act(async () => {
    await (await autoscaling()).send(new DeleteScheduledActionCommand({ AutoScalingGroupName: name, ScheduledActionName: action }));
    return "Scheduled action deleted";
  }, ...PAGES);
}

export async function executePolicy(name: string, policy: string) {
  return act(async () => {
    await (await autoscaling()).send(new ExecutePolicyCommand({ AutoScalingGroupName: name, PolicyName: policy, HonorCooldown: true }));
    return `${policy} executed`;
  }, ...PAGES);
}

// --- Warm pool ----------------------------------------------------------------

export async function putWarmPool(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await autoscaling()).send(
      new PutWarmPoolCommand({
        AutoScalingGroupName: name,
        MinSize: int(form, "min"),
        MaxGroupPreparedCapacity: int(form, "maxPrepared"),
        PoolState: (text(form, "state") || "Stopped") as WarmPoolState,
        InstanceReusePolicy: { ReuseOnScaleIn: on(form, "reuse") },
      }),
    );
    return "Warm pool saved";
  }, { revalidate: PAGES, fields: { MinSize: "min", MaxGroupPreparedCapacity: "maxPrepared", PoolState: "state" } });
}

export async function deleteWarmPool(name: string) {
  return act(async () => {
    await (await autoscaling()).send(new DeleteWarmPoolCommand({ AutoScalingGroupName: name, ForceDelete: true }));
    return "Deleting warm pool";
  }, ...PAGES);
}

// --- Load balancing -----------------------------------------------------------

export async function attachTargetGroups(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const arns = values(form, "tg");
    if (!arns.length) throw new FieldError("tg", "Pick at least one target group", "required");
    await (await autoscaling()).send(new AttachTrafficSourcesCommand({ AutoScalingGroupName: name, TrafficSources: arns.map((Identifier) => ({ Identifier, Type: "elbv2" })) }));
    return `${arns.length} attached`;
  }, { revalidate: PAGES, fields: { TrafficSources: "tg" } });
}

export async function detachTrafficSource(name: string, identifier: string, type: string | undefined) {
  return act(async () => {
    await (await autoscaling()).send(new DetachTrafficSourcesCommand({ AutoScalingGroupName: name, TrafficSources: [{ Identifier: identifier, Type: type }] }));
    return "Detaching";
  }, ...PAGES);
}

// --- Group settings -----------------------------------------------------------

export async function editSettings(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const template = text(form, "template");
    const subnets = values(form, "subnet");
    await (await autoscaling()).send(
      new UpdateAutoScalingGroupCommand({
        AutoScalingGroupName: name,
        LaunchTemplate: template ? { LaunchTemplateName: template, Version: text(form, "version") || "$Default" } : undefined,
        VPCZoneIdentifier: subnets.length ? subnets.join(",") : undefined,
        HealthCheckType: text(form, "health") || undefined,
        HealthCheckGracePeriod: int(form, "grace"),
        DefaultCooldown: int(form, "cooldown"),
        DefaultInstanceWarmup: int(form, "warmup"),
        MaxInstanceLifetime: int(form, "lifetime"),
        TerminationPolicies: values(form, "termination").length ? values(form, "termination") : undefined,
        CapacityRebalance: on(form, "rebalance"),
        NewInstancesProtectedFromScaleIn: on(form, "protect"),
      }),
    );
    return "Settings saved";
  }, {
    revalidate: PAGES,
    fields: {
      HealthCheckType: "health",
      HealthCheckGracePeriod: "grace",
      DefaultCooldown: "cooldown",
      DefaultInstanceWarmup: "warmup",
      MaxInstanceLifetime: "lifetime",
      TerminationPolicies: "termination",
      VPCZoneIdentifier: "subnet",
      "LaunchTemplate.Version": "version",
    },
  });
}

export async function setProcess(name: string, process: string, suspend: boolean) {
  return act(async () => {
    const client = await autoscaling();
    if (suspend) await client.send(new SuspendProcessesCommand({ AutoScalingGroupName: name, ScalingProcesses: [process] }));
    else await client.send(new ResumeProcessesCommand({ AutoScalingGroupName: name, ScalingProcesses: [process] }));
    return suspend ? `${process} suspended` : `${process} resumed`;
  }, ...PAGES);
}

export async function setMetrics(name: string, enable: boolean) {
  return act(async () => {
    const client = await autoscaling();
    if (enable) await client.send(new EnableMetricsCollectionCommand({ AutoScalingGroupName: name, Granularity: "1Minute" }));
    else await client.send(new DisableMetricsCollectionCommand({ AutoScalingGroupName: name }));
    return enable ? "Group metrics collection on" : "Group metrics collection off";
  }, ...PAGES);
}

export async function putTag(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Key = required(form, "key", "Key");
    await (await autoscaling()).send(
      new CreateOrUpdateTagsCommand({ Tags: [{ ResourceId: name, ResourceType: "auto-scaling-group", Key, Value: text(form, "value"), PropagateAtLaunch: on(form, "propagate") }] }),
    );
    return `Tag ${Key} saved`;
  }, { revalidate: PAGES, fields: { Key: "key", "Tags.member.1.Key": "key", Value: "value" } });
}

export async function deleteTag(name: string, key: string) {
  return act(async () => {
    await (await autoscaling()).send(new DeleteTagsCommand({ Tags: [{ ResourceId: name, ResourceType: "auto-scaling-group", Key: key }] }));
    return "Tag deleted";
  }, ...PAGES);
}

export async function putNotification(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const TopicARN = required(form, "topic", "SNS topic");
    const NotificationTypes = values(form, "type");
    if (!NotificationTypes.length) throw new FieldError("type", "Pick at least one event", "required");
    await (await autoscaling()).send(new PutNotificationConfigurationCommand({ AutoScalingGroupName: name, TopicARN, NotificationTypes }));
    return "Notification saved";
  }, { revalidate: PAGES, fields: { TopicARN: "topic", NotificationTypes: "type" } });
}

export async function deleteNotification(name: string, topic: string) {
  return act(async () => {
    await (await autoscaling()).send(new DeleteNotificationConfigurationCommand({ AutoScalingGroupName: name, TopicARN: topic }));
    return "Notification deleted";
  }, ...PAGES);
}
