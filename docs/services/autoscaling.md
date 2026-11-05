# EC2 Auto Scaling

> Crate: [`mws-autoscaling`](../../crates/services/mws-autoscaling) · Tests: [`autoscaling.rs`](../../tests/e2e-rust/tests/e2e/autoscaling.rs)

All 68 operations of EC2 Auto Scaling (API version 2011-01-01, awsQuery).
Groups are reconciled on the emulated clock: they launch, start, stop and
terminate real EC2 instances through [EC2](ec2.md) (as Docker containers with
the Docker backend), register them with [Elastic Load Balancing](elb.md),
publish group metrics and target tracking alarms to [CloudWatch](cloudwatch.md),
and send notifications through [SNS](sns.md), [SQS](sqs.md) and
[EventBridge](events.md).

✅ supported · 🟡 partial · ❌ not supported

## Groups and instances

| Feature | Status | Details |
| --- | :---: | --- |
| Groups | ✅ | Launch templates (id or name, `$Latest`, `$Default` or a version; the caller needs `ec2:RunInstances` on the template), launch configurations, `CreateAutoScalingGroup` from an `InstanceId`, subnets (`VPCZoneIdentifier`) or Availability Zones, min/max/desired with AWS's checks, `AlreadyExists`, `ResourceInUse` while instances remain, `ForceDelete`, the `AWSServiceRoleForAutoScaling` service-linked role. |
| Capacity | ✅ | A reconciler runs every second of the emulated clock (and after every request): it launches in the zone with the fewest instances, terminates per the termination policies (`Default`, `OldestInstance`, `NewestInstance`, `OldestLaunchTemplate`, `OldestLaunchConfiguration`, `ClosestToNextInstanceHour`, `AllocationStrategy`), rebalances zones, and replaces instances EC2 reports stopped, terminated or impaired. Every change is a scaling activity with AWS's descriptions and causes. |
| Instances | ✅ | Launched as the service-linked role with the template's or configuration's settings, the group's `PropagateAtLaunch` tags and `aws:autoscaling:groupName`; lifecycle states from `Pending` through `InService` to `Terminated`, health (`SetInstanceHealth`, EC2 status), scale-in protection, default instance warmup. |
| Attach, detach, standby | ✅ | `AttachInstances` (same VPC and zones, tags applied), `DetachInstances` with or without decrementing desired capacity, `EnterStandby`/`ExitStandby`, `TerminateInstanceInAutoScalingGroup`, `LaunchInstances` (synchronous launches with per-zone errors). |
| Processes | ✅ | `SuspendProcesses`/`ResumeProcesses` for `Launch`, `Terminate`, `HealthCheck`, `ReplaceUnhealthy`, `AZRebalance`, `AlarmNotification`, `ScheduledActions`, `AddToLoadBalancer`, `InstanceRefresh` and `RemoveFromLoadBalancerLowPriority`; each stops the matching part of the reconciler. |
| Tags | ✅ | `CreateOrUpdateTags`, `DeleteTags`, `DescribeTags` with filters, `aws:` keys refused, `autoscaling:ResourceTag` conditions. |
| Metrics collection | ✅ | `EnableMetricsCollection` publishes the `AWS/AutoScaling` group metrics (`GroupMinSize` ... `GroupTotalCapacity`, warm pool metrics) to CloudWatch every minute. |
| Account limits, catalogues | ✅ | `DescribeAccountLimits`, adjustment types, metric collection types, lifecycle hook and termination policy types, notification types, scaling process types. |
| Mixed instances, Spot | 🟡 | Mixed instances policies are stored and their launch template and overrides (instance type, image) used; Spot options and allocation strategies are not modelled, so every instance is On-Demand. |
| Weighted capacity | 🟡 | Overrides' `WeightedCapacity` is kept on the instance, but capacity counts instances, not weights. |
| ELB health checks | 🟡 | `HealthCheckType` `ELB`/`VPC_LATTICE`/`EBS` is accepted; only EC2 status and `SetInstanceHealth` mark instances unhealthy. |
| Authorization | ✅ | `autoscaling:*` actions on group and launch configuration ARNs with AWS's condition keys (`autoscaling:MinSize`, `MaxSize`, `LaunchConfigurationName`, `LaunchTemplateVersionSpecified`, `VPCZoneIdentifiers`, resource tags). |

## Lifecycle hooks and notifications

| Feature | Status | Details |
| --- | :---: | --- |
| Lifecycle hooks | ✅ | Launching and terminating hooks hold instances in `Pending:Wait`/`Terminating:Wait` (and the warm pool's `Warmed:*` states) until `CompleteLifecycleAction`, the heartbeat timeout (`DefaultResult`) or the global timeout; `RecordLifecycleActionHeartbeat` extends it. Hooks created with the group or by `PutLifecycleHook` send `autoscaling:TEST_NOTIFICATION`. |
| Hook targets | ✅ | SNS topics and SQS queues get AWS's message (`LifecycleActionToken`, `NotificationMetadata`, origin and destination); EventBridge gets `EC2 Instance-launch Lifecycle Action` / `EC2 Instance-terminate Lifecycle Action`. |
| Notification configurations | ✅ | `EC2_INSTANCE_LAUNCH`, `_TERMINATE` and their `_ERROR` types published to SNS (and a test notification when added). |
| EventBridge events | 🟡 | `EC2 Instance Launch Successful`/`Unsuccessful`, `EC2 Instance Terminate Successful`/`Unsuccessful` and the lifecycle action events, source `aws.autoscaling`; instance refresh and warm pool events are not sent. |
| Hook roles | 🟡 | `RoleARN` is required with a target, but its permissions are not checked: Auto Scaling delivers as itself. |
| Other hook targets | ❌ | Hooks deliver to SNS topics and SQS queues (and EventBridge); other ARNs are stored but nothing is delivered to them. |

## Scaling

| Feature | Status | Details |
| --- | :---: | --- |
| Simple and step scaling | ✅ | `ChangeInCapacity`, `ExactCapacity`, `PercentChangeInCapacity` with `MinAdjustmentMagnitude`, step intervals checked for gaps and overlaps, cooldowns (`HonorCooldown`, `ScalingActivityInProgress`), `ExecutePolicy` with metric value and breach threshold. |
| CloudWatch alarms | ✅ | Alarms whose actions name a scaling policy ARN run it when they go to `ALARM` (the cause names the alarm), unless `AlarmNotification` is suspended or the group is in cooldown. |
| Target tracking | ✅ | `PutScalingPolicy` creates the two `TargetTracking-<group>-AlarmHigh/AlarmLow-<uuid>` alarms in CloudWatch for predefined (`ASGAverageCPUUtilization`, `ASGAverageNetworkIn/Out`, `ALBRequestCountPerTarget`) and customized metrics, deleted with the policy; their alarms scale to bring the metric to the target. |
| Predictive scaling | 🟡 | Policies are stored and `GetPredictiveScalingForecast` answers, but the forecast is flat (today's capacity) and `ForecastAndScale` does not act on it. |
| Metric math target tracking | 🟡 | Accepted and stored; the alarms watch the first metric only. |
| Scheduled actions | ✅ | One-time and recurring (cron) actions run on the emulated clock and change min/max/desired, `BatchPutScheduledUpdateGroupAction`/`BatchDeleteScheduledAction` with per-action failures; one-time actions are removed once run. |
| Time zones | 🟡 | `TimeZone` is stored, but recurrences are evaluated in UTC. |

## Instance refresh and warm pools

| Feature | Status | Details |
| --- | :---: | --- |
| Instance refresh | ✅ | `StartInstanceRefresh` replaces instances in batches that keep `MinHealthyPercentage` in service, waits out `InstanceWarmup`, honours `SkipMatching`, protected and standby instance preferences, checkpoints, a `DesiredConfiguration` (applied to the group when the refresh succeeds), `CancelInstanceRefresh`, `RollbackInstanceRefresh` (`IrreversibleInstanceRefresh` without a desired configuration), `DescribeInstanceRefreshes` with progress. |
| Auto rollback | 🟡 | `AutoRollback` and alarm specifications are stored; a refresh only rolls back when asked. |
| Warm pools | ✅ | `PutWarmPool` keeps `MinSize`/`MaxGroupPreparedCapacity` instances launched and then stopped, hibernated or running; scale out takes warmed instances first (from the zone that needs one), scale in returns instances when `ReuseOnScaleIn` is set, `DeleteWarmPool` with and without `ForceDelete`. |

## Load balancers

| Feature | Status | Details |
| --- | :---: | --- |
| Classic and target groups | ✅ | `AttachLoadBalancers`/`AttachLoadBalancerTargetGroups`/`AttachTrafficSources` (and their detach and describe operations) register every in-service instance with the load balancer or target group, newly in-service instances are registered, and terminating, standby and detached ones are deregistered first; the state moves `Adding` → `Added` → `InService`, `Removing` → `Removed`. |
| VPC Lattice | ❌ | MWS has no VPC Lattice, so `vpc-lattice` traffic sources get no targets. |

## Known gaps

- Capacity counts instances, not weights; Spot and allocation strategies are
  not modelled.
- Health checks other than EC2 status do not mark instances unhealthy.
- Predictive scaling forecasts are flat and never scale the group.
- Recurring scheduled actions are evaluated in UTC whatever their `TimeZone`.
- Lifecycle hook roles' permissions are not checked.
- No EventBridge events for instance refreshes or warm pools.
- Alarms only run their scaling policy when they change to `ALARM`, not again
  each period while they stay there.

See also: [all services](README.md) · [configuration](../configuration.md).
