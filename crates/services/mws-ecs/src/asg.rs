//! Auto Scaling group capacity providers: instances the group launches join
//! the provider's cluster as container instances (as the ECS agent in the
//! ECS-optimized AMI makes them do), leave it when they terminate, and with
//! managed scaling ECS sets the group's desired capacity from the
//! `CapacityProviderReservation` it targets.

use mws_core::{AllowAll, RequestContext};

use crate::generated::types as t;
use crate::names::{last_segment, Scope};
use crate::state::Region;
use crate::Ecs;

/// One provider's view of its cluster, taken under the state lock.
#[derive(Debug, Clone)]
pub(crate) struct ProviderView {
    name: String,
    group: String,
    cluster: String,
    /// (target capacity, minimum step, maximum step) when managed scaling is on.
    managed: Option<(i32, i32, i32)>,
    /// Registered instances: (container instance ARN, EC2 id, runs tasks?).
    registered: Vec<(String, String, bool)>,
    /// Service tasks this provider should run but has no room for.
    unplaced: i32,
}

/// The group name in an Auto Scaling group ARN.
fn group_name(arn: &str) -> String {
    arn.rsplit_once("autoScalingGroupName/").map(|(_, n)| n.to_string()).unwrap_or_else(|| last_segment(arn).into())
}

fn uses(strategy: &[t::CapacityProviderStrategyItem], name: &str) -> bool {
    strategy.iter().any(|s| s.capacity_provider == name)
}

impl Ecs {
    pub(crate) fn provider_views(r: &Region) -> Vec<ProviderView> {
        let mut out = Vec::new();
        for cp in r.capacity_providers.values() {
            if cp.status.as_deref() != Some("ACTIVE") {
                continue;
            }
            let Some(asg) = &cp.auto_scaling_group_provider else { continue };
            let name = cp.name.clone().unwrap_or_default();
            let Some(cluster) = r
                .clusters
                .values()
                .find(|c| {
                    c.status.as_deref() == Some("ACTIVE") && c.capacity_providers.iter().flatten().any(|p| *p == name)
                })
                .and_then(|c| c.cluster_name.clone())
            else {
                continue;
            };
            let managed = asg.managed_scaling.as_ref().filter(|m| m.status.as_deref() == Some("ENABLED")).map(|m| {
                (
                    m.target_capacity.unwrap_or(100).clamp(1, 100),
                    m.minimum_scaling_step_size.unwrap_or(1).max(1),
                    m.maximum_scaling_step_size.unwrap_or(10_000).max(1),
                )
            });
            let registered = r
                .container_instances
                .iter()
                .filter(|(_, i)| {
                    i.cluster == cluster
                        && i.instance.capacity_provider_name.as_deref() == Some(name.as_str())
                        && i.instance.status.as_deref() != Some("INACTIVE")
                })
                .map(|(a, i)| {
                    let busy = r.tasks.values().any(|t| {
                        t.task.container_instance_arn.as_deref() == Some(a.as_str())
                            && t.task.desired_status.as_deref() != Some("STOPPED")
                    });
                    (a.clone(), i.instance.ec2_instance_id.clone().unwrap_or_default(), busy)
                })
                .collect();
            let default_strategy =
                r.clusters.get(&cluster).and_then(|c| c.default_capacity_provider_strategy.clone()).unwrap_or_default();
            let unplaced = r
                .services
                .values()
                .filter(|s| s.cluster == cluster && s.service.status.as_deref() == Some("ACTIVE"))
                .filter(|s| {
                    let strategy = s.service.capacity_provider_strategy.clone().unwrap_or_default();
                    if strategy.is_empty() && s.service.launch_type.is_none() {
                        uses(&default_strategy, &name)
                    } else {
                        uses(&strategy, &name)
                    }
                })
                .map(|s| {
                    let arn = s.service.service_arn.clone().unwrap_or_default();
                    let live = r
                        .tasks
                        .values()
                        .filter(|t| {
                            t.service_arn.as_deref() == Some(arn.as_str())
                                && t.task.desired_status.as_deref() != Some("STOPPED")
                        })
                        .count() as i32;
                    (s.service.desired_count - live).max(0)
                })
                .sum();
            out.push(ProviderView {
                name,
                group: group_name(&asg.auto_scaling_group_arn),
                cluster,
                managed,
                registered,
                unplaced,
            });
        }
        out
    }

    /// Bring a provider's container instances in line with its group, then
    /// scale the group when managed scaling is on.
    pub(crate) async fn sync_provider(&self, ctx: &RequestContext, view: ProviderView) {
        let Some(platform) = self.platform() else { return };
        let Some(group) = platform.scaling_group(ctx, &view.group).await else { return };
        let behalf = RequestContext { authorizer: std::sync::Arc::new(AllowAll), ..ctx.clone() };
        for inst in &group.instances {
            if inst.lifecycle_state != "InService" {
                continue;
            }
            if view.registered.iter().any(|(_, id, _)| id == &inst.instance_id) {
                continue;
            }
            let (vcpus, mem) = platform.instance_type_resources(ctx, &inst.instance_type).await.unwrap_or((2, 4096));
            let doc = serde_json::json!({
                "instanceId": inst.instance_id,
                "instanceType": inst.instance_type,
                "availabilityZone": inst.availability_zone,
                "region": ctx.region,
            })
            .to_string();
            let resources = vec![
                t::Resource {
                    name: Some("CPU".into()),
                    r#type: Some("INTEGER".into()),
                    integer_value: vcpus * 1024,
                    ..Default::default()
                },
                t::Resource {
                    name: Some("MEMORY".into()),
                    r#type: Some("INTEGER".into()),
                    integer_value: (mem - 256).max(256),
                    ..Default::default()
                },
                t::Resource {
                    name: Some("PORTS".into()),
                    r#type: Some("STRINGSET".into()),
                    string_set_value: Some(["22", "2375", "2376", "51678", "51679"].map(String::from).to_vec()),
                    ..Default::default()
                },
            ];
            let registered = self.register_container_instance_op(
                &behalf,
                t::RegisterContainerInstanceRequest {
                    cluster: Some(view.cluster.clone()),
                    instance_identity_document: Some(doc),
                    total_resources: Some(resources),
                    ..Default::default()
                },
            );
            match registered {
                Ok(out) => {
                    let arn = out.container_instance.and_then(|c| c.container_instance_arn).unwrap_or_default();
                    let scope = Scope::of(ctx);
                    let mut st = self.lock();
                    if let Some(rec) = st.region(&scope.key()).container_instances.get_mut(&arn) {
                        rec.instance.capacity_provider_name = Some(view.name.clone());
                        rec.instance.attributes.get_or_insert_with(Vec::new).push(t::Attribute {
                            name: "ecs.capacity-provider-name".into(),
                            value: Some(view.name.clone()),
                            ..Default::default()
                        });
                    }
                }
                Err(e) => tracing::warn!("ECS could not register {}: {}", inst.instance_id, e.message),
            }
        }
        for (arn, id, _) in &view.registered {
            let gone =
                !group.instances.iter().any(|i| &i.instance_id == id && !i.lifecycle_state.starts_with("Terminat"));
            if gone {
                let _ = self.deregister_container_instance_op(
                    &behalf,
                    t::DeregisterContainerInstanceRequest {
                        cluster: Some(view.cluster.clone()),
                        container_instance: arn.clone(),
                        force: Some(true),
                    },
                );
            }
        }
        let Some((target, min_step, max_step)) = view.managed else { return };
        let busy = view.registered.iter().filter(|(_, _, b)| *b).count() as i32;
        let current = group.instances.iter().filter(|i| !i.lifecycle_state.starts_with("Terminat")).count() as i32;
        // M: the instances needed to run every task. Tasks waiting for room
        // each get an instance (a step at a time) on top of the busy ones;
        // the group never shrinks while any are waiting.
        let needed = if view.unplaced > 0 { current.max(busy + view.unplaced.clamp(min_step, max_step)) } else { busy };
        let desired = ((needed * 100) as f64 / target as f64).ceil() as i32;
        let desired = desired.clamp(group.min_size, group.max_size);
        // Scale-out alarms fire after a minute; scale-in ones after fifteen
        // minutes of low reservation.
        let key = format!("{}/{}", Scope::of(ctx).key(), view.name);
        if desired < group.desired_capacity {
            let now = self.now();
            let mut low = self.inner.low_reservation.lock().expect("ECS scaling lock poisoned");
            let since = *low.entry(key).or_insert(now);
            if now - since < chrono::Duration::minutes(15) {
                return;
            }
        } else {
            self.inner.low_reservation.lock().expect("ECS scaling lock poisoned").remove(&key);
        }
        if desired != group.desired_capacity {
            if let Err(e) = platform.set_desired_capacity(ctx, &view.group, desired).await {
                tracing::warn!("ECS managed scaling of {} failed: {}", view.group, e.message);
            }
        }
    }
}
