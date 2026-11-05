//! Express gateway services: one call that registers a Fargate task
//! definition and runs it as a service behind a public HTTPS endpoint.
//! MWS does what ECS does on your behalf (creates the cluster when missing,
//! registers the task definition, creates and updates the real service), so
//! the tasks run like any other service's; the load balancer, certificate
//! and auto scaling ECS would manage are reported but not created.

use std::sync::Arc;

use mws_core::{AllowAll, RequestContext, ServiceError};

use crate::generated::types as t;
use crate::names::{authorize, check_tags, client, cluster_name, invalid, request_tags, resource_tags, Cond, Scope};
use crate::{services, Ecs};

const DEFAULT_PORT: i32 = 80;
const DEFAULT_CPU: &str = "1024";
const DEFAULT_MEMORY: &str = "2048";
const DEFAULT_HEALTH_CHECK: &str = "/ping";

/// What ECS manages for an Express service's ingress, as service revisions
/// report it.
fn managed_resources(
    i: &crate::platform::ExpressIngress,
    endpoint: &str,
    port: i32,
    health_check_path: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> t::ECSManagedResources {
    t::ECSManagedResources {
        ingress_paths: Some(vec![t::ManagedIngressPath {
            access_type: "PUBLIC".into(),
            endpoint: endpoint.to_string(),
            load_balancer: Some(t::ManagedLoadBalancer {
                arn: Some(i.load_balancer_arn.clone()),
                status: "ACTIVE".into(),
                status_reason: None,
                updated_at: now,
                scheme: "internet-facing".into(),
                subnet_ids: Some(i.subnets.clone()),
                security_group_ids: Some(i.security_groups.clone()),
            }),
            listener: Some(t::ManagedListener {
                arn: Some(i.listener_arn.clone()),
                status: "ACTIVE".into(),
                status_reason: None,
                updated_at: now,
            }),
            target_groups: Some(vec![t::ManagedTargetGroup {
                arn: Some(i.target_group_arn.clone()),
                status: "ACTIVE".into(),
                status_reason: None,
                updated_at: now,
                health_check_path: health_check_path.to_string(),
                health_check_port: port,
                port,
            }]),
            ..Default::default()
        }]),
        ..Default::default()
    }
}

fn not_found() -> ServiceError {
    crate::names::service_not_found()
}

/// A service name from an image reference: `repo/app:tag` -> `app`.
fn name_from_image(image: &str) -> String {
    let base = image.rsplit('/').next().unwrap_or(image);
    let base = base.split(['@', ':']).next().unwrap_or(base);
    let clean: String = base.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '-' }).collect();
    let clean = clean.trim_matches('-');
    let clean = if clean.is_empty() { "express" } else { clean };
    let suffix = &crate::names::hex_id()[..6];
    format!("{}-{suffix}", &clean[..clean.len().min(40)])
}

/// What ECS acts with on the caller's behalf: the caller's identity, with
/// the checks already done.
fn on_behalf(ctx: &RequestContext) -> RequestContext {
    let mut c = ctx.clone();
    c.authorizer = Arc::new(AllowAll);
    c
}

struct Config {
    execution_role_arn: Option<String>,
    task_role_arn: Option<String>,
    cpu: String,
    memory: String,
    cpu_architecture: Option<String>,
    health_check_path: String,
    primary_container: Option<t::ExpressGatewayContainer>,
    network: t::ExpressGatewayServiceNetworkConfiguration,
    scaling: t::ExpressGatewayScalingTarget,
    task_definition_arn: Option<String>,
}

impl Ecs {
    fn express_task_definition(
        &self,
        ctx: &RequestContext,
        family: &str,
        cluster: &str,
        c: &Config,
    ) -> Result<String, ServiceError> {
        if let Some(td) = &c.task_definition_arn {
            return Ok(td.clone());
        }
        let p = c
            .primary_container
            .as_ref()
            .ok_or_else(|| invalid("primaryContainer must be provided when taskDefinitionArn is not."))?;
        let port = p.container_port.unwrap_or(DEFAULT_PORT);
        let logs = p.aws_logs_configuration.clone().unwrap_or(t::ExpressGatewayServiceAwsLogsConfiguration {
            log_group: format!("/aws/ecs/{cluster}/{family}"),
            log_stream_prefix: "ecs".into(),
        });
        let mut options = std::collections::BTreeMap::new();
        options.insert("awslogs-group".to_string(), logs.log_group.clone());
        options.insert("awslogs-region".to_string(), ctx.region.clone());
        options.insert("awslogs-stream-prefix".to_string(), logs.log_stream_prefix.clone());
        options.insert("awslogs-create-group".to_string(), "true".to_string());
        let container = t::ContainerDefinition {
            name: Some("Main".into()),
            image: Some(p.image.clone()),
            repository_credentials: p
                .repository_credentials
                .as_ref()
                .and_then(|r| r.credentials_parameter.clone())
                .map(|credentials_parameter| t::RepositoryCredentials { credentials_parameter }),
            port_mappings: Some(vec![t::PortMapping {
                container_port: Some(port),
                host_port: Some(port),
                protocol: Some("tcp".into()),
                name: Some(format!("{port}-tcp")),
                app_protocol: Some("http".into()),
                container_port_range: None,
            }]),
            essential: Some(true),
            command: p.command.clone(),
            environment: p.environment.clone(),
            secrets: p.secrets.clone(),
            log_configuration: c.execution_role_arn.as_ref().map(|_| t::LogConfiguration {
                log_driver: "awslogs".into(),
                options: Some(options.into_iter().collect()),
                secret_options: None,
            }),
            ..Default::default()
        };
        let out = self.register_task_definition_op(
            &on_behalf(ctx),
            t::RegisterTaskDefinitionRequest {
                family: family.to_string(),
                task_role_arn: c.task_role_arn.clone(),
                execution_role_arn: c.execution_role_arn.clone(),
                network_mode: Some("awsvpc".into()),
                container_definitions: vec![container],
                requires_compatibilities: Some(vec!["FARGATE".into()]),
                cpu: Some(c.cpu.clone()),
                memory: Some(c.memory.clone()),
                runtime_platform: Some(t::RuntimePlatform {
                    cpu_architecture: Some(c.cpu_architecture.clone().unwrap_or_else(|| "X86_64".into())),
                    operating_system_family: Some("LINUX".into()),
                }),
                ..Default::default()
            },
        )?;
        out.task_definition
            .and_then(|d| d.task_definition_arn)
            .ok_or_else(|| client("Unable to register the task definition."))
    }

    fn subnets_for(&self, ctx: &RequestContext, given: &t::ExpressGatewayServiceNetworkConfiguration) -> Vec<String> {
        if let Some(s) = given.subnets.clone().filter(|s| !s.is_empty()) {
            return s;
        }
        let scope = Scope::of(ctx);
        let found = self.platform().map(|p| p.default_subnets(ctx, &scope.account)).unwrap_or_default();
        if found.is_empty() {
            vec!["subnet-default".into()]
        } else {
            found
        }
    }

    fn configuration(
        c: &Config,
        td: &str,
        revision: Option<String>,
        endpoint: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> t::ExpressGatewayServiceConfiguration {
        t::ExpressGatewayServiceConfiguration {
            service_revision_arn: revision,
            execution_role_arn: c.execution_role_arn.clone(),
            task_role_arn: c.task_role_arn.clone(),
            task_definition_arn: Some(td.to_string()),
            cpu: Some(c.cpu.clone()),
            memory: Some(c.memory.clone()),
            cpu_architecture: Some(c.cpu_architecture.clone().unwrap_or_else(|| "X86_64".into())),
            network_configuration: Some(c.network.clone()),
            health_check_path: Some(c.health_check_path.clone()),
            primary_container: c.primary_container.clone(),
            scaling_target: Some(c.scaling.clone()),
            ingress_paths: Some(vec![t::IngressPathSummary {
                access_type: "PUBLIC".into(),
                endpoint: endpoint.to_string(),
            }]),
            created_at: Some(now),
        }
    }

    fn authorize_express_roles(
        &self,
        ctx: &RequestContext,
        infrastructure: Option<&str>,
        execution: Option<&str>,
        task: Option<&str>,
    ) -> Result<(), ServiceError> {
        if let Some(r) = infrastructure {
            self.pass_role(ctx, r, "ecs.amazonaws.com")?;
        }
        for r in [execution, task].into_iter().flatten() {
            self.pass_role(ctx, r, "ecs-tasks.amazonaws.com")?;
        }
        Ok(())
    }

    fn latest_revision(&self, ctx: &RequestContext, service_arn: &str) -> Option<String> {
        self.with_region(ctx, |r, _| {
            let rec = r.services.get(service_arn)?;
            let dep = rec.current_deployment_arn.as_ref()?;
            r.service_deployments.get(dep)?.target_service_revision.as_ref()?.arn.clone()
        })
    }

    pub(crate) async fn create_express_gateway_service_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateExpressGatewayServiceRequest,
    ) -> Result<t::CreateExpressGatewayServiceResponse, ServiceError> {
        if let Some(tags) = &input.tags {
            check_tags(tags)?;
        }
        if input.primary_container.is_none() && input.task_definition_arn.is_none() {
            return Err(invalid("primaryContainer must be provided when taskDefinitionArn is not."));
        }
        let scope = Scope::of(ctx);
        let cluster = cluster_name(input.cluster.as_deref());
        let name = input.service_name.clone().unwrap_or_else(|| {
            name_from_image(input.primary_container.as_ref().map(|p| p.image.as_str()).unwrap_or("express"))
        });
        let arn = services::service_arn(&scope, &cluster, &name);
        authorize(
            ctx,
            "CreateExpressGatewayService",
            &arn,
            Cond::new().cluster(&scope, &cluster).extend(request_tags(input.tags.as_ref())),
        )?;
        self.authorize_express_roles(
            ctx,
            Some(&input.infrastructure_role_arn),
            input.execution_role_arn.as_deref(),
            input.task_role_arn.as_deref(),
        )?;
        if input.task_definition_arn.is_none() {
            authorize(ctx, "RegisterTaskDefinition", &scope.arn(&format!("task-definition/{name}:*")), Cond::new())?;
        }
        self.authorize_create_tags(ctx, &arn, "CreateExpressGatewayService", input.tags.as_ref())?;
        let cpu = input.cpu.clone().unwrap_or_else(|| DEFAULT_CPU.into());
        let memory = input.memory.clone().unwrap_or_else(|| DEFAULT_MEMORY.into());
        let mut scaling = input.scaling_target.clone().unwrap_or_default();
        let min = scaling.min_task_count.unwrap_or(1);
        let max = scaling.max_task_count.unwrap_or(min.max(1));
        if min < 0 || max < min {
            return Err(invalid("scalingTarget.maxTaskCount must be greater than or equal to minTaskCount."));
        }
        scaling.min_task_count = Some(min);
        scaling.max_task_count = Some(max);
        scaling.auto_scaling_metric.get_or_insert_with(|| "AVERAGE_CPU".into());
        scaling.auto_scaling_target_value.get_or_insert(60);
        let mut network = input.network_configuration.clone().unwrap_or_default();
        network.subnets = Some(self.subnets_for(ctx, &network));
        let config = Config {
            execution_role_arn: input.execution_role_arn.clone(),
            task_role_arn: input.task_role_arn.clone(),
            cpu,
            memory,
            cpu_architecture: input.cpu_architecture.clone(),
            health_check_path: input.health_check_path.clone().unwrap_or_else(|| DEFAULT_HEALTH_CHECK.into()),
            primary_container: input.primary_container.clone(),
            network,
            scaling,
            task_definition_arn: input.task_definition_arn.clone(),
        };
        let behalf = on_behalf(ctx);
        let cluster_exists = self.with_region(ctx, |r, _| crate::clusters::active(r, Some(&cluster)).is_ok());
        if !cluster_exists {
            self.create_cluster_op(
                &behalf,
                t::CreateClusterRequest { cluster_name: Some(cluster.clone()), ..Default::default() },
            )?;
        }
        if self.with_region(ctx, |r, _| {
            r.services.get(&arn).is_some_and(|s| s.service.status.as_deref() != Some("INACTIVE"))
        }) {
            return Err(invalid("Creation of service was not idempotent."));
        }
        let td = self.express_task_definition(ctx, &name, &cluster, &config)?;
        let port = config.primary_container.as_ref().and_then(|p| p.container_port).unwrap_or(DEFAULT_PORT);
        let ingress = match self.platform() {
            Some(p) => {
                p.create_express_ingress(
                    ctx,
                    &name,
                    config.network.subnets.as_deref().unwrap_or_default(),
                    config.network.security_groups.as_deref().unwrap_or_default(),
                    port,
                    &config.health_check_path,
                )
                .await?
            }
            None => None,
        };
        let load_balancers = ingress.as_ref().map(|i| {
            vec![t::LoadBalancer {
                target_group_arn: Some(i.target_group_arn.clone()),
                container_name: Some("Main".into()),
                container_port: Some(port),
                ..Default::default()
            }]
        });
        self.create_service_op(
            &behalf,
            t::CreateServiceRequest {
                cluster: Some(cluster.clone()),
                service_name: name.clone(),
                task_definition: Some(td.clone()),
                desired_count: Some(min),
                launch_type: Some("FARGATE".into()),
                network_configuration: Some(t::NetworkConfiguration {
                    awsvpc_configuration: Some(t::AwsVpcConfiguration {
                        subnets: config.network.subnets.clone().unwrap_or_default(),
                        security_groups: config.network.security_groups.clone(),
                        assign_public_ip: Some("DISABLED".into()),
                    }),
                }),
                health_check_grace_period_seconds: Some(60),
                load_balancers,
                tags: input.tags.clone(),
                enable_ecs_managed_tags: true,
                propagate_tags: Some("SERVICE".into()),
                ..Default::default()
            },
        )?;
        let endpoint = format!("https://{name}.ecs.{}.on.aws", scope.region);
        let revision = self.latest_revision(ctx, &arn);
        let now = ctx.received_at;
        let deployment =
            self.with_region(ctx, |r, _| r.services.get(&arn).and_then(|s| s.current_deployment_arn.clone()));
        let svc = t::ECSExpressGatewayService {
            cluster: Some(scope.cluster_arn(&cluster)),
            service_name: Some(name.clone()),
            service_arn: Some(arn.clone()),
            infrastructure_role_arn: Some(input.infrastructure_role_arn.clone()),
            status: Some(t::ExpressGatewayServiceStatus { status_code: Some("ACTIVE".into()), status_reason: None }),
            current_deployment: deployment,
            active_configurations: Some(vec![Self::configuration(&config, &td, revision, &endpoint, now)]),
            tags: input.tags.clone(),
            created_at: Some(now),
            updated_at: Some(now),
        };
        self.with_region(ctx, |r, _| {
            r.express_services.insert(arn.clone(), svc.clone());
            if let Some(i) = ingress {
                let managed = managed_resources(&i, &endpoint, port, &config.health_check_path, now);
                for rev in r.service_revisions.values_mut().filter(|v| v.service_arn.as_deref() == Some(arn.as_str())) {
                    rev.ecs_managed_resources = Some(managed.clone());
                }
                r.express_ingress.insert(arn.clone(), i);
            }
        });
        self.kick();
        Ok(t::CreateExpressGatewayServiceResponse { service: Some(svc) })
    }

    /// The Express service at `arn`, with its status and deployment read
    /// from the service it runs as.
    fn express(
        &self,
        ctx: &RequestContext,
        action: &str,
        arn: &str,
    ) -> Result<t::ECSExpressGatewayService, ServiceError> {
        let (svc, tags) = self.with_region(ctx, |r, _| {
            let mut svc = r.express_services.get(arn).cloned();
            if let (Some(s), Some(rec)) = (svc.as_mut(), r.services.get(arn)) {
                let code = match rec.service.status.as_deref() {
                    Some("ACTIVE") => "ACTIVE",
                    Some("DRAINING") => "DRAINING",
                    _ => "INACTIVE",
                };
                s.status = Some(t::ExpressGatewayServiceStatus { status_code: Some(code.into()), status_reason: None });
                s.current_deployment = rec.current_deployment_arn.clone();
            }
            (svc, r.tags.get(arn).cloned())
        });
        authorize(ctx, action, arn, Cond::new().extend(resource_tags(tags.as_ref())))?;
        let mut svc = svc.ok_or_else(not_found)?;
        svc.tags = tags;
        Ok(svc)
    }

    pub(crate) fn describe_express_gateway_service_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeExpressGatewayServiceRequest,
    ) -> Result<t::DescribeExpressGatewayServiceResponse, ServiceError> {
        let mut svc = self.express(ctx, "DescribeExpressGatewayService", &input.service_arn)?;
        if !input.include.as_ref().is_some_and(|i| i.iter().any(|x| x == "TAGS")) {
            svc.tags = None;
        }
        Ok(t::DescribeExpressGatewayServiceResponse { service: Some(svc) })
    }

    pub(crate) fn update_express_gateway_service_op(
        &self,
        ctx: &RequestContext,
        input: t::UpdateExpressGatewayServiceRequest,
    ) -> Result<t::UpdateExpressGatewayServiceResponse, ServiceError> {
        let svc = self.express(ctx, "UpdateExpressGatewayService", &input.service_arn)?;
        if svc.status.as_ref().and_then(|s| s.status_code.as_deref()) != Some("ACTIVE") {
            return Err(crate::generated::errors::service_not_active("Service was not ACTIVE."));
        }
        self.authorize_express_roles(ctx, None, input.execution_role_arn.as_deref(), input.task_role_arn.as_deref())?;
        let prev = svc.active_configurations.clone().unwrap_or_default().into_iter().next().unwrap_or_default();
        let name = svc.service_name.clone().unwrap_or_default();
        let cluster = crate::names::last_segment(svc.cluster.as_deref().unwrap_or("default")).to_string();
        let changes_task = input.primary_container.is_some()
            || input.cpu.is_some()
            || input.memory.is_some()
            || input.cpu_architecture.is_some()
            || input.execution_role_arn.is_some()
            || input.task_role_arn.is_some();
        if changes_task && input.task_definition_arn.is_none() {
            let scope = Scope::of(ctx);
            authorize(ctx, "RegisterTaskDefinition", &scope.arn(&format!("task-definition/{name}:*")), Cond::new())?;
        }
        let mut network =
            input.network_configuration.clone().or(prev.network_configuration.clone()).unwrap_or_default();
        network.subnets = Some(self.subnets_for(ctx, &network));
        let config = Config {
            execution_role_arn: input.execution_role_arn.clone().or(prev.execution_role_arn.clone()),
            task_role_arn: input.task_role_arn.clone().or(prev.task_role_arn.clone()),
            cpu: input.cpu.clone().or(prev.cpu.clone()).unwrap_or_else(|| DEFAULT_CPU.into()),
            memory: input.memory.clone().or(prev.memory.clone()).unwrap_or_else(|| DEFAULT_MEMORY.into()),
            cpu_architecture: input.cpu_architecture.clone().or(prev.cpu_architecture.clone()),
            health_check_path: input
                .health_check_path
                .clone()
                .or(prev.health_check_path.clone())
                .unwrap_or_else(|| DEFAULT_HEALTH_CHECK.into()),
            primary_container: input.primary_container.clone().or(prev.primary_container.clone()),
            network,
            scaling: input.scaling_target.clone().or(prev.scaling_target.clone()).unwrap_or_default(),
            task_definition_arn: input.task_definition_arn.clone().or(if changes_task {
                None
            } else {
                prev.task_definition_arn.clone()
            }),
        };
        let td = self.express_task_definition(ctx, &name, &cluster, &config)?;
        let desired = config.scaling.min_task_count.unwrap_or(1);
        self.update_service_op(
            &on_behalf(ctx),
            t::UpdateServiceRequest {
                cluster: Some(cluster.clone()),
                service: input.service_arn.clone(),
                desired_count: Some(desired),
                task_definition: Some(td.clone()),
                network_configuration: Some(t::NetworkConfiguration {
                    awsvpc_configuration: Some(t::AwsVpcConfiguration {
                        subnets: config.network.subnets.clone().unwrap_or_default(),
                        security_groups: config.network.security_groups.clone(),
                        assign_public_ip: Some("DISABLED".into()),
                    }),
                }),
                ..Default::default()
            },
        )?;
        let now = ctx.received_at;
        let endpoint = prev
            .ingress_paths
            .as_ref()
            .and_then(|p| p.first())
            .map(|p| p.endpoint.clone())
            .unwrap_or_else(|| format!("https://{name}.ecs.{}.on.aws", ctx.region));
        let revision = self.latest_revision(ctx, &input.service_arn);
        let target = Self::configuration(&config, &td, revision, &endpoint, now);
        let out = self.with_region(ctx, |r, _| {
            let deployment = r.services.get(&input.service_arn).and_then(|s| s.current_deployment_arn.clone());
            let rec = r.express_services.get_mut(&input.service_arn)?;
            rec.active_configurations = Some(vec![target.clone()]);
            rec.current_deployment = deployment;
            rec.updated_at = Some(now);
            Some(rec.clone())
        });
        let svc = out.ok_or_else(not_found)?;
        self.kick();
        Ok(t::UpdateExpressGatewayServiceResponse {
            service: Some(t::UpdatedExpressGatewayService {
                service_arn: svc.service_arn.clone(),
                cluster: svc.cluster.clone(),
                service_name: svc.service_name.clone(),
                status: svc.status.clone(),
                target_configuration: Some(target),
                created_at: svc.created_at,
                updated_at: svc.updated_at,
            }),
        })
    }

    pub(crate) async fn delete_express_gateway_service_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteExpressGatewayServiceRequest,
    ) -> Result<t::DeleteExpressGatewayServiceResponse, ServiceError> {
        let svc = self.express(ctx, "DeleteExpressGatewayService", &input.service_arn)?;
        if svc.status.as_ref().and_then(|s| s.status_code.as_deref()) == Some("INACTIVE") {
            return Err(crate::generated::errors::service_not_active("Service was not ACTIVE."));
        }
        let cluster = crate::names::last_segment(svc.cluster.as_deref().unwrap_or("default")).to_string();
        if svc.status.as_ref().and_then(|s| s.status_code.as_deref()) == Some("ACTIVE") {
            self.delete_service_op(
                &on_behalf(ctx),
                t::DeleteServiceRequest {
                    cluster: Some(cluster),
                    service: input.service_arn.clone(),
                    force: Some(true),
                },
            )?;
        }
        let ingress = self.with_region(ctx, |r, _| r.express_ingress.remove(&input.service_arn));
        if let (Some(p), Some(i)) = (self.platform(), ingress) {
            p.delete_express_ingress(ctx, &i).await;
        }
        let now = ctx.received_at;
        let svc = self.with_region(ctx, |r, _| {
            let rec = r.express_services.get_mut(&input.service_arn)?;
            rec.status =
                Some(t::ExpressGatewayServiceStatus { status_code: Some("DRAINING".into()), status_reason: None });
            rec.updated_at = Some(now);
            Some(rec.clone())
        });
        Ok(t::DeleteExpressGatewayServiceResponse { service: svc })
    }
}
