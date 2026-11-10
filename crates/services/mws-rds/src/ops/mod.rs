//! The RDS operations, by resource, and what they share: lookups, the
//! background lifecycle of databases, and events.

pub mod backtrack;
pub mod bluegreen;
pub mod catalog_ops;
pub mod cluster;
pub mod endpoint;
pub mod events;
pub mod export;
pub mod global;
pub mod groups;
pub mod instance;
pub mod limitless;
pub mod maintenance;
pub mod misc;
pub mod params;
pub mod pitr;
pub mod proxy;
pub mod reserved;
pub mod secret;
pub mod snapshot;
pub mod tags;

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::backend::DatabaseSpec;
use crate::catalog::{self, Kind};
use crate::generated::{errors, types as t};
use crate::state::{ClusterRecord, InstanceRecord, Listen, RegionState};
use crate::util::{account_of, arn, endpoint_suffix, hosted_zone_id};
use crate::{Rds, Subnet};

/// Authorize `rds:<action>` on `resource`.
pub fn authorize(
    ctx: &RequestContext,
    action: &str,
    resource: &str,
    context: ConditionContext,
) -> Result<(), ServiceError> {
    ctx.authorize(&format!("rds:{action}"), resource, context)
}

pub fn cond(pairs: &[(&str, Option<String>)]) -> ConditionContext {
    pairs.iter().filter_map(|(k, v)| v.clone().map(|v| (k.to_string(), vec![v]))).collect()
}

pub fn instance_not_found(id: &str) -> ServiceError {
    errors::db_instance_not_found_fault(format!("DBInstance {id} not found."))
}

pub fn cluster_not_found(id: &str) -> ServiceError {
    errors::db_cluster_not_found_fault(format!("DBCluster {id} not found."))
}

pub fn invalid_instance_state(id: &str, state: &str) -> ServiceError {
    errors::invalid_db_instance_state_fault(format!("Instance {id} is not in available state. Its state is {state}."))
}

pub fn invalid_cluster_state(id: &str, state: &str) -> ServiceError {
    errors::invalid_db_cluster_state_fault(format!("DbCluster {id} is not in available state. Its state is {state}."))
}

/// The AWS-style host name of an instance (`<id>.<token>.<region>.rds.amazonaws.com`).
pub fn instance_host(ctx: &RequestContext, id: &str) -> String {
    format!("{id}.{}", endpoint_suffix(ctx))
}

pub fn cluster_host(ctx: &RequestContext, id: &str, kind: &str) -> String {
    format!("{id}.{kind}-{}", endpoint_suffix(ctx))
}

impl Rds {
    /// The endpoint clients connect to: the backend's when it runs the
    /// database, the AWS-style name otherwise.
    pub(crate) fn endpoint_for(
        &self,
        ctx: &RequestContext,
        host: &str,
        port: i32,
        listen: &Option<Listen>,
    ) -> t::Endpoint {
        match listen {
            Some(l) if self.backend().runs_databases() && l.port != 0 => t::Endpoint {
                address: Some(l.host.clone()),
                port: Some(l.port as i32),
                hosted_zone_id: Some(hosted_zone_id(&ctx.region).into()),
            },
            _ => t::Endpoint {
                address: Some(host.to_string()),
                port: Some(port),
                hosted_zone_id: Some(hosted_zone_id(&ctx.region).into()),
            },
        }
    }

    /// The backend spec of a standalone instance.
    pub(crate) fn instance_spec(&self, r: &RegionState, rec: &InstanceRecord, ctx: &RequestContext) -> DatabaseSpec {
        let db = &rec.db;
        let engine = catalog::engine(db.engine.as_deref().unwrap_or_default()).unwrap_or(&catalog::ENGINES[0]);
        let mut parameters = native_parameters(
            r.parameter_groups.get(
                db.db_parameter_groups
                    .as_ref()
                    .and_then(|g| g.first())
                    .and_then(|g| g.db_parameter_group_name.as_deref())
                    .unwrap_or_default(),
            ),
            engine.kind,
        );
        if db.read_replica_source_db_instance_identifier.is_some() {
            parameters.push(read_only_parameter(engine.kind));
        }
        DatabaseSpec {
            name: rec.backend_name.clone(),
            account_id: account_of(ctx),
            region: ctx.region.clone(),
            identifier: db.db_instance_identifier.clone().unwrap_or_default(),
            engine: engine.name.to_string(),
            kind: engine.kind,
            image: rec.image.clone(),
            master_username: db.master_username.clone().unwrap_or_default(),
            master_password: rec.master_password.clone(),
            database_name: db.db_name.clone(),
            parameters,
            memory_mib: catalog::memory_mib(db.db_instance_class.as_deref().unwrap_or_default()),
        }
    }

    /// The backend spec of a cluster (its shared storage and writer).
    pub(crate) fn cluster_spec(&self, r: &RegionState, rec: &ClusterRecord, ctx: &RequestContext) -> DatabaseSpec {
        let c = &rec.cluster;
        let engine = catalog::engine(c.engine.as_deref().unwrap_or_default()).unwrap_or(&catalog::ENGINES[0]);
        let parameters = native_parameters(
            r.cluster_parameter_groups.get(c.db_cluster_parameter_group.as_deref().unwrap_or_default()),
            engine.kind,
        );
        let memory = c
            .db_cluster_members
            .iter()
            .flatten()
            .filter_map(|m| r.instances.get(m.db_instance_identifier.as_deref().unwrap_or_default()))
            .map(|i| catalog::memory_mib(i.db.db_instance_class.as_deref().unwrap_or_default()))
            .max()
            .unwrap_or(1024);
        DatabaseSpec {
            name: rec.backend_name.clone(),
            account_id: account_of(ctx),
            region: ctx.region.clone(),
            identifier: c.db_cluster_identifier.clone().unwrap_or_default(),
            engine: engine.name.to_string(),
            kind: engine.kind,
            image: rec.image.clone(),
            master_username: c.master_username.clone().unwrap_or_default(),
            master_password: rec.master_password.clone(),
            database_name: c.database_name.clone(),
            parameters,
            memory_mib: memory,
        }
    }

    /// Run backend work: inline when no database really runs (so states
    /// change at once), in the background otherwise.
    pub(crate) async fn run_task<F>(&self, task: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        if self.backend().runs_databases() {
            tokio::spawn(task);
        } else {
            task.await;
        }
    }

    /// Subnets of a subnet group's ids, through EC2 when wired.
    pub(crate) fn lookup_subnets(&self, ctx: &RequestContext, ids: &[String]) -> Vec<Subnet> {
        match self.network() {
            Some(n) => n.subnets(ctx, ids),
            None => {
                let zones = crate::util::zones(&ctx.region);
                ids.iter()
                    .enumerate()
                    .filter(|(_, id)| id.starts_with("subnet-"))
                    .map(|(i, id)| Subnet {
                        subnet_id: id.clone(),
                        vpc_id: standin_vpc(ctx),
                        availability_zone: zones[i % zones.len()].clone(),
                    })
                    .collect()
            }
        }
    }

    pub(crate) fn default_subnets(&self, ctx: &RequestContext) -> Vec<Subnet> {
        match self.network() {
            Some(n) => n.default_subnets(ctx),
            None => {
                let vpc = standin_vpc(ctx);
                crate::util::zones(&ctx.region)
                    .into_iter()
                    .enumerate()
                    .map(|(i, z)| Subnet {
                        subnet_id: format!("subnet-{}{i:x}", &crate::util::stable_token(&vpc, 16)[..16]),
                        vpc_id: vpc.clone(),
                        availability_zone: z,
                    })
                    .collect()
            }
        }
    }

    /// Check VPC security groups belong to `vpc_id`; default to the VPC's
    /// default group.
    pub(crate) fn security_groups(
        &self,
        ctx: &RequestContext,
        ids: &Option<Vec<String>>,
        vpc_id: &str,
    ) -> Result<Vec<t::VpcSecurityGroupMembership>, ServiceError> {
        let ids = match ids {
            Some(ids) if !ids.is_empty() => ids.clone(),
            _ => match self.network() {
                Some(n) => n.default_security_group(ctx, vpc_id).into_iter().collect(),
                None => vec![format!("sg-{}", &crate::util::stable_token(vpc_id, 17)[..17])],
            },
        };
        if let Some(n) = self.network() {
            for id in &ids {
                match n.security_group_vpc(ctx, id) {
                    None => {
                        return Err(crate::util::invalid_parameter(format!(
                            "Invalid security group , groupId= {id}, groupName=."
                        )))
                    }
                    Some(v) if v != vpc_id => {
                        return Err(crate::util::invalid_combination(format!(
                            "The DB instance and EC2 security group are in different VPCs. The DB instance is in {vpc_id} and the EC2 security group is in {v}"
                        )))
                    }
                    Some(_) => {}
                }
            }
        }
        Ok(ids
            .into_iter()
            .map(|id| t::VpcSecurityGroupMembership { vpc_security_group_id: Some(id), status: Some("active".into()) })
            .collect())
    }
}

/// The VPC MWS reports when EC2 is not wired in.
fn standin_vpc(ctx: &RequestContext) -> String {
    format!("vpc-{}", &crate::util::stable_token(&format!("{}/{}", account_of(ctx), ctx.region), 17)[..17])
}

/// Parameter group values the database server itself understands.
fn native_parameters(group: Option<&crate::state::ParamGroup>, kind: Kind) -> Vec<(String, String)> {
    let Some(g) = group else { return Vec::new() };
    g.values
        .iter()
        .filter(|(name, value)| {
            catalog::params(kind).iter().any(|p| p.name == *name && p.native) && !value.contains('{')
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

fn read_only_parameter(kind: Kind) -> (String, String) {
    match kind {
        Kind::Postgres => ("default_transaction_read_only".into(), "on".into()),
        Kind::Mysql | Kind::Mariadb => ("read_only".into(), "ON".into()),
    }
}

/// ARN of a DB instance.
pub fn db_arn(ctx: &RequestContext, id: &str) -> String {
    arn(ctx, "db", id)
}

pub fn cluster_arn(ctx: &RequestContext, id: &str) -> String {
    arn(ctx, "cluster", id)
}

/// Check a master password the way RDS does for `engine`.
pub fn check_password(engine: &catalog::Engine, password: &str) -> Result<(), ServiceError> {
    let max = match engine.kind {
        Kind::Postgres => 128,
        Kind::Mysql | Kind::Mariadb => 41,
    };
    if password.chars().count() < 8 {
        return Err(crate::util::invalid_parameter(
            "The parameter MasterUserPassword is not a valid password because it is shorter than 8 characters.",
        ));
    }
    if password.chars().count() > max {
        return Err(crate::util::invalid_parameter(format!(
            "The parameter MasterUserPassword is not a valid password because it is longer than {max} characters."
        )));
    }
    if password.chars().any(|c| !(' '..='~').contains(&c) || matches!(c, '/' | '@' | '"' | ' ')) {
        return Err(crate::util::invalid_parameter(
            "The parameter MasterUserPassword is not a valid password. Only printable ASCII characters besides '/', '@', '\"', ' ' may be used.",
        ));
    }
    Ok(())
}

/// Check a master user name.
pub fn check_username(engine: &catalog::Engine, name: &str) -> Result<(), ServiceError> {
    let max = match engine.kind {
        Kind::Postgres => 63,
        Kind::Mysql | Kind::Mariadb => 32,
    };
    let ok = !name.is_empty()
        && name.len() <= max
        && name.starts_with(|c: char| c.is_ascii_alphabetic())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !ok {
        return Err(crate::util::invalid_parameter(format!(
            "The parameter MasterUsername is not a valid identifier. It must begin with a letter, contain only alphanumeric characters or underscores, and be at most {max} characters long."
        )));
    }
    if name.eq_ignore_ascii_case("rdsadmin") {
        return Err(crate::util::invalid_parameter(
            "MasterUsername rdsadmin cannot be used as it is a reserved word used by the engine",
        ));
    }
    Ok(())
}

/// Check a database name for `engine`.
pub fn check_db_name(engine: &catalog::Engine, name: &str) -> Result<(), ServiceError> {
    let max = match engine.kind {
        Kind::Postgres => 63,
        Kind::Mysql | Kind::Mariadb => 64,
    };
    let ok = !name.is_empty()
        && name.len() <= max
        && name.starts_with(|c: char| c.is_ascii_alphabetic())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if ok {
        Ok(())
    } else {
        Err(crate::util::invalid_parameter(format!(
            "The parameter DBName is not a valid identifier. It must begin with a letter, contain only alphanumeric characters or underscores, and be at most {max} characters long."
        )))
    }
}

/// A random password RDS generates (managed master passwords).
pub fn generate_password() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%^&*()_+-=[]{}<>?:;.,~|";
    let mut rng = rand::thread_rng();
    (0..28).map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char).collect()
}
