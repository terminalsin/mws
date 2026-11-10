//! RDS Proxy: proxies, their default target group and targets, and proxy
//! endpoints. With a backend that runs databases, each endpoint really
//! listens and passes connections to the target (see [`crate::forward`]).

use std::sync::Arc;

use mws_core::{ConditionContext, RequestContext, ServiceError};

use super::{authorize, cluster_not_found};
use crate::catalog::{self, Kind};
use crate::generated::{errors, types as t};
use crate::state::{ProxyRecord, State, Tagged};
use crate::util::{
    account_of, arn, endpoint_suffix, identifier, invalid_parameter, paginate, request_tag_context,
    resource_tag_context, tags_from, Filters,
};
use crate::Rds;

const MAX_PROXIES: usize = 20;
const MAX_ENDPOINTS: usize = 20;

fn not_found(name: &str) -> ServiceError {
    errors::db_proxy_not_found_fault(format!("DBProxy {name} not found."))
}

fn endpoint_not_found(name: &str) -> ServiceError {
    errors::db_proxy_endpoint_not_found_fault(format!("DBProxyEndpoint {name} not found."))
}

fn hex_id(seed: &str) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(seed.as_bytes());
    d.iter().take(9).map(|b| format!("{b:02x}")).collect::<String>()[..17].to_string()
}

fn proxy_name(param: &str, name: &str) -> Result<String, ServiceError> {
    identifier(param, name, 63)
}

fn engine_family(kind: Kind) -> &'static str {
    match kind {
        Kind::Postgres => "POSTGRESQL",
        Kind::Mysql | Kind::Mariadb => "MYSQL",
    }
}

fn default_port(family: &str) -> u16 {
    match family {
        "POSTGRESQL" => 5432,
        "SQLSERVER" => 1433,
        _ => 3306,
    }
}

/// The connection pool settings with RDS's defaults filled in.
fn pool_info(
    c: Option<&t::ConnectionPoolConfiguration>,
    current: Option<&t::ConnectionPoolConfigurationInfo>,
) -> Result<t::ConnectionPoolConfigurationInfo, ServiceError> {
    let mut info = current.cloned().unwrap_or(t::ConnectionPoolConfigurationInfo {
        max_connections_percent: Some(100),
        max_idle_connections_percent: Some(50),
        connection_borrow_timeout: Some(120),
        session_pinning_filters: Some(Vec::new()),
        init_query: Some(String::new()),
    });
    if let Some(c) = c {
        if let Some(m) = c.max_connections_percent {
            if !(1..=100).contains(&m) {
                return Err(invalid_parameter("MaxConnectionsPercent must be between 1 and 100."));
            }
            info.max_connections_percent = Some(m);
        }
        if let Some(m) = c.max_idle_connections_percent {
            if !(0..=100).contains(&m) {
                return Err(invalid_parameter("MaxIdleConnectionsPercent must be between 0 and 100."));
            }
            info.max_idle_connections_percent = Some(m);
        }
        if let Some(b) = c.connection_borrow_timeout {
            if !(0..=3600).contains(&b) {
                return Err(invalid_parameter("ConnectionBorrowTimeout must be between 0 and 3600."));
            }
            info.connection_borrow_timeout = Some(b);
        }
        if let Some(f) = &c.session_pinning_filters {
            for x in f {
                if x != "EXCLUDE_VARIABLE_SETS" {
                    return Err(invalid_parameter(format!("Invalid session pinning filter: {x}")));
                }
            }
            info.session_pinning_filters = Some(f.clone());
        }
        if let Some(q) = &c.init_query {
            info.init_query = Some(q.clone());
        }
    }
    if info.max_idle_connections_percent > info.max_connections_percent {
        return Err(invalid_parameter("MaxIdleConnectionsPercent can't be greater than MaxConnectionsPercent."));
    }
    Ok(info)
}

impl Rds {
    fn proxy(&self, ctx: &RequestContext, name: &str) -> Result<ProxyRecord, ServiceError> {
        let name = name.to_ascii_lowercase();
        self.with_region(ctx, |r| r.proxies.get(&name).cloned()).ok_or_else(|| not_found(&name))
    }

    /// Check `Auth` entries: secrets that exist, valid schemes.
    fn proxy_auth(
        &self,
        family: &str,
        auth: &Option<Vec<t::UserAuthConfig>>,
        default_scheme: &str,
    ) -> Result<Vec<t::UserAuthConfigInfo>, ServiceError> {
        let auth = auth.clone().unwrap_or_default();
        if auth.is_empty() && default_scheme != "IAM_AUTH" {
            return Err(invalid_parameter(
                "The Auth parameter must contain at least one item when DefaultAuthScheme is NONE.",
            ));
        }
        let mut out = Vec::new();
        for a in auth {
            let secret = a.secret_arn.clone().unwrap_or_default();
            if secret.is_empty() {
                return Err(invalid_parameter("SecretArn must be specified for each Auth item."));
            }
            if !self.secrets().secret_exists(&secret) {
                return Err(invalid_parameter(format!("Secret {secret} doesn't exist or isn't accessible.")));
            }
            let iam = a.iam_auth.clone().unwrap_or_else(|| "DISABLED".into());
            if !matches!(iam.as_str(), "DISABLED" | "REQUIRED" | "ENABLED") {
                return Err(invalid_parameter(format!("Invalid IAMAuth value: {iam}")));
            }
            let client = a.client_password_auth_type.clone().unwrap_or_else(|| match family {
                "POSTGRESQL" => "POSTGRES_SCRAM_SHA_256".into(),
                "SQLSERVER" => "SQL_SERVER_AUTHENTICATION".into(),
                _ => "MYSQL_NATIVE_PASSWORD".into(),
            });
            let ok = match family {
                "POSTGRESQL" => client.starts_with("POSTGRES_"),
                "SQLSERVER" => client == "SQL_SERVER_AUTHENTICATION",
                _ => client.starts_with("MYSQL_"),
            };
            if !ok {
                return Err(invalid_parameter(format!(
                    "ClientPasswordAuthType {client} isn't valid for engine family {family}."
                )));
            }
            out.push(t::UserAuthConfigInfo {
                description: a.description.clone(),
                user_name: a.user_name.clone(),
                auth_scheme: Some(a.auth_scheme.clone().unwrap_or_else(|| "SECRETS".into())),
                secret_arn: Some(secret),
                iam_auth: Some(iam),
                client_password_auth_type: Some(client),
            });
        }
        Ok(out)
    }

    /// Subnets of a proxy (or proxy endpoint): at least two Availability
    /// Zones of one VPC. Returns the VPC.
    fn proxy_subnets(&self, ctx: &RequestContext, ids: &[String]) -> Result<String, ServiceError> {
        let found = self.lookup_subnets(ctx, ids);
        for id in ids {
            if !found.iter().any(|s| &s.subnet_id == id) {
                return Err(invalid_parameter(format!("The subnet {id} doesn't exist.")));
            }
        }
        let vpcs: std::collections::BTreeSet<&str> = found.iter().map(|s| s.vpc_id.as_str()).collect();
        if vpcs.len() != 1 {
            return Err(invalid_parameter("The subnets must all be in the same VPC."));
        }
        let zones: std::collections::BTreeSet<&str> = found.iter().map(|s| s.availability_zone.as_str()).collect();
        if zones.len() < 2 {
            return Err(invalid_parameter("The subnets must cover at least two Availability Zones in the same VPC."));
        }
        let vpc = vpcs.into_iter().next().unwrap_or_default().to_string();
        Ok(vpc)
    }

    /// Where a proxy sends connections now: its target's endpoint.
    pub(crate) fn proxy_target(&self, account: &str, region: &str, proxy: &str) -> Option<(String, u16)> {
        let st = self.lock();
        let r = st.regions.get(&State::key(account, region))?;
        let p = r.proxies.get(proxy)?;
        if p.proxy.status.as_deref() != Some("available") {
            return None;
        }
        let listen = match (p.clusters.first(), p.instances.first()) {
            (Some(c), _) => r.clusters.get(c)?.listen.clone()?,
            (None, Some(i)) => r.instances.get(i)?.listen.clone()?,
            _ => return None,
        };
        Some((listen.host, listen.port))
    }

    /// Start (or find) the listener of a proxy endpoint and return the
    /// endpoint address clients use.
    async fn proxy_listen(
        &self,
        ctx: &RequestContext,
        proxy: &str,
        key: &str,
        aws_host: String,
        family: &str,
    ) -> String {
        if !self.backend().runs_databases() {
            return aws_host;
        }
        let weak = Arc::downgrade(&self.inner);
        let (account, region, name) = (account_of(ctx), ctx.region.clone(), proxy.to_string());
        let resolve: crate::forward::Resolve = Arc::new(move || {
            let inner = weak.upgrade()?;
            Rds { inner }.proxy_target(&account, &region, &name)
        });
        match self.inner.forwarders.start(key, default_port(family), resolve).await {
            Some((addr, true)) => addr.ip().to_string(),
            _ => aws_host,
        }
    }

    /// Restart listeners after a restart of MWS (state loaded from disk).
    pub(crate) async fn ensure_proxy_listeners(&self, ctx: &RequestContext) {
        if !self.backend().runs_databases() {
            return;
        }
        let running = self.inner.forwarders.addresses();
        let missing: Vec<(String, String, String, String)> = self.with_region(ctx, |r| {
            let mut v: Vec<(String, String, String, String)> = r
                .proxies
                .values()
                .filter(|p| !running.contains_key(p.proxy.db_proxy_arn.as_deref().unwrap_or_default()))
                .map(|p| {
                    (
                        p.proxy.db_proxy_name.clone().unwrap_or_default(),
                        p.proxy.db_proxy_arn.clone().unwrap_or_default(),
                        String::new(),
                        p.proxy.engine_family.clone().unwrap_or_default(),
                    )
                })
                .collect();
            for e in r.proxy_endpoints.values() {
                let key = e.item.db_proxy_endpoint_arn.clone().unwrap_or_default();
                if !running.contains_key(&key) {
                    let p = e.item.db_proxy_name.clone().unwrap_or_default();
                    let family = r.proxies.get(&p).and_then(|x| x.proxy.engine_family.clone()).unwrap_or_default();
                    v.push((p, key, e.item.db_proxy_endpoint_name.clone().unwrap_or_default(), family));
                }
            }
            v
        });
        for (proxy, key, endpoint, family) in missing {
            let host = self.proxy_listen(ctx, &proxy, &key, String::new(), &family).await;
            if host.is_empty() {
                continue;
            }
            self.with_region(ctx, |r| {
                if endpoint.is_empty() {
                    if let Some(p) = r.proxies.get_mut(&proxy) {
                        p.proxy.endpoint = Some(host);
                    }
                } else if let Some(e) = r.proxy_endpoints.get_mut(&endpoint) {
                    e.item.endpoint = Some(host);
                }
            });
        }
    }

    /// Listener addresses for `GET /_aws/rds/proxy-endpoints`.
    pub(crate) fn proxy_listeners(&self) -> serde_json::Value {
        let addrs = self.inner.forwarders.addresses();
        serde_json::Value::Array(
            addrs
                .into_iter()
                .map(|(arn, a)| serde_json::json!({"arn": arn, "host": a.ip().to_string(), "port": a.port()}))
                .collect(),
        )
    }

    pub(crate) async fn create_db_proxy_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateDBProxyRequest,
    ) -> Result<t::CreateDBProxyResponse, ServiceError> {
        let name = proxy_name("DBProxyName", &input.db_proxy_name)?;
        let id =
            format!("prx-{}", hex_id(&format!("{}/{}/{name}/{}", account_of(ctx), ctx.region, uuid::Uuid::new_v4())));
        let parn = arn(ctx, "db-proxy", &id);
        let tags = tags_from(&input.tags)?;
        authorize(ctx, "CreateDBProxy", &parn, request_tag_context(&tags))?;
        ctx.authorize("iam:PassRole", &input.role_arn, ConditionContext::new())?;
        let family = input.engine_family.to_ascii_uppercase();
        if !matches!(family.as_str(), "MYSQL" | "POSTGRESQL" | "SQLSERVER") {
            return Err(invalid_parameter(format!("Invalid EngineFamily: {}", input.engine_family)));
        }
        let scheme = input.default_auth_scheme.clone().unwrap_or_else(|| "NONE".into());
        if !matches!(scheme.as_str(), "NONE" | "IAM_AUTH") {
            return Err(invalid_parameter(format!("Invalid DefaultAuthScheme: {scheme}")));
        }
        let auth = self.proxy_auth(&family, &input.auth, &scheme)?;
        if let Some(t) = input.idle_client_timeout {
            if !(1..=28_800).contains(&t) {
                return Err(invalid_parameter("IdleClientTimeout must be between 1 and 28800 seconds."));
            }
        }
        let vpc = self.proxy_subnets(ctx, &input.vpc_subnet_ids)?;
        let sgs: Vec<String> = self
            .security_groups(ctx, &input.vpc_security_group_ids, &vpc)?
            .into_iter()
            .filter_map(|g| g.vpc_security_group_id)
            .collect();
        let now = ctx.received_at;
        let host = format!("{name}.proxy-{}", endpoint_suffix(ctx));
        let proxy = t::DBProxy {
            db_proxy_name: Some(name.clone()),
            db_proxy_arn: Some(parn.clone()),
            status: Some("creating".into()),
            engine_family: Some(family.clone()),
            vpc_id: Some(vpc),
            vpc_security_group_ids: Some(sgs),
            vpc_subnet_ids: Some(input.vpc_subnet_ids.clone()),
            default_auth_scheme: Some(scheme),
            auth: Some(auth),
            role_arn: Some(input.role_arn.clone()),
            endpoint: Some(host.clone()),
            require_tls: Some(input.require_tls.unwrap_or(false)),
            idle_client_timeout: Some(input.idle_client_timeout.unwrap_or(1800)),
            debug_logging: Some(input.debug_logging.unwrap_or(false)),
            created_date: Some(now),
            updated_date: Some(now),
            endpoint_network_type: Some(input.endpoint_network_type.clone().unwrap_or_else(|| "IPV4".into())),
            target_connection_network_type: Some(
                input.target_connection_network_type.clone().unwrap_or_else(|| "IPV4".into()),
            ),
        };
        let group = t::DBProxyTargetGroup {
            db_proxy_name: Some(name.clone()),
            target_group_name: Some("default".into()),
            target_group_arn: Some(arn(ctx, "target-group", &format!("prx-tg-{}", hex_id(&parn)))),
            is_default: Some(true),
            status: Some("available".into()),
            connection_pool_config: Some(pool_info(None, None)?),
            created_date: Some(now),
            updated_date: Some(now),
        };
        self.with_region(ctx, |r| {
            if r.proxies.contains_key(&name) {
                return Err(errors::db_proxy_already_exists_fault(format!(
                    "Cannot create the DBProxy because a DBProxy with name {name} already exists."
                )));
            }
            if r.proxies.len() >= MAX_PROXIES {
                return Err(errors::db_proxy_quota_exceeded_fault("Cannot create more than 20 DB proxies."));
            }
            r.proxies.insert(
                name.clone(),
                ProxyRecord {
                    proxy: proxy.clone(),
                    tags,
                    target_group: group,
                    instances: Vec::new(),
                    clusters: Vec::new(),
                },
            );
            Ok(())
        })?;
        let view = proxy.clone();
        let this = self.clone();
        let ctx2 = ctx.clone();
        self.run_task(async move {
            let address = this.proxy_listen(&ctx2, &name, &parn, host, &family).await;
            this.with_region(&ctx2, |r| {
                if let Some(p) = r.proxies.get_mut(&name) {
                    p.proxy.status = Some("available".into());
                    p.proxy.endpoint = Some(address);
                }
            });
        })
        .await;
        Ok(t::CreateDBProxyResponse { db_proxy: Some(view) })
    }

    pub(crate) fn describe_db_proxies_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBProxiesRequest,
    ) -> Result<t::DescribeDBProxiesResponse, ServiceError> {
        Filters::new(&input.filters, &[])?;
        authorize(ctx, "DescribeDBProxies", &arn(ctx, "db-proxy", "*"), ConditionContext::new())?;
        let all: Vec<t::DBProxy> = match &input.db_proxy_name {
            Some(n) => vec![self.proxy(ctx, n)?.proxy],
            None => self.with_region(ctx, |r| r.proxies.values().map(|p| p.proxy.clone()).collect()),
        };
        let (page, marker) = paginate(all, &input.marker, input.max_records)?;
        Ok(t::DescribeDBProxiesResponse { db_proxies: Some(page), marker })
    }

    pub(crate) fn modify_db_proxy_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyDBProxyRequest,
    ) -> Result<t::ModifyDBProxyResponse, ServiceError> {
        let name = input.db_proxy_name.to_ascii_lowercase();
        let rec = self.proxy(ctx, &name)?;
        let parn = rec.proxy.db_proxy_arn.clone().unwrap_or_default();
        authorize(ctx, "ModifyDBProxy", &parn, resource_tag_context("db-proxy", &Some(rec.tags.clone())))?;
        if rec.proxy.status.as_deref() != Some("available") {
            return Err(errors::invalid_db_proxy_state_fault(format!("DBProxy {name} is not in available state.")));
        }
        let family = rec.proxy.engine_family.clone().unwrap_or_default();
        let scheme = input.default_auth_scheme.clone().or(rec.proxy.default_auth_scheme.clone()).unwrap_or_default();
        let auth = match &input.auth {
            Some(_) => Some(self.proxy_auth(&family, &input.auth, &scheme)?),
            None => None,
        };
        if let Some(r) = &input.role_arn {
            ctx.authorize("iam:PassRole", r, ConditionContext::new())?;
        }
        let new_name = match &input.new_db_proxy_name {
            Some(n) => Some(proxy_name("NewDBProxyName", n)?),
            None => None,
        };
        let sgs = match &input.security_groups {
            Some(g) => Some(
                self.security_groups(ctx, &Some(g.clone()), rec.proxy.vpc_id.as_deref().unwrap_or_default())?
                    .into_iter()
                    .filter_map(|g| g.vpc_security_group_id)
                    .collect::<Vec<_>>(),
            ),
            None => None,
        };
        let now = ctx.received_at;
        let proxy = self.with_region(ctx, |r| {
            if let Some(n) = &new_name {
                if n != &name && r.proxies.contains_key(n) {
                    return Err(errors::db_proxy_already_exists_fault(format!(
                        "Cannot rename the DBProxy because a DBProxy with name {n} already exists."
                    )));
                }
            }
            let mut p = r.proxies.remove(&name).expect("looked up above");
            if let Some(a) = auth {
                p.proxy.auth = Some(a);
            }
            if let Some(s) = &input.default_auth_scheme {
                p.proxy.default_auth_scheme = Some(s.clone());
            }
            if let Some(v) = input.require_tls {
                p.proxy.require_tls = Some(v);
            }
            if let Some(v) = input.idle_client_timeout {
                p.proxy.idle_client_timeout = Some(v);
            }
            if let Some(v) = input.debug_logging {
                p.proxy.debug_logging = Some(v);
            }
            if let Some(v) = &input.role_arn {
                p.proxy.role_arn = Some(v.clone());
            }
            if let Some(g) = sgs {
                p.proxy.vpc_security_group_ids = Some(g);
            }
            p.proxy.updated_date = Some(now);
            let key = new_name.clone().unwrap_or(name.clone());
            if let Some(n) = &new_name {
                // Renaming changes the default endpoint's name too.
                if p.proxy.endpoint.as_deref().is_some_and(|e| e.starts_with(&format!("{name}.proxy-"))) {
                    p.proxy.endpoint = Some(format!("{n}.proxy-{}", endpoint_suffix(ctx)));
                }
                p.proxy.db_proxy_name = Some(n.clone());
                p.target_group.db_proxy_name = Some(n.clone());
                for e in r.proxy_endpoints.values_mut() {
                    if e.item.db_proxy_name.as_deref() == Some(name.as_str()) {
                        e.item.db_proxy_name = Some(n.clone());
                    }
                }
            }
            let view = p.proxy.clone();
            r.proxies.insert(key, p);
            Ok(view)
        })?;
        if let Some(n) = &new_name {
            // The listener resolves the target by the proxy's name.
            self.inner.forwarders.stop(&parn);
            let ends: Vec<String> = self.with_region(ctx, |r| {
                r.proxy_endpoints
                    .values()
                    .filter(|e| e.item.db_proxy_name.as_deref() == Some(n.as_str()))
                    .filter_map(|e| e.item.db_proxy_endpoint_arn.clone())
                    .collect()
            });
            for e in ends {
                self.inner.forwarders.stop(&e);
            }
        }
        Ok(t::ModifyDBProxyResponse { db_proxy: Some(proxy) })
    }

    pub(crate) fn delete_db_proxy_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteDBProxyRequest,
    ) -> Result<t::DeleteDBProxyResponse, ServiceError> {
        let name = input.db_proxy_name.to_ascii_lowercase();
        let rec = self.proxy(ctx, &name)?;
        let parn = rec.proxy.db_proxy_arn.clone().unwrap_or_default();
        authorize(ctx, "DeleteDBProxy", &parn, resource_tag_context("db-proxy", &Some(rec.tags.clone())))?;
        let ends: Vec<String> = self.with_region(ctx, |r| {
            r.proxies.remove(&name);
            let ends = r
                .proxy_endpoints
                .values()
                .filter(|e| e.item.db_proxy_name.as_deref() == Some(name.as_str()))
                .filter_map(|e| e.item.db_proxy_endpoint_arn.clone())
                .collect();
            r.proxy_endpoints.retain(|_, e| e.item.db_proxy_name.as_deref() != Some(name.as_str()));
            ends
        });
        self.inner.forwarders.stop(&parn);
        for e in ends {
            self.inner.forwarders.stop(&e);
        }
        let mut p = rec.proxy;
        p.status = Some("deleting".into());
        Ok(t::DeleteDBProxyResponse { db_proxy: Some(p) })
    }

    fn target_group(&self, rec: &ProxyRecord, name: &Option<String>) -> Result<(), ServiceError> {
        match name.as_deref() {
            None | Some("default") => Ok(()),
            Some(n) => {
                Err(errors::db_proxy_target_group_not_found_fault(format!("DBProxy target group {n} not found.")))
            }
        }
        .map(|_| {
            let _ = rec;
        })
    }

    pub(crate) fn register_db_proxy_targets_op(
        &self,
        ctx: &RequestContext,
        input: t::RegisterDBProxyTargetsRequest,
    ) -> Result<t::RegisterDBProxyTargetsResponse, ServiceError> {
        let name = input.db_proxy_name.to_ascii_lowercase();
        let rec = self.proxy(ctx, &name)?;
        authorize(
            ctx,
            "RegisterDBProxyTargets",
            rec.proxy.db_proxy_arn.as_deref().unwrap_or_default(),
            resource_tag_context("db-proxy", &Some(rec.tags.clone())),
        )?;
        self.target_group(&rec, &input.target_group_name)?;
        let instances: Vec<String> =
            input.db_instance_identifiers.iter().flatten().map(|i| i.to_ascii_lowercase()).collect();
        let clusters: Vec<String> =
            input.db_cluster_identifiers.iter().flatten().map(|i| i.to_ascii_lowercase()).collect();
        if instances.is_empty() && clusters.is_empty() {
            return Err(invalid_parameter("Specify DBInstanceIdentifiers or DBClusterIdentifiers."));
        }
        if instances.len() + clusters.len() > 1 || !rec.instances.is_empty() || !rec.clusters.is_empty() {
            if rec.instances.iter().any(|i| instances.contains(i)) || rec.clusters.iter().any(|c| clusters.contains(c))
            {
                return Err(errors::db_proxy_target_already_registered_fault(
                    "The specified target is already registered with the target group.",
                ));
            }
            return Err(invalid_parameter("A DB proxy target group can contain only one DB instance or DB cluster."));
        }
        let family = rec.proxy.engine_family.clone().unwrap_or_default();
        let engine_ok = |engine: &str| catalog::engine(engine).is_some_and(|e| engine_family(e.kind) == family);
        for i in &instances {
            let db = self.instance(ctx, i)?.db;
            if db.db_cluster_identifier.is_some() {
                return Err(invalid_parameter(format!(
                    "DB instance {i} is a member of a DB cluster. Register the cluster instead."
                )));
            }
            if !engine_ok(db.engine.as_deref().unwrap_or_default()) {
                return Err(invalid_parameter(format!(
                    "The engine of DB instance {i} isn't compatible with the proxy's engine family {family}."
                )));
            }
            if !super::maintenance::operational(db.db_instance_status.as_deref().unwrap_or_default()) {
                return Err(super::invalid_instance_state(i, db.db_instance_status.as_deref().unwrap_or_default()));
            }
        }
        for c in &clusters {
            let cl = self.cluster(ctx, c).map_err(|_| cluster_not_found(c))?.cluster;
            if !engine_ok(cl.engine.as_deref().unwrap_or_default()) {
                return Err(invalid_parameter(format!(
                    "The engine of DB cluster {c} isn't compatible with the proxy's engine family {family}."
                )));
            }
        }
        self.with_region(ctx, |r| {
            if let Some(p) = r.proxies.get_mut(&name) {
                p.instances.extend(instances.iter().cloned());
                p.clusters.extend(clusters.iter().cloned());
            }
        });
        let rec = self.proxy(ctx, &name)?;
        Ok(t::RegisterDBProxyTargetsResponse { db_proxy_targets: Some(self.proxy_targets(ctx, &rec)) })
    }

    /// The targets a proxy routes to, as `DescribeDBProxyTargets` shows
    /// them: a cluster appears as itself and as each of its instances.
    fn proxy_targets(&self, ctx: &RequestContext, rec: &ProxyRecord) -> Vec<t::DBProxyTarget> {
        let health = |status: Option<&str>| t::TargetHealth {
            state: Some(if status == Some("available") { "AVAILABLE" } else { "UNAVAILABLE" }.into()),
            reason: (status != Some("available")).then(|| "UNREACHABLE".into()),
            description: (status != Some("available")).then(|| "The DB instance isn't available.".into()),
        };
        let mut out = Vec::new();
        for c in &rec.clusters {
            let Ok(cl) = self.cluster(ctx, c) else { continue };
            let view = self.cluster_view(ctx, &cl);
            out.push(t::DBProxyTarget {
                target_arn: view.db_cluster_arn.clone(),
                tracked_cluster_id: Some(c.clone()),
                rds_resource_id: Some(c.clone()),
                port: view.port,
                r#type: Some("TRACKED_CLUSTER".into()),
                ..Default::default()
            });
            for m in view.db_cluster_members.iter().flatten() {
                let id = m.db_instance_identifier.clone().unwrap_or_default();
                let Ok(i) = self.instance(ctx, &id) else { continue };
                let v = self.instance_view(ctx, &i);
                out.push(t::DBProxyTarget {
                    target_arn: v.db_instance_arn.clone(),
                    endpoint: v.endpoint.as_ref().and_then(|e| e.address.clone()),
                    tracked_cluster_id: Some(c.clone()),
                    rds_resource_id: Some(id.clone()),
                    port: v.endpoint.as_ref().and_then(|e| e.port),
                    r#type: Some("RDS_INSTANCE".into()),
                    role: Some(if m.is_cluster_writer == Some(true) { "READ_WRITE" } else { "READ_ONLY" }.into()),
                    target_health: Some(health(v.db_instance_status.as_deref())),
                });
            }
        }
        for id in &rec.instances {
            let Ok(i) = self.instance(ctx, id) else { continue };
            let v = self.instance_view(ctx, &i);
            out.push(t::DBProxyTarget {
                target_arn: v.db_instance_arn.clone(),
                endpoint: v.endpoint.as_ref().and_then(|e| e.address.clone()),
                tracked_cluster_id: None,
                rds_resource_id: Some(id.clone()),
                port: v.endpoint.as_ref().and_then(|e| e.port),
                r#type: Some("RDS_INSTANCE".into()),
                role: Some("READ_WRITE".into()),
                target_health: Some(health(v.db_instance_status.as_deref())),
            });
        }
        out
    }

    pub(crate) fn deregister_db_proxy_targets_op(
        &self,
        ctx: &RequestContext,
        input: t::DeregisterDBProxyTargetsRequest,
    ) -> Result<t::DeregisterDBProxyTargetsResponse, ServiceError> {
        let name = input.db_proxy_name.to_ascii_lowercase();
        let rec = self.proxy(ctx, &name)?;
        authorize(
            ctx,
            "DeregisterDBProxyTargets",
            rec.proxy.db_proxy_arn.as_deref().unwrap_or_default(),
            resource_tag_context("db-proxy", &Some(rec.tags.clone())),
        )?;
        self.target_group(&rec, &input.target_group_name)?;
        let instances: Vec<String> =
            input.db_instance_identifiers.iter().flatten().map(|i| i.to_ascii_lowercase()).collect();
        let clusters: Vec<String> =
            input.db_cluster_identifiers.iter().flatten().map(|i| i.to_ascii_lowercase()).collect();
        for i in &instances {
            if !rec.instances.contains(i) {
                return Err(errors::db_proxy_target_not_found_fault(format!(
                    "DB instance {i} isn't registered with the target group."
                )));
            }
        }
        for c in &clusters {
            if !rec.clusters.contains(c) {
                return Err(errors::db_proxy_target_not_found_fault(format!(
                    "DB cluster {c} isn't registered with the target group."
                )));
            }
        }
        self.with_region(ctx, |r| {
            if let Some(p) = r.proxies.get_mut(&name) {
                p.instances.retain(|i| !instances.contains(i));
                p.clusters.retain(|c| !clusters.contains(c));
            }
        });
        Ok(t::DeregisterDBProxyTargetsResponse {})
    }

    pub(crate) fn describe_db_proxy_targets_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBProxyTargetsRequest,
    ) -> Result<t::DescribeDBProxyTargetsResponse, ServiceError> {
        Filters::new(&input.filters, &[])?;
        let rec = self.proxy(ctx, &input.db_proxy_name)?;
        authorize(
            ctx,
            "DescribeDBProxyTargets",
            rec.proxy.db_proxy_arn.as_deref().unwrap_or_default(),
            ConditionContext::new(),
        )?;
        self.target_group(&rec, &input.target_group_name)?;
        let (page, marker) = paginate(self.proxy_targets(ctx, &rec), &input.marker, input.max_records)?;
        Ok(t::DescribeDBProxyTargetsResponse { targets: Some(page), marker })
    }

    pub(crate) fn describe_db_proxy_target_groups_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBProxyTargetGroupsRequest,
    ) -> Result<t::DescribeDBProxyTargetGroupsResponse, ServiceError> {
        Filters::new(&input.filters, &[])?;
        let rec = self.proxy(ctx, &input.db_proxy_name)?;
        authorize(
            ctx,
            "DescribeDBProxyTargetGroups",
            rec.proxy.db_proxy_arn.as_deref().unwrap_or_default(),
            ConditionContext::new(),
        )?;
        self.target_group(&rec, &input.target_group_name)?;
        let (page, marker) = paginate(vec![rec.target_group], &input.marker, input.max_records)?;
        Ok(t::DescribeDBProxyTargetGroupsResponse { target_groups: Some(page), marker })
    }

    pub(crate) fn modify_db_proxy_target_group_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyDBProxyTargetGroupRequest,
    ) -> Result<t::ModifyDBProxyTargetGroupResponse, ServiceError> {
        let name = input.db_proxy_name.to_ascii_lowercase();
        let rec = self.proxy(ctx, &name)?;
        authorize(
            ctx,
            "ModifyDBProxyTargetGroup",
            rec.target_group.target_group_arn.as_deref().unwrap_or_default(),
            resource_tag_context("db-proxy", &Some(rec.tags.clone())),
        )?;
        self.target_group(&rec, &Some(input.target_group_name.clone()))?;
        if input.new_name.as_deref().is_some_and(|n| n != "default") {
            return Err(invalid_parameter("The default target group can't be renamed."));
        }
        let info = pool_info(input.connection_pool_config.as_ref(), rec.target_group.connection_pool_config.as_ref())?;
        let now = ctx.received_at;
        let group = self.with_region(ctx, |r| {
            let p = r.proxies.get_mut(&name).expect("looked up above");
            p.target_group.connection_pool_config = Some(info);
            p.target_group.updated_date = Some(now);
            p.target_group.clone()
        });
        Ok(t::ModifyDBProxyTargetGroupResponse { db_proxy_target_group: Some(group) })
    }

    pub(crate) async fn create_db_proxy_endpoint_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateDBProxyEndpointRequest,
    ) -> Result<t::CreateDBProxyEndpointResponse, ServiceError> {
        let name = identifier("DBProxyEndpointName", &input.db_proxy_endpoint_name, 63)?;
        let proxy = input.db_proxy_name.to_ascii_lowercase();
        let rec = self.proxy(ctx, &proxy)?;
        let earn = arn(
            ctx,
            "db-proxy-endpoint",
            &format!("prx-endpoint-{}", hex_id(&format!("{}/{name}", uuid::Uuid::new_v4()))),
        );
        let tags = tags_from(&input.tags)?;
        authorize(ctx, "CreateDBProxyEndpoint", &earn, request_tag_context(&tags))?;
        if rec.proxy.status.as_deref() != Some("available") {
            return Err(errors::invalid_db_proxy_state_fault(format!("DBProxy {proxy} is not in available state.")));
        }
        let role = input.target_role.clone().unwrap_or_else(|| "READ_WRITE".into());
        if !matches!(role.as_str(), "READ_WRITE" | "READ_ONLY") {
            return Err(invalid_parameter(format!("Invalid TargetRole: {role}")));
        }
        let vpc = self.proxy_subnets(ctx, &input.vpc_subnet_ids)?;
        let sgs: Vec<String> = self
            .security_groups(ctx, &input.vpc_security_group_ids, &vpc)?
            .into_iter()
            .filter_map(|g| g.vpc_security_group_id)
            .collect();
        let host = format!("{name}.endpoint.proxy-{}", endpoint_suffix(ctx));
        let endpoint = t::DBProxyEndpoint {
            db_proxy_endpoint_name: Some(name.clone()),
            db_proxy_endpoint_arn: Some(earn.clone()),
            db_proxy_name: Some(proxy.clone()),
            status: Some("creating".into()),
            vpc_id: Some(vpc),
            vpc_security_group_ids: Some(sgs),
            vpc_subnet_ids: Some(input.vpc_subnet_ids.clone()),
            endpoint: Some(host.clone()),
            created_date: Some(ctx.received_at),
            target_role: Some(role),
            is_default: Some(false),
            endpoint_network_type: Some(input.endpoint_network_type.clone().unwrap_or_else(|| "IPV4".into())),
        };
        self.with_region(ctx, |r| {
            if r.proxy_endpoints.contains_key(&name) || name == "default" {
                return Err(errors::db_proxy_endpoint_already_exists_fault(format!(
                    "Cannot create the DBProxyEndpoint because a DBProxyEndpoint with name {name} already exists."
                )));
            }
            let count =
                r.proxy_endpoints.values().filter(|e| e.item.db_proxy_name.as_deref() == Some(proxy.as_str())).count();
            if count >= MAX_ENDPOINTS {
                return Err(errors::db_proxy_endpoint_quota_exceeded_fault(
                    "Cannot create more than 20 endpoints for a DB proxy.",
                ));
            }
            r.proxy_endpoints.insert(name.clone(), Tagged { item: endpoint.clone(), tags });
            Ok(())
        })?;
        let family = rec.proxy.engine_family.clone().unwrap_or_default();
        let this = self.clone();
        let ctx2 = ctx.clone();
        self.run_task(async move {
            let address = this.proxy_listen(&ctx2, &proxy, &earn, host, &family).await;
            this.with_region(&ctx2, |r| {
                if let Some(e) = r.proxy_endpoints.get_mut(&name) {
                    e.item.status = Some("available".into());
                    e.item.endpoint = Some(address);
                }
            });
        })
        .await;
        Ok(t::CreateDBProxyEndpointResponse { db_proxy_endpoint: Some(endpoint) })
    }

    pub(crate) fn describe_db_proxy_endpoints_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBProxyEndpointsRequest,
    ) -> Result<t::DescribeDBProxyEndpointsResponse, ServiceError> {
        Filters::new(&input.filters, &[])?;
        authorize(ctx, "DescribeDBProxyEndpoints", &arn(ctx, "db-proxy-endpoint", "*"), ConditionContext::new())?;
        let proxy = input.db_proxy_name.as_deref().map(str::to_ascii_lowercase);
        let wanted = input.db_proxy_endpoint_name.as_deref().map(str::to_ascii_lowercase);
        if let Some(p) = &proxy {
            self.proxy(ctx, p)?;
        }
        let mut all: Vec<t::DBProxyEndpoint> = Vec::new();
        self.with_region(ctx, |r| {
            // Each proxy's default endpoint comes first.
            for p in r.proxies.values() {
                if proxy.as_ref().is_some_and(|w| p.proxy.db_proxy_name.as_ref() != Some(w)) {
                    continue;
                }
                all.push(t::DBProxyEndpoint {
                    db_proxy_endpoint_name: Some("default".into()),
                    db_proxy_name: p.proxy.db_proxy_name.clone(),
                    status: p.proxy.status.clone(),
                    vpc_id: p.proxy.vpc_id.clone(),
                    vpc_security_group_ids: p.proxy.vpc_security_group_ids.clone(),
                    vpc_subnet_ids: p.proxy.vpc_subnet_ids.clone(),
                    endpoint: p.proxy.endpoint.clone(),
                    created_date: p.proxy.created_date,
                    target_role: Some("READ_WRITE".into()),
                    is_default: Some(true),
                    endpoint_network_type: p.proxy.endpoint_network_type.clone(),
                    db_proxy_endpoint_arn: None,
                });
            }
            all.extend(
                r.proxy_endpoints
                    .values()
                    .filter(|e| proxy.as_ref().is_none_or(|w| e.item.db_proxy_name.as_ref() == Some(w)))
                    .map(|e| e.item.clone()),
            );
        });
        if let Some(w) = &wanted {
            all.retain(|e| e.db_proxy_endpoint_name.as_ref() == Some(w));
            if all.is_empty() {
                return Err(endpoint_not_found(w));
            }
        }
        let (page, marker) = paginate(all, &input.marker, input.max_records)?;
        Ok(t::DescribeDBProxyEndpointsResponse { db_proxy_endpoints: Some(page), marker })
    }

    pub(crate) fn modify_db_proxy_endpoint_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyDBProxyEndpointRequest,
    ) -> Result<t::ModifyDBProxyEndpointResponse, ServiceError> {
        let name = input.db_proxy_endpoint_name.to_ascii_lowercase();
        let current = self
            .with_region(ctx, |r| r.proxy_endpoints.get(&name).cloned())
            .ok_or_else(|| endpoint_not_found(&name))?;
        authorize(
            ctx,
            "ModifyDBProxyEndpoint",
            current.item.db_proxy_endpoint_arn.as_deref().unwrap_or_default(),
            resource_tag_context("db-proxy-endpoint", &Some(current.tags.clone())),
        )?;
        if current.item.status.as_deref() != Some("available") {
            return Err(errors::invalid_db_proxy_endpoint_state_fault(format!(
                "DBProxyEndpoint {name} is not in available state."
            )));
        }
        let new_name = match &input.new_db_proxy_endpoint_name {
            Some(n) => Some(identifier("NewDBProxyEndpointName", n, 63)?),
            None => None,
        };
        let sgs = match &input.vpc_security_group_ids {
            Some(g) => Some(
                self.security_groups(ctx, &Some(g.clone()), current.item.vpc_id.as_deref().unwrap_or_default())?
                    .into_iter()
                    .filter_map(|g| g.vpc_security_group_id)
                    .collect::<Vec<_>>(),
            ),
            None => None,
        };
        let suffix = endpoint_suffix(ctx);
        let e = self.with_region(ctx, |r| {
            if let Some(n) = &new_name {
                if n != &name && r.proxy_endpoints.contains_key(n) {
                    return Err(errors::db_proxy_endpoint_already_exists_fault(format!(
                        "Cannot rename the DBProxyEndpoint because a DBProxyEndpoint with name {n} already exists."
                    )));
                }
            }
            let mut e = r.proxy_endpoints.remove(&name).expect("looked up above");
            if let Some(g) = sgs {
                e.item.vpc_security_group_ids = Some(g);
            }
            if let Some(n) = &new_name {
                e.item.db_proxy_endpoint_name = Some(n.clone());
                if e.item.endpoint.as_deref().is_some_and(|h| h.contains(".endpoint.proxy-")) {
                    e.item.endpoint = Some(format!("{n}.endpoint.proxy-{suffix}"));
                }
            }
            let view = e.item.clone();
            r.proxy_endpoints.insert(new_name.clone().unwrap_or(name.clone()), e);
            Ok(view)
        })?;
        Ok(t::ModifyDBProxyEndpointResponse { db_proxy_endpoint: Some(e) })
    }

    pub(crate) fn delete_db_proxy_endpoint_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteDBProxyEndpointRequest,
    ) -> Result<t::DeleteDBProxyEndpointResponse, ServiceError> {
        let name = input.db_proxy_endpoint_name.to_ascii_lowercase();
        let current = self
            .with_region(ctx, |r| r.proxy_endpoints.get(&name).cloned())
            .ok_or_else(|| endpoint_not_found(&name))?;
        let earn = current.item.db_proxy_endpoint_arn.clone().unwrap_or_default();
        authorize(
            ctx,
            "DeleteDBProxyEndpoint",
            &earn,
            resource_tag_context("db-proxy-endpoint", &Some(current.tags.clone())),
        )?;
        self.with_region(ctx, |r| r.proxy_endpoints.remove(&name));
        self.inner.forwarders.stop(&earn);
        let mut e = current.item;
        e.status = Some("deleting".into());
        Ok(t::DeleteDBProxyEndpointResponse { db_proxy_endpoint: Some(e) })
    }

    /// Proxies registered with `instance` or `cluster` stop routing to it
    /// when it goes away.
    pub(crate) fn forget_proxy_targets(
        r: &mut crate::state::RegionState,
        instance: Option<&str>,
        cluster: Option<&str>,
    ) {
        for p in r.proxies.values_mut() {
            if let Some(i) = instance {
                p.instances.retain(|x| x != i);
            }
            if let Some(c) = cluster {
                p.clusters.retain(|x| x != c);
            }
        }
    }
}
