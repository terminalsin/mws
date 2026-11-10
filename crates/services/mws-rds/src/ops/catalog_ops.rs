//! Read-only catalog operations (engine versions, orderable options,
//! certificates, account quotas, Regions), maintenance actions and log
//! files.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use super::instance::engine_of;
use super::{authorize, db_arn};
use crate::catalog::{self, Kind, ENGINES};
use crate::generated::{errors, types as t};
use crate::util::{invalid_parameter, name_of, opt, paginate, zones, Filters};
use crate::Rds;

const REGIONS: &[&str] = &[
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "ca-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-central-1",
    "eu-north-1",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-south-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "sa-east-1",
];

fn log_file_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Postgres => "error/postgresql.log",
        Kind::Mysql | Kind::Mariadb => "error/mysql-error.log",
    }
}

impl Rds {
    pub(crate) fn describe_db_engine_versions_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBEngineVersionsMessage,
    ) -> Result<t::DBEngineVersionMessage, ServiceError> {
        authorize(ctx, "DescribeDBEngineVersions", "*", ConditionContext::new())?;
        let f = Filters::new(
            &input.filters,
            &["db-parameter-group-family", "engine", "engine-version", "engine-mode", "status"],
        )?;
        let mut all = Vec::new();
        for e in ENGINES {
            if input.engine.as_ref().is_some_and(|w| w != e.name) {
                continue;
            }
            let versions: Vec<&catalog::Version> = match &input.engine_version {
                Some(v) => e.versions.iter().filter(|x| x.version == v || x.major == v).collect(),
                None if input.default_only == Some(true) => vec![e.default_version()],
                None => e.versions.iter().collect(),
            };
            let versions: Vec<&catalog::Version> =
                if input.default_only == Some(true) { versions.into_iter().rev().take(1).collect() } else { versions };
            for v in versions {
                if input.db_parameter_group_family.as_ref().is_some_and(|f| f != v.family) {
                    continue;
                }
                let dev = catalog::engine_version(e, v);
                let ok = f.matches(|n| match n {
                    "db-parameter-group-family" => opt(&dev.db_parameter_group_family),
                    "engine" => opt(&dev.engine),
                    "engine-version" => opt(&dev.engine_version),
                    "engine-mode" => dev.supported_engine_modes.clone().unwrap_or_default(),
                    "status" => opt(&dev.status),
                    _ => Vec::new(),
                });
                if ok {
                    all.push(dev);
                }
            }
        }
        all.extend(
            self.custom_engine_versions(ctx, input.engine.as_deref(), input.engine_version.as_deref())
                .into_iter()
                .filter(|c| {
                    input
                        .db_parameter_group_family
                        .as_ref()
                        .is_none_or(|f| c.db_parameter_group_family.as_ref() == Some(f))
                        && f.matches(|n| match n {
                            "db-parameter-group-family" => opt(&c.db_parameter_group_family),
                            "engine" => opt(&c.engine),
                            "engine-version" => opt(&c.engine_version),
                            "status" => opt(&c.status),
                            _ => Vec::new(),
                        })
                }),
        );
        let (page, marker) = paginate(all, &input.marker, input.max_records)?;
        Ok(t::DBEngineVersionMessage { marker, db_engine_versions: Some(page) })
    }

    pub(crate) fn describe_db_major_engine_versions_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBMajorEngineVersionsRequest,
    ) -> Result<t::DescribeDBMajorEngineVersionsResponse, ServiceError> {
        authorize(ctx, "DescribeDBMajorEngineVersions", "*", ConditionContext::new())?;
        let mut all = Vec::new();
        for e in ENGINES {
            if input.engine.as_ref().is_some_and(|w| w != e.name) {
                continue;
            }
            let mut majors: Vec<&str> = e.versions.iter().map(|v| v.major).collect();
            majors.dedup();
            for m in majors {
                if input.major_engine_version.as_ref().is_some_and(|w| w != m) {
                    continue;
                }
                let start = |y: i32| {
                    chrono::DateTime::parse_from_rfc3339(&format!("{y}-01-01T00:00:00Z"))
                        .map(|d| d.with_timezone(&chrono::Utc))
                        .unwrap_or_default()
                };
                let base: i32 =
                    2020 + m.split('.').next().and_then(|x| x.parse::<i32>().ok()).map(|x| x % 10).unwrap_or(0);
                all.push(t::DBMajorEngineVersion {
                    engine: Some(e.name.into()),
                    major_engine_version: Some(m.into()),
                    supported_engine_lifecycles: Some(vec![
                        t::SupportedEngineLifecycle {
                            lifecycle_support_name: "open-source-rds-standard-support".into(),
                            lifecycle_support_start_date: start(base),
                            lifecycle_support_end_date: start(base + 5),
                        },
                        t::SupportedEngineLifecycle {
                            lifecycle_support_name: "open-source-rds-extended-support".into(),
                            lifecycle_support_start_date: start(base + 5),
                            lifecycle_support_end_date: start(base + 8),
                        },
                    ]),
                });
            }
        }
        let (page, marker) = paginate(all, &input.marker, input.max_records)?;
        Ok(t::DescribeDBMajorEngineVersionsResponse { db_major_engine_versions: Some(page), marker })
    }

    pub(crate) fn describe_orderable_db_instance_options_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeOrderableDBInstanceOptionsMessage,
    ) -> Result<t::OrderableDBInstanceOptionsMessage, ServiceError> {
        authorize(ctx, "DescribeOrderableDBInstanceOptions", "*", ConditionContext::new())?;
        let engine = engine_of(&input.engine)?;
        let f = Filters::new(&input.filters, &[])?;
        let _ = f;
        let azs: Vec<t::AvailabilityZone> =
            zones(&ctx.region).into_iter().map(|z| t::AvailabilityZone { name: Some(z) }).collect();
        let mut all = Vec::new();
        for v in engine.versions {
            if input.engine_version.as_ref().is_some_and(|w| w != v.version) {
                continue;
            }
            for (class, _, _) in catalog::CLASSES {
                if !catalog::class_supported(engine, class)
                    || input.db_instance_class.as_ref().is_some_and(|c| c != class)
                {
                    continue;
                }
                let types: &[&str] =
                    if engine.aurora { &["aurora", "aurora-iopt1"] } else { &["gp2", "gp3", "io1", "io2", "standard"] };
                for st in types {
                    let (min, max) = if engine.aurora { (0, 0) } else { catalog::storage_range(engine, st) };
                    let iops = matches!(*st, "io1" | "io2" | "gp3");
                    all.push(t::OrderableDBInstanceOption {
                        engine: Some(engine.name.into()),
                        engine_version: Some(v.version.into()),
                        db_instance_class: Some(class.to_string()),
                        license_model: Some(engine.license.into()),
                        availability_zone_group: None,
                        availability_zones: Some(azs.clone()),
                        multi_az_capable: Some(true),
                        read_replica_capable: Some(true),
                        vpc: Some(true),
                        supports_storage_encryption: Some(true),
                        storage_type: Some(st.to_string()),
                        supports_iops: Some(iops),
                        supports_storage_throughput: Some(*st == "gp3"),
                        supports_enhanced_monitoring: Some(true),
                        supports_iam_database_authentication: Some(true),
                        supports_performance_insights: Some(true),
                        min_storage_size: (!engine.aurora).then_some(min),
                        max_storage_size: (!engine.aurora).then_some(max),
                        min_iops_per_db_instance: iops.then_some(1000),
                        max_iops_per_db_instance: iops.then_some(256000),
                        min_iops_per_gib: iops.then_some(0.5),
                        max_iops_per_gib: iops.then_some(1000.0),
                        available_processor_features: Some(Vec::new()),
                        supported_engine_modes: Some(vec!["provisioned".into()]),
                        supports_storage_autoscaling: Some(!engine.aurora),
                        supports_kerberos_authentication: Some(true),
                        outpost_capable: Some(false),
                        supported_activity_stream_modes: Some(Vec::new()),
                        supports_global_databases: Some(engine.aurora),
                        supported_network_types: Some(vec!["IPV4".into(), "DUAL".into()]),
                        supports_clusters: Some(true),
                        supports_dedicated_log_volume: Some(false),
                        supports_additional_storage_volumes: Some(false),
                        supports_http_endpoint: Some(engine.aurora),
                        ..Default::default()
                    });
                }
            }
        }
        let (page, marker) = paginate(all, &input.marker, input.max_records)?;
        Ok(t::OrderableDBInstanceOptionsMessage { orderable_db_instance_options: Some(page), marker })
    }

    pub(crate) fn describe_account_attributes_op(
        &self,
        ctx: &RequestContext,
        _input: t::DescribeAccountAttributesMessage,
    ) -> Result<t::AccountAttributesMessage, ServiceError> {
        authorize(ctx, "DescribeAccountAttributes", "*", ConditionContext::new())?;
        let q = |code| self.quota(ctx, code);
        let (instances, storage_max, parameter_groups, snapshots, subnet_groups, replicas, clusters, cluster_snapshots) = (
            q(crate::quotas::DB_INSTANCES),
            q(crate::quotas::ALLOCATED_STORAGE),
            q(crate::quotas::PARAMETER_GROUPS),
            q(crate::quotas::MANUAL_SNAPSHOTS),
            q(crate::quotas::SUBNET_GROUPS),
            q(crate::quotas::READ_REPLICAS),
            q(crate::quotas::DB_CLUSTERS),
            q(crate::quotas::MANUAL_CLUSTER_SNAPSHOTS),
        );
        let used = self.with_region(ctx, |r| {
            let storage: i64 = r.instances.values().map(|i| i.db.allocated_storage.unwrap_or(0) as i64).sum();
            vec![
                ("DBInstances", r.instances.len() as i64, instances),
                ("ReservedDBInstances", 0, 40),
                ("AllocatedStorage", storage, storage_max),
                ("DBSecurityGroups", 0, 25),
                ("AuthorizationsPerDBSecurityGroup", 0, 20),
                (
                    "DBParameterGroups",
                    r.parameter_groups.values().filter(|g| !g.name.starts_with("default.")).count() as i64,
                    parameter_groups,
                ),
                (
                    "ManualSnapshots",
                    r.snapshots.values().filter(|s| s.snapshot.snapshot_type.as_deref() == Some("manual")).count()
                        as i64,
                    snapshots,
                ),
                ("EventSubscriptions", r.event_subscriptions.len() as i64, 20),
                ("DBSubnetGroups", r.subnet_groups.len() as i64, subnet_groups),
                (
                    "OptionGroups",
                    r.option_groups
                        .values()
                        .filter(|g| !g.item.option_group_name.as_deref().unwrap_or_default().starts_with("default:"))
                        .count() as i64,
                    20,
                ),
                ("SubnetsPerDBSubnetGroup", 0, 20),
                ("ReadReplicasPerMaster", 0, replicas),
                ("DBClusters", r.clusters.len() as i64, clusters),
                (
                    "DBClusterParameterGroups",
                    r.cluster_parameter_groups.values().filter(|g| !g.name.starts_with("default.")).count() as i64,
                    50,
                ),
                ("DBClusterRoles", 0, 5),
                (
                    "ManualClusterSnapshots",
                    r.cluster_snapshots
                        .values()
                        .filter(|s| s.snapshot.snapshot_type.as_deref() == Some("manual"))
                        .count() as i64,
                    cluster_snapshots,
                ),
                ("CustomEndpointsPerDBCluster", 0, 5),
            ]
        });
        Ok(t::AccountAttributesMessage {
            account_quotas: Some(
                used.into_iter()
                    .map(|(n, u, m)| t::AccountQuota {
                        account_quota_name: Some(n.into()),
                        used: Some(u),
                        max: Some(m),
                    })
                    .collect(),
            ),
        })
    }

    pub(crate) fn describe_certificates_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeCertificatesMessage,
    ) -> Result<t::CertificateMessage, ServiceError> {
        authorize(ctx, "DescribeCertificates", "*", ConditionContext::new())?;
        Filters::new(&input.filters, &[])?;
        let over = self.certificate_override(ctx);
        let all: Vec<t::Certificate> = catalog::CERTIFICATES
            .iter()
            .filter(|c| input.certificate_identifier.as_ref().is_none_or(|w| w == c.0))
            .map(|c| t::Certificate {
                certificate_identifier: Some(c.0.into()),
                certificate_type: Some(c.1.into()),
                thumbprint: Some(crate::util::stable_token(c.0, 40)),
                valid_from: c.2.parse().ok(),
                valid_till: c.3.parse().ok(),
                certificate_arn: Some(format!("arn:{}:rds:{}::cert:{}", ctx.partition, ctx.region, c.0)),
                customer_override: Some(over.as_deref() == Some(c.0)),
                customer_override_valid_till: (over.as_deref() == Some(c.0)).then(|| c.3.parse().ok()).flatten(),
            })
            .collect();
        if let Some(w) = &input.certificate_identifier {
            if all.is_empty() {
                return Err(errors::certificate_not_found_fault(format!("Certificate {w} not found.")));
            }
        }
        let (page, marker) = paginate(all, &input.marker, input.max_records)?;
        Ok(t::CertificateMessage {
            default_certificate_for_new_launches: Some(self.default_certificate(ctx)),
            certificates: Some(page),
            marker,
        })
    }

    /// The account's CA override for new DB instances, if any.
    pub(crate) fn certificate_override(&self, ctx: &RequestContext) -> Option<String> {
        let key = (crate::util::account_of(ctx), ctx.region.clone());
        self.inner.certificate_overrides.lock().expect("certificate lock").get(&key).cloned()
    }

    /// The CA new DB instances get when they name none.
    pub(crate) fn default_certificate(&self, ctx: &RequestContext) -> String {
        self.certificate_override(ctx).unwrap_or_else(|| catalog::DEFAULT_CERTIFICATE.into())
    }

    pub(crate) fn modify_certificates_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyCertificatesMessage,
    ) -> Result<t::ModifyCertificatesResult, ServiceError> {
        authorize(ctx, "ModifyCertificates", "*", ConditionContext::new())?;
        let key = (crate::util::account_of(ctx), ctx.region.clone());
        let remove = input.remove_customer_override == Some(true);
        let id = match (&input.certificate_identifier, remove) {
            (Some(_), true) => {
                return Err(crate::util::invalid_combination(
                    "You can't specify both CertificateIdentifier and RemoveCustomerOverride.",
                ))
            }
            (None, false) => {
                return Err(crate::util::invalid_parameter(
                    "Specify either CertificateIdentifier or RemoveCustomerOverride.",
                ))
            }
            (Some(id), false) => Some(id.clone()),
            (None, true) => None,
        };
        let shown = match &id {
            Some(id) => {
                if !catalog::CERTIFICATES.iter().any(|c| c.0 == id) {
                    return Err(errors::certificate_not_found_fault(format!("Certificate {id} not found.")));
                }
                self.inner.certificate_overrides.lock().expect("certificate lock").insert(key, id.clone());
                id.clone()
            }
            None => {
                let old = self.inner.certificate_overrides.lock().expect("certificate lock").remove(&key);
                old.unwrap_or_else(|| catalog::DEFAULT_CERTIFICATE.into())
            }
        };
        let c = catalog::CERTIFICATES.iter().find(|c| c.0 == shown).copied();
        Ok(t::ModifyCertificatesResult {
            certificate: c.map(|c| t::Certificate {
                certificate_identifier: Some(c.0.into()),
                certificate_type: Some(c.1.into()),
                thumbprint: Some(crate::util::stable_token(c.0, 40)),
                valid_from: c.2.parse().ok(),
                valid_till: c.3.parse().ok(),
                certificate_arn: Some(format!("arn:{}:rds:{}::cert:{}", ctx.partition, ctx.region, c.0)),
                customer_override: Some(id.is_some()),
                customer_override_valid_till: id.is_some().then(|| c.3.parse().ok()).flatten(),
            }),
        })
    }

    pub(crate) fn describe_source_regions_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeSourceRegionsMessage,
    ) -> Result<t::SourceRegionMessage, ServiceError> {
        authorize(ctx, "DescribeSourceRegions", "*", ConditionContext::new())?;
        Filters::new(&input.filters, &[])?;
        let all: Vec<t::SourceRegion> = REGIONS
            .iter()
            .filter(|r| **r != ctx.region && input.region_name.as_ref().is_none_or(|w| w == *r))
            .map(|r| t::SourceRegion {
                region_name: Some(r.to_string()),
                endpoint: Some(format!("https://rds.{r}.amazonaws.com")),
                status: Some("available".into()),
                supports_db_instance_automated_backups_replication: Some(true),
            })
            .collect();
        let (page, marker) = paginate(all, &input.marker, input.max_records)?;
        Ok(t::SourceRegionMessage { marker, source_regions: Some(page) })
    }

    pub(crate) async fn describe_db_log_files_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBLogFilesMessage,
    ) -> Result<t::DescribeDBLogFilesResponse, ServiceError> {
        let id = name_of(&input.db_instance_identifier).to_ascii_lowercase();
        let rec = self.instance(ctx, &id)?;
        authorize(ctx, "DescribeDBLogFiles", &db_arn(ctx, &id), ConditionContext::new())?;
        Filters::new(&input.filters, &[])?;
        let engine = engine_of(rec.db.engine.as_deref().unwrap_or_default())?;
        let backend_name = self.log_source(ctx, &rec);
        let data = self.backend().logs(&backend_name).await.unwrap_or_default();
        let name = log_file_name(engine.kind);
        let last = self.now().timestamp_millis();
        let files = vec![t::DescribeDBLogFilesDetails {
            log_file_name: Some(name.into()),
            last_written: Some(last),
            size: Some(data.len() as i64),
        }];
        let files: Vec<_> = files
            .into_iter()
            .filter(|f| {
                input
                    .filename_contains
                    .as_ref()
                    .is_none_or(|c| f.log_file_name.as_deref().unwrap_or_default().contains(c.as_str()))
            })
            .filter(|f| input.file_size.is_none_or(|s| f.size.unwrap_or(0) >= s))
            .filter(|f| input.file_last_written.is_none_or(|s| f.last_written.unwrap_or(0) >= s))
            .collect();
        let (page, marker) = paginate(files, &input.marker, input.max_records)?;
        Ok(t::DescribeDBLogFilesResponse { describe_db_log_files: Some(page), marker })
    }

    fn log_source(&self, ctx: &RequestContext, rec: &crate::state::InstanceRecord) -> String {
        match &rec.db.db_cluster_identifier {
            Some(c) => self.with_region(ctx, |r| r.clusters.get(c).map(|c| c.backend_name.clone())).unwrap_or_default(),
            None => rec.backend_name.clone(),
        }
    }

    pub(crate) async fn download_db_log_file_portion_op(
        &self,
        ctx: &RequestContext,
        input: t::DownloadDBLogFilePortionMessage,
    ) -> Result<t::DownloadDBLogFilePortionDetails, ServiceError> {
        let id = name_of(&input.db_instance_identifier).to_ascii_lowercase();
        let rec = self.instance(ctx, &id)?;
        authorize(ctx, "DownloadDBLogFilePortion", &db_arn(ctx, &id), ConditionContext::new())?;
        let engine = engine_of(rec.db.engine.as_deref().unwrap_or_default())?;
        if input.log_file_name != log_file_name(engine.kind) {
            return Err(errors::db_log_file_not_found_fault(format!(
                "DBLog File: {}, is not found on the DB instance",
                input.log_file_name
            )));
        }
        let data = self.backend().logs(&self.log_source(ctx, &rec)).await.unwrap_or_default();
        let lines: Vec<&str> = data.lines().collect();
        let start: usize = match input.marker.as_deref() {
            None | Some("0") => 0,
            Some(m) => m
                .split(':')
                .next_back()
                .and_then(|x| x.parse().ok())
                .ok_or_else(|| invalid_parameter("Invalid marker"))?,
        };
        let n = input.number_of_lines.unwrap_or(10000).clamp(1, 10000) as usize;
        let end = (start + n).min(lines.len());
        let chunk = lines.get(start..end).unwrap_or_default().join("\n");
        Ok(t::DownloadDBLogFilePortionDetails {
            log_file_data: Some(if chunk.is_empty() { chunk } else { chunk + "\n" }),
            marker: Some(format!("0:{end}")),
            additional_data_pending: Some(end < lines.len()),
        })
    }
}
