//! Cross-service glue for costs (platform services): the running resources
//! Cost Explorer bills by the hour or GB-month, and Marketplace metering
//! charged to the buyer.

use std::collections::BTreeMap;
use std::sync::Arc;

use mws_ce::rates::{self, region_code, region_prefix, GB};
use mws_ce::{CostExplorer, ResourceUsage, ResourceUsageSource, UsageCharge, UsageRate};

/// Wire the resource sources and Marketplace metering into Cost Explorer.
pub(crate) fn wire(ce: &CostExplorer, resources: PlatformResources, metering: &mws_marketplace_metering::Metering) {
    ce.add_resource_source(Arc::new(resources));
    metering.set_usage_sink(Arc::new(MeteringToCostExplorer(ce.clone())));
}

/// The services that own billable resources.
pub(crate) struct PlatformResources {
    pub ec2: mws_ec2::Ec2,
    pub rds: mws_rds::Rds,
    pub eks: mws_eks::Eks,
    pub elasticache: mws_elasticache::ElastiCache,
    pub ecs: mws_ecs::Ecs,
    pub s3: mws_s3::S3,
    pub efs: mws_efs::Efs,
}

fn hourly(account: &str, region: &str, service: &str, usage_type: String, resource_id: &str) -> ResourceUsage {
    ResourceUsage {
        account: account.to_string(),
        region: region.to_string(),
        service: service.to_string(),
        usage_type,
        resource_id: resource_id.to_string(),
        unit: "Hrs".into(),
        rate: UsageRate::PerHour,
        quantity: 1.0,
        ..Default::default()
    }
}

fn monthly(
    account: &str,
    region: &str,
    service: &str,
    usage_type: String,
    resource_id: &str,
    gb: f64,
) -> ResourceUsage {
    ResourceUsage {
        unit: "GB-Mo".into(),
        rate: UsageRate::PerMonth,
        quantity: gb,
        ..hourly(account, region, service, usage_type, resource_id)
    }
}

const EC2: &str = "Amazon Elastic Compute Cloud - Compute";
const EC2_OTHER: &str = "EC2 - Other";
const RDS: &str = "Amazon Relational Database Service";
const EKS: &str = "Amazon Elastic Container Service for Kubernetes";
const ELASTICACHE: &str = "Amazon ElastiCache";
const ECS: &str = "Amazon Elastic Container Service";
const S3: &str = "Amazon Simple Storage Service";
const EFS: &str = "Amazon Elastic File System";

fn database_engine(engine: &str) -> String {
    match engine {
        "mysql" => "MySQL".into(),
        "postgres" => "PostgreSQL".into(),
        "mariadb" => "MariaDB".into(),
        "aurora-mysql" | "aurora" => "Aurora MySQL".into(),
        "aurora-postgresql" => "Aurora PostgreSQL".into(),
        e if e.starts_with("oracle") => "Oracle".into(),
        e if e.starts_with("sqlserver") => "SQL Server".into(),
        e => e.to_string(),
    }
}

impl PlatformResources {
    fn ec2(&self, out: &mut Vec<ResourceUsage>) {
        for i in self.ec2.billable_instances() {
            let p = region_prefix(&i.region);
            let windows = i.platform.starts_with("Windows");
            let mut u = hourly(&i.account, &i.region, EC2, format!("{p}BoxUsage:{}", i.instance_type), &i.instance_id);
            u.operation = if windows { "RunInstances:0002" } else { "RunInstances" }.into();
            u.price = mws_ec2::product_price(&i.instance_type, &i.platform).unwrap_or(0.0416);
            u.instance_type = Some(i.instance_type.clone());
            u.started = i.launched;
            u.ended = i.stopped;
            u.tags = i.tags;
            u.dimensions.insert("PLATFORM".into(), i.platform);
            out.push(u);
        }
        for v in self.ec2.billable_volumes() {
            let (price, suffix) = rates::ebs_volume(&v.volume_type);
            let p = region_prefix(&v.region);
            let mut u =
                monthly(&v.account, &v.region, EC2_OTHER, format!("{p}{suffix}"), &v.volume_id, v.size_gib as f64);
            u.operation = match v.volume_type.as_str() {
                "gp3" => "CreateVolume-Gp3",
                "gp2" => "CreateVolume-Gp2",
                "io1" | "io2" => "CreateVolume-P-IOPS",
                _ => "CreateVolume",
            }
            .into();
            u.price = price;
            u.started = v.created;
            u.tags = v.tags;
            out.push(u);
        }
    }

    fn rds(&self, out: &mut Vec<ResourceUsage>) {
        for db in self.rds.billable_instances() {
            let p = region_prefix(&db.region);
            let az = if db.multi_az { "Multi-AZUsage" } else { "InstanceUsage" };
            let mut dims = BTreeMap::new();
            dims.insert("DATABASE_ENGINE".to_string(), database_engine(&db.engine));
            let mut u = hourly(&db.account, &db.region, RDS, format!("{p}{az}:{}", db.instance_class), &db.arn);
            u.operation = "CreateDBInstance".into();
            // Stopped instances keep their place on the meter but accrue
            // no compute.
            u.quantity = if db.running { 1.0 } else { 0.0 };
            u.price = rates::rds_instance_hour(&db.instance_class) * if db.multi_az { 2.0 } else { 1.0 };
            u.instance_type = Some(db.instance_class.clone());
            u.started = db.created;
            u.tags = db.tags.clone();
            u.dimensions = dims.clone();
            out.push(u);
            let (price, suffix) = rates::rds_storage(&db.storage_type);
            let suffix = if db.multi_az { suffix.replacen("RDS:", "RDS:Multi-AZ-", 1) } else { suffix.to_string() };
            let mut s = monthly(&db.account, &db.region, RDS, format!("{p}{suffix}"), &db.arn, db.allocated_gib as f64);
            s.operation = "CreateDBInstance".into();
            s.price = price * if db.multi_az { 2.0 } else { 1.0 };
            s.started = db.created;
            s.tags = db.tags;
            s.dimensions = dims;
            out.push(s);
        }
    }

    fn eks(&self, out: &mut Vec<ResourceUsage>) {
        for c in self.eks.billable_clusters() {
            let code = region_code(&c.region);
            let mut u = hourly(&c.account, &c.region, EKS, format!("{code}-AmazonEKS-Hours:perCluster"), &c.arn);
            u.operation = "CreateOperation".into();
            u.price = rates::EKS_CLUSTER_HOUR;
            u.started = c.created;
            u.tags = c.tags;
            out.push(u);
        }
    }

    fn elasticache(&self, out: &mut Vec<ResourceUsage>) {
        for c in self.elasticache.billable_clusters() {
            let p = region_prefix(&c.region);
            let mut u = hourly(&c.account, &c.region, ELASTICACHE, format!("{p}NodeUsage:{}", c.node_type), &c.arn);
            u.operation = "CreateCacheCluster".into();
            u.quantity = c.nodes.max(1) as f64;
            u.price = rates::elasticache_node_hour(&c.node_type);
            u.instance_type = Some(c.node_type.clone());
            u.started = c.created;
            u.tags = c.tags;
            let engine = match c.engine.as_str() {
                "memcached" => "Memcached",
                "valkey" => "Valkey",
                _ => "Redis",
            };
            u.dimensions.insert("CACHE_ENGINE".into(), engine.into());
            out.push(u);
        }
    }

    fn fargate(&self, out: &mut Vec<ResourceUsage>) {
        for t in self.ecs.billable_tasks() {
            let code = region_code(&t.region);
            let spot = if t.spot { "SpotUsage-" } else { "" };
            // Fargate Spot runs at about 30% of the On-Demand price.
            let factor = if t.spot { 0.3 } else { 1.0 };
            for (usage_type, unit, quantity, price) in [
                (format!("{code}-{spot}Fargate-vCPU-Hours:perCPU"), "vCPU-Hours", t.vcpu, rates::FARGATE_VCPU_HOUR),
                (format!("{code}-{spot}Fargate-GB-Hours"), "GB-Hours", t.memory_gb, rates::FARGATE_GB_HOUR),
            ] {
                let mut u = hourly(&t.account, &t.region, ECS, usage_type, &t.task_arn);
                u.operation = "FargateTask".into();
                u.unit = unit.into();
                u.quantity = quantity;
                u.price = price * factor;
                u.started = t.started;
                u.ended = t.stopped;
                u.tags = t.tags.clone();
                out.push(u);
            }
        }
    }

    fn storage(&self, out: &mut Vec<ResourceUsage>) {
        for b in self.s3.bucket_storage() {
            let p = region_prefix(&b.region);
            for (class, bytes) in &b.bytes {
                let (price, suffix, operation) = rates::s3_storage(class);
                let mut u = monthly(&b.account, &b.region, S3, format!("{p}{suffix}"), &b.bucket, *bytes as f64 / GB);
                u.operation = operation.into();
                u.price = price;
                u.started = Some(b.created);
                u.tags = b.tags.clone();
                out.push(u);
            }
        }
        for f in self.efs.file_system_storage() {
            let p = region_prefix(&f.region);
            let mut u =
                monthly(&f.account, &f.region, EFS, format!("{p}TimedStorage-ByteHrs"), &f.arn, f.bytes as f64 / GB);
            u.operation = "Storage".into();
            u.price = rates::EFS_STANDARD_GB_MONTH;
            u.started = Some(f.created);
            u.tags = f.tags;
            out.push(u);
        }
    }
}

impl ResourceUsageSource for PlatformResources {
    fn resources(&self) -> Vec<ResourceUsage> {
        let mut out = Vec::new();
        self.ec2(&mut out);
        self.rds(&mut out);
        self.eks(&mut out);
        self.elasticache(&mut out);
        self.fargate(&mut out);
        self.storage(&mut out);
        out
    }
}

/// Accepted Marketplace metering records, charged to the buyer at the
/// dimension's price under the product's title (`BILLING_ENTITY`
/// `AWS Marketplace`), with the usage allocations' tags.
pub(crate) struct MeteringToCostExplorer(pub CostExplorer);

impl mws_marketplace_metering::UsageSink for MeteringToCostExplorer {
    fn accepted(
        &self,
        region: &str,
        record: &mws_marketplace_metering::MeteringRecord,
        product: &mws_marketplace_entitlement::Product,
    ) {
        let price = product.dimensions.iter().find(|d| d.name == record.dimension).and_then(|d| d.price).unwrap_or(0.0);
        let service = if product.title.is_empty() { product.product_code.clone() } else { product.title.clone() };
        let mut parts: Vec<(f64, BTreeMap<String, String>)> = record
            .usage_allocations
            .iter()
            .map(|a| (a.allocated_usage_quantity as f64, a.tags.iter().cloned().collect()))
            .collect();
        if parts.is_empty() {
            parts.push((record.quantity as f64, BTreeMap::new()));
        }
        for (quantity, tags) in parts {
            self.0.record_usage(UsageCharge {
                account: record.customer_aws_account_id.clone(),
                region: region.to_string(),
                at: record.timestamp,
                service: service.clone(),
                usage_type: format!("{}-MP:{}", region_code(region), record.dimension),
                operation: record.operation.clone(),
                resource_id: None,
                unit: "Units".into(),
                quantity,
                cost: quantity * price,
                tags,
                dimensions: BTreeMap::from([
                    ("BILLING_ENTITY".to_string(), "AWS Marketplace".to_string()),
                    ("RECORD_TYPE".to_string(), "Usage".to_string()),
                ]),
            });
        }
    }
}
