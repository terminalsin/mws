//! Public on-demand prices (US East (N. Virginia), Linux, no free tier) and
//! usage type names of resource-hours and storage, for the
//! [`crate::ResourceUsageSource`]s that report running resources. Unknown
//! sizes fall back to the closest family price.

/// The usage type prefix of a Region, as most usage types print it (`USE2-`,
/// none in us-east-1).
pub fn region_prefix(region: &str) -> String {
    crate::pricing::region_prefix(region)
}

/// The Region code that some usage types carry even in us-east-1
/// (`USE1-AmazonEKS-Hours:perCluster`, `USE1-Fargate-vCPU-Hours:perCPU`).
pub fn region_code(region: &str) -> String {
    match region {
        "us-east-1" => "USE1".into(),
        other => crate::pricing::region_prefix(other).trim_end_matches('-').to_string(),
    }
}

/// Hourly price of an RDS DB instance class (MySQL, Single-AZ).
pub fn rds_instance_hour(class: &str) -> f64 {
    match class {
        "db.t3.micro" => 0.017,
        "db.t3.small" => 0.034,
        "db.t3.medium" => 0.068,
        "db.t3.large" => 0.136,
        "db.t3.xlarge" => 0.272,
        "db.t4g.micro" => 0.016,
        "db.t4g.small" => 0.032,
        "db.t4g.medium" => 0.065,
        "db.t4g.large" => 0.129,
        "db.m5.large" | "db.m6i.large" => 0.171,
        "db.m5.xlarge" | "db.m6i.xlarge" => 0.342,
        "db.m6g.large" => 0.152,
        "db.m7g.large" => 0.168,
        "db.r5.large" | "db.r6i.large" => 0.25,
        "db.r6g.large" => 0.225,
        "db.r7g.large" => 0.239,
        "db.serverless" => 0.12,
        c if c.contains(".micro") => 0.017,
        c if c.contains(".small") => 0.034,
        c if c.contains(".medium") => 0.068,
        c if c.contains(".xlarge") => 0.342,
        _ => 0.171,
    }
}

/// Monthly price of a GB of RDS storage, and its usage type suffix.
pub fn rds_storage(storage_type: &str) -> (f64, &'static str) {
    match storage_type {
        "io1" | "io2" => (0.125, "RDS:PIOPS-Storage"),
        "gp3" => (0.115, "RDS:GP3-Storage"),
        "standard" => (0.10, "RDS:StorageUsage"),
        _ => (0.115, "RDS:GP2-Storage"),
    }
}

/// Hourly price of an ElastiCache node type (Redis OSS / Valkey list price).
pub fn elasticache_node_hour(node_type: &str) -> f64 {
    match node_type {
        "cache.t2.micro" => 0.017,
        "cache.t3.micro" => 0.017,
        "cache.t3.small" => 0.034,
        "cache.t3.medium" => 0.068,
        "cache.t4g.micro" => 0.016,
        "cache.t4g.small" => 0.032,
        "cache.t4g.medium" => 0.065,
        "cache.m5.large" => 0.156,
        "cache.m6g.large" => 0.149,
        "cache.m7g.large" => 0.158,
        "cache.r5.large" => 0.216,
        "cache.r6g.large" => 0.206,
        "cache.r7g.large" => 0.219,
        t if t.contains(".micro") => 0.017,
        t if t.contains(".small") => 0.034,
        t if t.contains(".medium") => 0.068,
        _ => 0.156,
    }
}

/// EKS cluster (control plane) price per hour, standard support.
pub const EKS_CLUSTER_HOUR: f64 = 0.10;
/// Fargate (Linux/x86) price per vCPU-hour.
pub const FARGATE_VCPU_HOUR: f64 = 0.04048;
/// Fargate (Linux/x86) price per GB-hour of memory.
pub const FARGATE_GB_HOUR: f64 = 0.004445;
/// EFS Standard storage per GB-month.
pub const EFS_STANDARD_GB_MONTH: f64 = 0.30;

/// EBS volume price per GB-month and its usage type suffix.
pub fn ebs_volume(volume_type: &str) -> (f64, &'static str) {
    match volume_type {
        "gp2" => (0.10, "EBS:VolumeUsage.gp2"),
        "io1" => (0.125, "EBS:VolumeUsage.piops"),
        "io2" => (0.125, "EBS:VolumeUsage.io2"),
        "st1" => (0.045, "EBS:VolumeUsage.st1"),
        "sc1" => (0.015, "EBS:VolumeUsage.sc1"),
        "standard" => (0.05, "EBS:VolumeUsage"),
        _ => (0.08, "EBS:VolumeUsage.gp3"),
    }
}

/// S3 storage price per GB-month by storage class, its usage type suffix
/// and operation.
pub fn s3_storage(storage_class: &str) -> (f64, &'static str, &'static str) {
    match storage_class {
        "STANDARD_IA" => (0.0125, "TimedStorage-SIA-ByteHrs", "StandardIAStorage"),
        "ONEZONE_IA" => (0.01, "TimedStorage-ZIA-ByteHrs", "OneZoneIAStorage"),
        "GLACIER" => (0.0036, "TimedStorage-GlacierByteHrs", "GlacierStorage"),
        "GLACIER_IR" => (0.004, "TimedStorage-GIR-ByteHrs", "GlacierInstantRetrievalStorage"),
        "DEEP_ARCHIVE" => (0.00099, "TimedStorage-GDA-ByteHrs", "DeepArchiveStorage"),
        "INTELLIGENT_TIERING" => (0.023, "TimedStorage-INT-FA-ByteHrs", "IntelligentTieringFAStorage"),
        "REDUCED_REDUNDANCY" => (0.024, "TimedStorage-RRS-ByteHrs", "ReducedRedundancyStorage"),
        _ => (0.023, "TimedStorage-ByteHrs", "StandardStorage"),
    }
}

/// Bytes in a GB, as AWS bills storage (binary gigabytes).
pub const GB: f64 = 1024.0 * 1024.0 * 1024.0;
