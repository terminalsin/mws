# Amazon RDS and Amazon Aurora

> Crate: [`mws-rds`](../../crates/services/mws-rds) · Tests: [`tests/e2e-rust/tests/e2e/rds.rs`](../../tests/e2e-rust/tests/e2e/rds.rs), [`rds_more.rs`](../../tests/e2e-rust/tests/e2e/rds_more.rs), [`rds_maintenance.rs`](../../tests/e2e-rust/tests/e2e/rds_maintenance.rs), [`rds_docker.rs`](../../tests/e2e-rust/tests/e2e/rds_docker.rs)

All 168 of the model's operations are implemented (awsQuery). Identifiers are stored in lower case, names and ARNs are accepted where RDS accepts them, and errors use RDS's codes (`DBInstanceNotFound`, `InvalidDBInstanceState`, `InvalidParameterCombination`, ...).

✅ supported · 🟡 partial · ❌ not supported

## Databases

| Feature | Status | Details |
| --- | :---: | --- |
| Engines | ✅ | PostgreSQL 13 to 17, MySQL 8.0 and 8.4, MariaDB 10.11 and 11.4, Aurora PostgreSQL 13 to 17 and Aurora MySQL 3. Oracle, SQL Server, Db2 and RDS Custom are not offered. |
| DB instances | ✅ | RDS's states (`creating`, `backing-up`, `available`, `modifying`, `upgrading`, `storage-optimization`, `rebooting`, `stopping`, `stopped`, `starting`, `deleting`), storage types and limits, Multi-AZ, renames, deletion protection, final snapshots, automatic restart seven days after a stop. |
| Pending modifications | ✅ | Without `ApplyImmediately`, class, storage, IOPS, Multi-AZ, engine version and identifier changes wait in `PendingModifiedValues` and are applied at the start of the next `PreferredMaintenanceWindow` on the emulated clock (Multi-AZ DB clusters' storage and cluster engine versions too). With `ApplyImmediately` the response still shows the old values with the new ones pending while the instance is `modifying`, and queued changes are applied with it. `RDS-EVENT-0014` is sent only when the class changes. |
| Maintenance actions | 🟡 | `DescribePendingMaintenanceActions` lists pending engine upgrades as `db-upgrade` actions (on the instance or cluster ARN, with the next window as `CurrentApplyDate`); `ApplyPendingMaintenanceAction` applies them with `immediate`, or records `next-maintenance` / `undo-opt-in`. RDS's own OS and engine maintenance (`system-update`, `ca-certificate-rotation`) is never scheduled. |
| Storage changes | ✅ | Increases under 10% are refused; after a storage change the instance is in `storage-optimization` for six hours of the emulated clock, during which further storage changes fail with `InvalidParameterCombination`. (RDS's newer allowance of up to four changes in 24 hours is not modelled.) |
| Docker backend | ✅ | `MWS_RDS_BACKEND=docker` runs each DB instance (and each Aurora cluster) as a container of the engine's official image, with a data volume, the master user and database name, parameter group values as server settings, and memory limits from the instance class. The endpoint is `127.0.0.1` (or `MWS_RDS_BIND`) and the published port. |
| Metadata backend | ✅ | `MWS_RDS_BACKEND=metadata` runs nothing; resources become available at once and endpoints use AWS-style host names. |
| Read replicas | 🟡 | Created as a copy of the source's data, read-only; they do not stream changes from the source. `PromoteReadReplica` makes them writable. |
| Engine upgrades | ✅ | Minor upgrades switch the container image. A PostgreSQL major upgrade (in place, in a restore or in a Blue/Green green) dumps the data with the old server and loads it into a data directory the new server initialized; MySQL and MariaDB upgrade their data directory on start. Pending (not `ApplyImmediately`) upgrades are applied in the maintenance window. |
| Log files | 🟡 | One file per instance (`error/postgresql.log` or `error/mysql-error.log`) with the container's log. |
| RDS Proxy | ✅ | Proxies, target groups (connection pool settings), targets (one DB instance or one Aurora cluster) and custom endpoints, with RDS's validation (auth secrets must exist, password auth types per engine family, subnets in two Availability Zones of one VPC, `iam:PassRole`, 20 proxies and 20 endpoints). With the Docker backend each proxy endpoint is a TCP listener that forwards to its target's database: on a loopback address of its own (`127.77.x.y`) on the engine's port when the host allows it, otherwise on an ephemeral port of `127.0.0.1`. `GET /_aws/rds/proxy-endpoints` lists them. The proxy does not pool connections, check `RequireTLS` or authenticate with the auth secrets or IAM; clients sign in with the database's own credentials. |
| Blue/Green deployments | ✅ | The green environment is a copy of blue (a read replica of an instance, a clone of a cluster and its instances) with the requested engine version, parameter groups, class and storage. Switchover requires `AVAILABLE` and a timeout of at least 30 seconds; it copies blue's latest data and credentials to green, renames blue to `<name>-old1` and green to blue's name (endpoints follow the names) and emits `RDS-EVENT-0245`. `DeleteTarget` deletes green before a switchover; without it green replicas are promoted. Green does not replicate blue continuously: the switchover copy carries blue's writes. |
| Other platforms | 🟡 | DB security groups (EC2-Classic) answer `DBSecurityGroupNotSupported` or not found, tenant databases (Oracle multitenant) `InvalidDBInstanceState`, `SwitchoverReadReplica` (Oracle) `InvalidDBInstanceState`, `ModifyCurrentDBClusterCapacity` (Serverless v1) and `ModifyActivityStream` (Oracle) errors. RDS Custom engine versions (`custom-oracle-*`, `custom-sqlserver-*`) are recorded and listed by `DescribeDBEngineVersions`, but no RDS Custom instance can be created. |
| IAM database authentication, Kerberos | ❌ | Recorded where the API takes them, not enforced. |

## Aurora

| Feature | Status | Details |
| --- | :---: | --- |
| Clusters | ✅ | The cluster owns the database; its instances share it. Writer and reader endpoints, member promotion tiers, failover, stop, start and reboot of the whole cluster. |
| Serverless v2 | ✅ | `db.serverless` instances, capacity ranges in half-ACU steps, auto-pause at 0 ACU (capacity is not enforced). |
| Custom endpoints | ✅ | `READER` and `ANY` endpoints with static or excluded members. |
| Global databases | ✅ | Global clusters across Regions, secondaries inheriting the primary's credentials, switchover, failover and removal. Data is not replicated between Regions. |
| Multi-AZ DB clusters | 🟡 | Non-Aurora clusters come with three instances sharing one database. |
| Clones | 🟡 | `copy-on-write` restores share a clone group id and copy the data. |
| Backtrack | ✅ | Aurora MySQL clusters take a `BacktrackWindow` (up to 72 hours) at creation. With the Docker backend `BacktrackDBCluster` really rewinds the cluster in place: its newest backup before the target time is rolled forward with its binary log to that time and swapped in under the same endpoint. `DescribeDBClusterBacktracks` lists them. |
| Limitless Database | 🟡 | Aurora PostgreSQL clusters with `ClusterScalabilityType=limitless` take one DB shard group (create, modify, reboot, delete; ACU and redundancy checks). The shard group's endpoint reaches the cluster's database; there is no sharding. |
| Zero-ETL integrations | 🟡 | Integrations from an Aurora cluster or DB instance to a Redshift, Redshift Serverless or Glue target, with names, data filters, KMS keys and quotas. No data reaches the target. |
| Database activity streams | 🟡 | Aurora clusters start and stop an activity stream (mode, KMS key, `aws-rds-das-<resource id>` stream name). No Kinesis stream is created and no activity is recorded. |
| Data API | ❌ | `EnableHttpEndpoint` is recorded; the Data API itself is not emulated. |

## Backups

| Feature | Status | Details |
| --- | :---: | --- |
| Snapshots | ✅ | Manual DB and cluster snapshots (copies of the data volume with the Docker backend), copies across Regions and keys, sharing with accounts or the public through the `restore` attribute, `CopyTagsToSnapshot`. |
| Restores | ✅ | From DB and cluster snapshots, including snapshots shared from other accounts. |
| Point-in-time restore | ✅ | With the Docker backend the restore is real: PostgreSQL archives its WAL and MySQL and MariaDB keep a binary log, and a restore copies the newest backup taken before the restore time and replays the log up to it (PostgreSQL's `recovery_target_time`; MySQL's server replays the binary log as a relay log until the last transaction begun by then). `UseLatestRestorableTime` copies the current data. Works from live DB instances and clusters and from retained automated backups of deleted instances. Restore times are on the emulated clock; RDS maps them to the wall-clock time the log was written. |
| Automated backups | ✅ | A snapshot when a database is created, then one a day on the emulated clock while the retention period is above zero, dropped after the retention period. Retained backups after deletion keep the transaction log for point-in-time restores, and `DeleteDBInstanceAutomatedBackup` removes them. |
| Backup replication | 🟡 | `StartDBInstanceAutomatedBackupsReplication` (called in the destination Region) lists a `replicating` automated backup there and on the source instance; `Stop...` leaves it `retained`. The data is not copied, so the replicated backup can't be restored with the Docker backend. |
| Exports to S3 | ✅ | `StartExportTask` exports a DB snapshot, a cluster snapshot or a live cluster (`ExportOnly` by database, schema or table). With the Docker backend the export reads every table from a copy of the data and writes one Parquet file per table under `<prefix>/<export id>/<database>/<schema>.<table>/1/`, then `export_tables_info_<id>_from_1_to_<n>.json` and `export_info_<id>.json`, all with SSE-KMS under the export's key and as the IAM role (assumed as `export.rds.amazonaws.com`). Integers, floating-point numbers and booleans keep their types; every other column is a string. Files are uncompressed. `CancelExportTask` stops an export between tables. |

## Configuration

| Feature | Status | Details |
| --- | :---: | --- |
| Subnet groups | ✅ | Subnets checked against EC2 (same VPC, at least two Availability Zones); a `default` group from the default VPC. |
| Security groups | ✅ | VPC security groups checked against EC2; the VPC's default group otherwise. Traffic is not filtered. |
| Parameter groups | ✅ | DB and cluster parameter groups with the engines' common parameters, defaults per family, static versus dynamic parameters, `pending-reboot`, resets and copies. Native parameters reach the server at its next start. |
| Option groups | 🟡 | Created, copied and described; options are recorded but have no effect. |
| CA certificates | ✅ | `rds-ca-rsa2048-g1` (default), `rds-ca-rsa4096-g1`, `rds-ca-ecc384-g1`; `ModifyCertificates` sets the account's default for new DB instances (not kept in saved state). Connections are not TLS. |
| Catalog | ✅ | Engine versions, major versions, orderable options, account quotas, source Regions, Serverless v2 platform versions. `DescribeDBRecommendations` lists none. |
| Reserved instances | ✅ | An offerings catalog for every class, engine, term (one or three years), payment option and deployment, with prices in USD derived from the class's memory. Purchases are `payment-pending`, then `active`, and `retired` when their term ends on the emulated clock. |
| Capacity reservations | 🟡 | DB capacity reservations per class, engine and Availability Zone, with start and end dates, commitments, modifications and cancellation; available capacity counts the account's matching instances. Reservations don't limit launches. |

## Integrations

| Feature | Status | Details |
| --- | :---: | --- |
| Secrets Manager | ✅ | `ManageMasterUserPassword` creates an `rds!db-...` or `rds!cluster-...` secret owned by RDS, rotated every seven days, on `RotateSecret` or with `RotateMasterUserPassword`; each rotation sets the new password in the running database. |
| KMS | ✅ | Storage encryption with `aws/rds` or a customer key; RDS uses the key as the caller, so disabled keys and key policies give `KMSKeyNotAccessibleFault`. |
| Events | ✅ | `DescribeEvents` (14 days), event categories, event subscriptions publishing to SNS as `rds.amazonaws.com`, and `aws.rds` events on the default EventBridge bus. |
| IAM | ✅ | Every operation authorizes `rds:<Action>` with RDS condition keys (`rds:DatabaseEngine`, `rds:DatabaseClass`, `rds:<kind>-tag/*`, `aws:RequestTag`, ...); role associations and Enhanced Monitoring roles check `iam:PassRole`. |
| Tags | ✅ | On every resource, by ARN. |
| Enhanced Monitoring | 🟡 | `MonitoringInterval` other than 0 needs a `MonitoringRoleArn`, `iam:PassRole` on it, and a role `monitoring.rds.amazonaws.com` can assume (`ENHANCED_MONITORING` error otherwise). No OS metrics are sent to CloudWatch Logs. |
| Performance Insights, restores from S3 | ❌ | Recorded where the API takes them. `RestoreDBInstanceFromS3` and `RestoreDBClusterFromS3` answer `InvalidS3BucketFault`: Percona XtraBackup files are not read. |

See also: [all services](README.md) · [configuration](../configuration.md).
