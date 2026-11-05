# Amazon RDS and Amazon Aurora

> Crate: [`mws-rds`](../../crates/services/mws-rds) · Tests: [`tests/e2e-rust/tests/e2e/rds.rs`](../../tests/e2e-rust/tests/e2e/rds.rs), [`rds_docker.rs`](../../tests/e2e-rust/tests/e2e/rds_docker.rs)

103 of the model's 168 operations are implemented (awsQuery); the rest answer `NotImplemented`. Identifiers are stored in lower case, names and ARNs are accepted where RDS accepts them, and errors use RDS's codes (`DBInstanceNotFound`, `InvalidDBInstanceState`, `InvalidParameterCombination`, ...).

✅ supported · 🟡 partial · ❌ not supported

## Databases

| Feature | Status | Details |
| --- | :---: | --- |
| Engines | ✅ | PostgreSQL 13 to 17, MySQL 8.0 and 8.4, MariaDB 10.11 and 11.4, Aurora PostgreSQL 13 to 17 and Aurora MySQL 3. Oracle, SQL Server, Db2 and RDS Custom are not offered. |
| DB instances | ✅ | RDS's states (`creating`, `available`, `modifying`, `rebooting`, `stopping`, `stopped`, `starting`, `deleting`), storage types and limits, Multi-AZ, pending modifications versus `ApplyImmediately`, renames, deletion protection, final snapshots, automatic restart seven days after a stop. |
| Docker backend | ✅ | `MWS_RDS_BACKEND=docker` runs each DB instance (and each Aurora cluster) as a container of the engine's official image, with a data volume, the master user and database name, parameter group values as server settings, and memory limits from the instance class. The endpoint is `127.0.0.1` (or `MWS_RDS_BIND`) and the published port. |
| Metadata backend | ✅ | `MWS_RDS_BACKEND=metadata` runs nothing; resources become available at once and endpoints use AWS-style host names. |
| Read replicas | 🟡 | Created as a copy of the source's data, read-only; they do not stream changes from the source. `PromoteReadReplica` makes them writable. |
| Engine upgrades | 🟡 | Minor upgrades switch the container image; major upgrades are recorded but keep the old image (no `pg_upgrade`). |
| Log files | 🟡 | One file per instance (`error/postgresql.log` or `error/mysql-error.log`) with the container's log. |
| IAM database authentication, Kerberos, RDS Proxy, Blue/Green deployments | ❌ | Recorded where the API takes them, not enforced; Proxy and Blue/Green answer `NotImplemented`. |

## Aurora

| Feature | Status | Details |
| --- | :---: | --- |
| Clusters | ✅ | The cluster owns the database; its instances share it. Writer and reader endpoints, member promotion tiers, failover, stop, start and reboot of the whole cluster. |
| Serverless v2 | ✅ | `db.serverless` instances, capacity ranges in half-ACU steps, auto-pause at 0 ACU (capacity is not enforced). |
| Custom endpoints | ✅ | `READER` and `ANY` endpoints with static or excluded members. |
| Global databases | ✅ | Global clusters across Regions, secondaries inheriting the primary's credentials, switchover, failover and removal. Data is not replicated between Regions. |
| Multi-AZ DB clusters | 🟡 | Non-Aurora clusters come with three instances sharing one database. |
| Clones | 🟡 | `copy-on-write` restores share a clone group id and copy the data. |
| Backtrack, Data API calls, Limitless, zero-ETL integrations | ❌ | `EnableHttpEndpoint` is recorded; the Data API itself is not emulated. |

## Backups

| Feature | Status | Details |
| --- | :---: | --- |
| Snapshots | ✅ | Manual DB and cluster snapshots (copies of the data volume with the Docker backend), copies across Regions and keys, sharing with accounts or the public through the `restore` attribute, `CopyTagsToSnapshot`. |
| Restores | ✅ | From DB and cluster snapshots, including snapshots shared from other accounts. |
| Point-in-time restore | 🟡 | The restore time is checked against the restorable window, but the data is the source's latest state (no transaction log is kept). |
| Automated backups | 🟡 | An automated snapshot when an instance is created, retained backups after deletion, `DeleteDBInstanceAutomatedBackup`. No daily backups on the emulated clock; backup replication across Regions is not supported. |

## Configuration

| Feature | Status | Details |
| --- | :---: | --- |
| Subnet groups | ✅ | Subnets checked against EC2 (same VPC, at least two Availability Zones); a `default` group from the default VPC. |
| Security groups | ✅ | VPC security groups checked against EC2; the VPC's default group otherwise. Traffic is not filtered. |
| Parameter groups | ✅ | DB and cluster parameter groups with the engines' common parameters, defaults per family, static versus dynamic parameters, `pending-reboot`, resets and copies. Native parameters reach the server at its next start. |
| Option groups | 🟡 | Created, copied and described; options are recorded but have no effect. |
| CA certificates | ✅ | `rds-ca-rsa2048-g1` (default), `rds-ca-rsa4096-g1`, `rds-ca-ecc384-g1`. Connections are not TLS. |
| Catalog | ✅ | Engine versions, major versions, orderable options, account quotas, source Regions. |

## Integrations

| Feature | Status | Details |
| --- | :---: | --- |
| Secrets Manager | ✅ | `ManageMasterUserPassword` creates an `rds!db-...` or `rds!cluster-...` secret owned by RDS, rotated every seven days, on `RotateSecret` or with `RotateMasterUserPassword`; each rotation sets the new password in the running database. |
| KMS | ✅ | Storage encryption with `aws/rds` or a customer key; RDS uses the key as the caller, so disabled keys and key policies give `KMSKeyNotAccessibleFault`. |
| Events | ✅ | `DescribeEvents` (14 days), event categories, event subscriptions publishing to SNS as `rds.amazonaws.com`, and `aws.rds` events on the default EventBridge bus. |
| IAM | ✅ | Every operation authorizes `rds:<Action>` with RDS condition keys (`rds:DatabaseEngine`, `rds:DatabaseClass`, `rds:<kind>-tag/*`, `aws:RequestTag`, ...); role associations check `iam:PassRole`. |
| Tags | ✅ | On every resource, by ARN. |
| Reserved instances, Performance Insights, Enhanced Monitoring, exports to S3 | ❌ | Not yet. |

See also: [all services](README.md) · [configuration](../configuration.md).
