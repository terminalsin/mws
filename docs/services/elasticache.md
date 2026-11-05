# Amazon ElastiCache

> Crate: [`mws-elasticache`](../../crates/services/mws-elasticache) · Tests: [`tests/e2e-rust/tests/e2e/elasticache.rs`](../../tests/e2e-rust/tests/e2e/elasticache.rs), [`elasticache_docker.rs`](../../tests/e2e-rust/tests/e2e/elasticache_docker.rs)

All 77 operations are generated from the AWS model (awsQuery) and implemented. With the Docker backend every cache node is a real Valkey, Redis OSS or Memcached container that MWS configures over RESP, so applications connect to the endpoints ElastiCache describes and get a working cache.

✅ supported · 🟡 partial · ❌ not supported

## Engines and backends

| Feature | Status | Details |
| --- | :---: | --- |
| Docker backend | ✅ | `MWS_ELASTICACHE_BACKEND=docker` runs each node as a container (`valkey/valkey`, `redis`, `memcached` images matching the engine version; override with `MWS_ELASTICACHE_REDIS_IMAGE`, `_VALKEY_IMAGE`, `_MEMCACHED_IMAGE`). Memory limits come from the node type, parameters from the parameter group (Memcached connections are capped at 4096 in containers). Podman works too. |
| Metadata backend | ✅ | `MWS_ELASTICACHE_BACKEND=metadata` runs nothing: resources become `available` at once, endpoints use the engines' default ports. |
| Engine versions | ✅ | Valkey 7.2–8.1, Redis OSS 4.0–7.1 and Memcached 1.4–1.6, with their parameter group families and `DescribeCacheEngineVersions`. Redis OSS 7.1 runs the 7.2 image. |
| Endpoints | 🟡 | Nodes, primary, reader and configuration endpoints answer on `MWS_ELASTICACHE_HOST` (default `127.0.0.1`), each on its own port rather than 6379/11211, so many clusters can coexist. Primary and reader endpoints are proxies that follow failovers. |

## Clusters and replication groups

| Feature | Status | Details |
| --- | :---: | --- |
| Cache clusters | ✅ | Memcached clusters with up to 40 nodes (added and removed by `ModifyCacheCluster`), standalone Valkey/Redis OSS nodes, reboots, node type scaling lists, maintenance and snapshot windows, notification topics. |
| Replication groups | ✅ | Primary plus up to 5 replicas wired with `REPLICAOF`, `IncreaseReplicaCount`/`DecreaseReplicaCount`, adding clusters as read replicas, Multi-AZ and automatic failover flags, `TestFailover` that really promotes a replica. |
| Cluster mode | ✅ | Up to 500 shards with slot ranges, nodes joined with `CLUSTER MEET`/`ADDSLOTSRANGE`/`REPLICATE`, a configuration endpoint, and online resharding (`ModifyReplicationGroupShardConfiguration`) that migrates slots and keys. |
| AUTH tokens | ✅ | `requirepass` on the nodes; `ROTATE` keeps the old token valid until `SET` or `DELETE`. |
| Users and user groups (RBAC) | ✅ | Access strings applied with `ACL SETUSER` on every node, password and no-password users, the `default` user requirement, groups attached to replication groups and serverless caches. |
| Parameter groups | ✅ | Every Valkey/Redis OSS/Memcached family with their parameters, allowed values and defaults; changes reach running nodes with `CONFIG SET`. |
| Subnet groups | ✅ | Subnets and VPCs read from EC2 (`InvalidSubnet` for unknown ones); a default group in the default VPC. |
| Cache security groups | ✅ | As for current accounts (no EC2-Classic): creation is refused and the rest answer `CacheSecurityGroupNotFound`. |
| Encryption in transit | 🟡 | Recorded and validated (AUTH needs it, as in AWS), but nodes do not serve TLS. |
| Encryption at rest | 🟡 | Recorded only. |
| Restricted commands | ❌ | `CONFIG`, `SHUTDOWN` and other commands ElastiCache blocks are allowed. |
| Engine upgrades | 🟡 | Versions change in the metadata; running nodes keep their image. |
| Memcached auto discovery | ❌ | `config get cluster` is not answered. |

## Snapshots and serverless

| Feature | Status | Details |
| --- | :---: | --- |
| Snapshots | ✅ | Manual and final snapshots capture every key (`DUMP`), with their TTLs, from each shard; restoring into clusters or groups of any shape routes keys to their slots. `CopySnapshot` with `TargetBucket` exports RDB files to S3 as `elasticache.amazonaws.com`, which the bucket policy must allow; `SnapshotArns` seeds new groups from RDB files in S3. |
| Automatic snapshots | 🟡 | Retention limits and windows are recorded; snapshots are not taken on schedule. |
| Serverless caches | ✅ | Valkey, Redis OSS and Memcached serverless caches with endpoint and reader endpoint, usage limits, snapshots (create, copy, export to S3, restore), user groups. |
| Online migration | ✅ | `StartMigration` replicates from your self-managed endpoint with `REPLICAOF`; `TestMigration` checks it answers; `CompleteMigration` promotes the group. Serverless `PrepareMigration`/`StopMigration` track state only. |
| Global datastores | ✅ | Primary and secondary groups across Regions with settings copied from the primary, failover between Regions, node group changes applied to every member. Secondaries of cluster mode disabled groups really replicate from the primary. |

## Other

| Feature | Status | Details |
| --- | :---: | --- |
| Tags | ✅ | On every resource, checked against its ARN; `aws:RequestTag`/`aws:ResourceTag` conditions. |
| Events | ✅ | `DescribeEvents` with source, time window and duration filters; notifications published to SNS topics. |
| Reserved nodes | ✅ | Offerings for every node type, duration and payment option; purchases are recorded. |
| Service updates | ✅ | Engine patch updates with update actions per group or cluster, node-level status, `BatchApplyUpdateAction`/`BatchStopUpdateAction`. |
| IAM | ✅ | Every operation authorizes `elasticache:<Action>` with ElastiCache's condition keys (`CacheNodeType`, `EngineVersion`, `TransitEncryptionEnabled`, ...). IAM authentication for users is not supported. |
| CloudWatch metrics and log delivery | ❌ | Not published; log delivery configurations are recorded only. |
| EC2 instances reaching nodes | ❌ | Nodes listen on the host, not inside the emulated VPC's Docker network. |

See also: [all services](README.md) · [authentication and authorization](../security.md).
