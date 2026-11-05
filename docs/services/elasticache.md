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
| Encryption in transit | ✅ | Nodes with `TransitEncryptionEnabled` (and every serverless cache) listen with TLS only, replicate and run the cluster bus over TLS, and present a certificate from MWS's own CA: fetch it from `GET /_aws/elasticache/ca.pem` (unsigned) and trust it, for example `redis-cli --tls --cacert ca.pem`. Turning it on or off for a running cluster-mode-disabled group switches the nodes' listeners in place. `preferred` mode behaves like `required`: one port can't speak both. |
| Encryption at rest | 🟡 | Recorded only. |
| Restricted commands | ✅ | `BGREWRITEAOF`, `BGSAVE`, `CONFIG`, `DEBUG`, `MIGRATE`, `REPLICAOF`, `SAVE`, `SHUTDOWN` and `SLAVEOF` answer `ERR unknown command`, as on ElastiCache (nodes start with them renamed; MWS reaches them under the new names). `PSYNC`/`SYNC` and the restricted `CLUSTER` subcommands still run, because replication and the cluster bus need them. |
| Engine upgrades | ✅ | A new `EngineVersion` (or Redis OSS to Valkey) replaces every node with a container of the new image on the same port: the group is `modifying` meanwhile, its data is read first and loaded back (Memcached nodes come back empty, as on ElastiCache), and an `Engine version upgraded to ...` event follows. |
| Memcached auto discovery | ✅ | A Memcached cluster's configuration endpoint answers `config get cluster` with the current nodes and a version that changes as nodes are added or removed, and passes other commands through to a node, so auto discovery clients follow the cluster. The nodes' own endpoints don't answer it. |

## Snapshots and serverless

| Feature | Status | Details |
| --- | :---: | --- |
| Snapshots | ✅ | Manual and final snapshots capture every key (`DUMP`), with their TTLs, from each shard; restoring into clusters or groups of any shape routes keys to their slots. `CopySnapshot` with `TargetBucket` exports RDB files to S3 as `elasticache.amazonaws.com`, which the bucket policy must allow; `SnapshotArns` seeds new groups from RDB files in S3. |
| Automatic snapshots | ✅ | With `SnapshotRetentionLimit` above 0, an `automated` snapshot named `automatic.<id>-<yyyy-mm-dd-hh-mm>` is taken in each daily `SnapshotWindow` (serverless caches: `DailySnapshotTime`) on the emulated clock, so advancing the clock past a window takes one. Snapshots older than the retention limit are deleted, as are a cluster's automatic snapshots when it is deleted; copies stay. |
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
| CloudWatch metrics | ✅ | `AWS/ElastiCache` metrics per node (`CacheClusterId`, `CacheNodeId`) every minute on the emulated clock, from the nodes' own `INFO` and `stats`: `CPUUtilization`, `EngineCPUUtilization`, `FreeableMemory`, `BytesUsedForCache`, `DatabaseMemoryUsagePercentage`, `CurrConnections`, `NewConnections`, `CurrItems`, `CacheHits`, `CacheMisses`, `CacheHitRate`, `GetTypeCmds`, `SetTypeCmds`, `Evictions`, `Reclaimed`, `NetworkBytesIn`/`Out`, `IsMaster`, `ReplicationLag`, `ReplicationBytes`, `MemoryFragmentationRatio`, and Memcached's `GetHits`, `GetMisses`, `CmdGet`, `CmdSet`, `BytesUsedForCacheItems`, ... Serverless caches publish by `clusterId`, with `ElastiCacheProcessingUnits` counted as one per command. With the metadata backend nodes report as idle. |
| Log delivery | ✅ | Slow logs (`SLOWLOG`) and engine logs (the server's output) are delivered every few seconds, in `json` or `text`, to CloudWatch Logs log groups (streams `<cluster>-<node>-slow-log` / `-engine-log`) or to Firehose streams. Delivery to CloudWatch Logs adds `delivery.logs.amazonaws.com` to the account's `AWSLogDeliveryWrite20150319` resource policy, as AWS does; Firehose streams must carry the tag `LogDeliveryEnabled=true`. A destination that refuses the logs (missing log group, untagged stream) turns the configuration's status to `error` with the reason. MWS's own commands stay out of slow logs. Docker backend only. |
| EC2 instances reaching nodes | 🟡 | Nodes join their subnet group VPC's Docker network (the one EC2's Docker backend runs that VPC's instances on), where instances reach them as `<cluster-id>-<node-id>` on the node's port. The network has to exist when the node starts, so nodes started before the VPC's first instance stay on the host only. Security groups are not enforced on the node side, and the endpoints ElastiCache describes (`127.0.0.1`) are for the host. |

See also: [all services](README.md) · [authentication and authorization](../security.md).
