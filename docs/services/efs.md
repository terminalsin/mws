# Amazon EFS

> Crate: [`mws-efs`](../../crates/services/mws-efs) · Tests: [`tests/e2e-rust/tests/e2e/efs.rs`](../../tests/e2e-rust/tests/e2e/efs.rs)

All 31 operations are generated from the AWS model (restJson1). Every file
system is a real directory on the host (`MWS_EFS_DIR`, default `mws-efs` in the
temp directory), and EC2 instances that run in Docker can mount it.

✅ supported · 🟡 partial · ❌ not supported

## File systems

| Feature | Status | Details |
| --- | :---: | --- |
| Create, describe, update, delete | ✅ | Creation tokens (`FileSystemAlreadyExists` names the existing id), `creating` for 2 seconds then `available` (`IncorrectFileSystemLifeCycleState` for mount targets and access points until then), `deleting` for 2 seconds then gone, `FileSystemInUse` while mount targets or a replication exist, marker pagination. Transitions follow the emulated clock, so `/_mws/clock` finishes them at once. The SDKs have no EFS waiters: poll `DescribeFileSystems` |
| Performance and throughput modes | ✅ | `generalPurpose`/`maxIO`, `bursting`/`provisioned`/`elastic`, with AWS's combination checks. For 24 hours after switching to provisioned throughput or increasing it, changing the mode or decreasing it fails with `TooManyRequests` (HTTP 429) |
| One Zone file systems | ✅ | Availability Zone names or ids, backups on by default |
| Encryption | ✅ | `alias/aws/elasticfilesystem` or your KMS key (id, ARN, alias), checked to be an enabled symmetric key |
| `SizeInBytes` | ✅ | Measured from the directory (4 KiB blocks plus the 6 KiB of an empty file system); all Standard storage |
| Backup and lifecycle policies | 🟡 | Stored and validated; no backups are taken and data does not change storage class |
| Replication | ✅ | New or existing destination (overwrite protection off) in any Region; data copied at creation and whenever the configuration is described; destinations are `REPLICATING` and mount read-only |
| Account preferences | ✅ | `SHORT_ID` gives 8-digit ids for new resources |
| Tags | ✅ | `CreateTags`/`DeleteTags`/`DescribeTags` and `TagResource`/`UntagResource`/`ListTagsForResource`, `Name` tag as the name |

## Mount targets and access points

| Feature | Status | Details |
| --- | :---: | --- |
| Mount targets | ✅ | `creating` for 4 seconds (about 90 on AWS; the emulated clock finishes it), then `available`; mounts and security group calls wait for `available`. A requester-managed `efs` network interface in the EC2 subnet, IP from the subnet (or yours), default VPC group or up to five of yours; one per Availability Zone, all in one VPC (`MountTargetConflict`); IPv6 and dual stack when the subnet has an IPv6 block |
| Security groups | ✅ | `DescribeMountTargetSecurityGroups`, `ModifyMountTargetSecurityGroups`; EC2 refuses to delete groups or interfaces in use |
| Access points | ✅ | Root directory with `CreationInfo`, POSIX user, client token idempotency, tags |

## Mounting from instances

Docker-backed instances get the data root shared in at `/var/lib/mws-efs` and a
`mount` helper (also `mount.efs` and `mount.nfs4`) installed at boot, so user
data such as `mount -t nfs4 fs-1234.efs.us-east-1.amazonaws.com:/ /mnt/efs` or
`mount -t efs -o tls,iam,accesspoint=fsap-1234 fs-1234:/ /mnt/efs` works. The
helper asks MWS (`GET /_aws/efs/mount`) and then bind-mounts the directory
(linking it where the container cannot mount).

| Feature | Status | Details |
| --- | :---: | --- |
| Reachability | ✅ | Needs a running instance and an available mount target in its VPC: in its zone for the plain DNS name, any zone for the EFS mount helper, or by mount target IP (`mounttargetip=` too) |
| Security groups | ✅ | The mount target's inbound rules must allow TCP 2049 from the instance's address or groups, or the mount times out |
| File system policy | ✅ | `elasticfilesystem:ClientMount` and `ClientWrite` (read-only otherwise) for anonymous clients or, with `-o iam`, the instance profile role's session; `aws:SecureTransport` follows `tls`, `elasticfilesystem:AccessPointArn` and `AccessedViaMountTarget` are set |
| Access points | ✅ | Root directory created with its owner and mode on first mount; `accesspoint` and `iam` need `tls`, as with the EFS mount helper |
| POSIX user and root squash | ❌ | The access point's POSIX user and `ClientRootAccess` are not enforced on file operations |
| `/etc/fstab` and `mount -a` | ✅ | `mount -a` mounts the `efs`, `nfs` and `nfs4` entries in `/etc/fstab` through the helper and passes the rest to the real `mount` |

## Known gaps

No NFS server: only instances MWS runs in Docker can mount, through the helper,
and [Lambda](lambda.md) functions with `FileSystemConfigs` that run in containers.
Access point POSIX users are not enforced. Backups, storage classes and
throughput limits have no effect.

See also: [all services](README.md) · [EC2](ec2.md) · [authentication and authorization](../security.md).
