# Amazon EKS

> Crate: [`mws-eks`](../../crates/services/mws-eks) · Tests: [`tests/e2e-rust/tests/e2e/eks.rs`](../../tests/e2e-rust/tests/e2e/eks.rs)

All 70 operations of the EKS model (restJson1) are implemented. EKS manages
the control plane's metadata and the AWS resources a cluster owns: the cluster
security group, managed node groups as real Auto Scaling groups of EC2 instances, their IAM instance
profiles and access entries. No Kubernetes API server runs behind the cluster
endpoint.

Resources move through EKS's states (`CREATING`, `UPDATING`, `DELETING`) and
settle on the next request, so SDK waiters (`ClusterActive`,
`NodegroupActive`, `AddonDeleted`, ...) pass on their first poll. Every handler
authorizes `eks:<Action>` on the resource ARN with `aws:ResourceTag/*`,
`aws:RequestTag/*` and `aws:TagKeys`, and roles passed to EKS need
`iam:PassRole` (with `iam:PassedToService`) and a trust policy for the right
service principal.

✅ supported · 🟡 partial · ❌ not supported

## Clusters

| Feature | Status | Details |
| --- | :---: | --- |
| Create, describe, list, delete | ✅ | Kubernetes 1.28–1.35 (default 1.34), platform versions, standard and extended support windows. |
| VPC configuration | ✅ | Subnets must exist, share a VPC and span two Availability Zones; endpoint access and public CIDRs; service CIDR avoids the VPC range. |
| Cluster security group | ✅ | `eks-cluster-sg-<name>-<n>` created in the VPC with a self-referencing rule, tagged `kubernetes.io/cluster/<name>=owned`, deleted with the cluster. |
| Endpoint, OIDC issuer, certificate authority | ✅ | `https://<id>.gr7.<region>.eks.amazonaws.com`, `https://oidc.eks.<region>.amazonaws.com/id/<id>`, a real self-signed `kubernetes` CA. |
| `UpdateClusterConfig` | ✅ | Endpoint access, VPC, logging, access config, upgrade policy, zonal shift, Auto Mode, remote networks, deletion protection, control plane scaling; one kind of change per call. |
| `UpdateClusterVersion` | ✅ | Next minor version only, node version skew check unless `force`. |
| Updates | ✅ | `DescribeUpdate`, `ListUpdates` (per node group, add-on or capability), `CancelUpdate`. |
| Envelope encryption | ✅ | `AssociateEncryptionConfig` once per cluster. |
| Cluster versions | ✅ | `DescribeClusterVersions` with status and support dates. |
| Certificate authority rotation | ✅ | Create, activate, delete and list CAs; the cluster bundle carries every distributed CA. |
| EKS Connector | ✅ | `RegisterCluster` (pending, activation code) and `DeregisterCluster`; `ListClusters include=all`. |
| Insights | 🟡 | Computed from cluster state (version skew, add-on compatibility, AL2 end of support, deprecated APIs), not from a running cluster. |

## Managed node groups

| Feature | Status | Details |
| --- | :---: | --- |
| Auto Scaling group | ✅ | Each node group is a real EC2 Auto Scaling group `eks-<nodegroup>-<uuid>` over its subnets, with a mixed instances policy (one override per instance type), EKS's tags propagated to the nodes, and the cluster security group. |
| EKS launch template | ✅ | An `eks-<uuid>` launch template with the EKS AMI, the node instance profile, IMDS hop limit 2 and the `<cluster>-<nodegroup>-Node` name; deleted with the node group. |
| EKS-optimized AMIs | ✅ | AL2023 and AL2 x86_64/arm64 images per Kubernetes version, matching `/aws/service/eks/optimized-ami/...` SSM parameters; `releaseVersion`. |
| AMI type defaults and checks | ✅ | AL2023 by default, ARM for Graviton instance types, AL2 refused above 1.32. |
| Instance profiles | ✅ | One per node group for the node role, deleted with it. |
| Scaling | ✅ | `UpdateNodegroupConfig` resizes the Auto Scaling group; sizes changed on the group itself (by the Cluster Autoscaler, say) show in the node group. |
| Version updates | ✅ | `UpdateNodegroupVersion` writes a new launch template version and replaces every node from it, with `AZRebalance` suspended while it does. |
| Group health | ✅ | A deleted group (`AutoScalingGroupNotFound`) or suspended processes (`AutoScalingGroupInvalidConfiguration`) degrade the node group, and version updates fail with `NodeCreationFailure` until the processes are resumed. |
| Labels, taints, update config, node repair | ✅ | Stored and returned, with EKS's validation. |
| Remote access | ✅ | A `eks-remoteAccess-*` security group opening SSH when no source groups are given. |
| Customer launch templates | ✅ | Copied into EKS's launch template: their instance type, user data, block devices, security groups and AMI (for `CUSTOM`) are kept, and EKS adds the instance profile. |
| Spot capacity | 🟡 | The group's instances distribution and capacity rebalancing are set for Spot, but Auto Scaling launches on demand. |

## Access, identity and add-ons

| Feature | Status | Details |
| --- | :---: | --- |
| Access entries | ✅ | Standard, EC2, Fargate and hybrid types, default usernames, the creator's admin entry, node and Fargate entries added automatically; `CONFIG_MAP` clusters refuse them. |
| Access policies | ✅ | The AWS-managed cluster access policies, cluster and namespace scopes. |
| OIDC identity providers | ✅ | One per cluster, associate and disassociate through updates. |
| Pod Identity | ✅ | Associations with trust checks for `pods.eks.amazonaws.com`, target roles, session tags; add-on owned associations. |
| Add-ons | ✅ | 12 AWS add-ons with versions per Kubernetes minor, configuration schemas, `configurationValues` validation, Pod Identity for their service accounts. |
| Fargate profiles | ✅ | Selectors, subnets, pod execution role trust; no pods run. |
| Capabilities | 🟡 | ACK, kro and Argo CD resources and updates; nothing is deployed. |
| EKS Anywhere subscriptions | ✅ | Terms, licenses, auto renew, expiry, the seven-day delete window. |
| Tags | ✅ | On every taggable resource, with EKS's limits. |

## Not emulated

| Feature | Status | Details |
| --- | :---: | --- |
| Kubernetes API | ❌ | No API server or kubelet runs, so `kubectl` cannot reach the endpoint and nodes, Fargate pods, add-ons and capabilities run no workloads. |
| Control plane logs | ❌ | Logging settings are stored; nothing is written to CloudWatch Logs. |
| Events and metrics | ❌ | EKS publishes no EventBridge events or CloudWatch metrics. |

See also: [all services](README.md) · [EC2 and VPC](ec2.md) · [authentication and authorization](../security.md).
