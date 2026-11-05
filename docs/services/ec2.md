# Amazon EC2 and Amazon VPC

> Crate: [`mws-ec2`](../../crates/services/mws-ec2) · Tests: [`tests/e2e-rust/tests/e2e/ec2.rs`](../../tests/e2e-rust/tests/e2e/ec2.rs)

107 of the model's 811 operations are generated (ec2Query) and implemented; the rest answer `NotImplemented`. Responses use EC2's filters, pagination, `DryRun`, id formats and `InvalidXxx.Malformed`/`.NotFound` errors.

✅ supported · 🟡 partial · ❌ not supported

## Networking

| Feature | Status | Details |
| --- | :---: | --- |
| Default VPC | ✅ | Every account and Region starts with one: 172.31.0.0/16, a default subnet per Availability Zone, an internet gateway, the main route table, and the default network ACL, security group and DHCP options. |
| VPCs and subnets | ✅ | Secondary CIDR blocks, DNS attributes, CIDR checks against the VPC and its other subnets, five reserved addresses, `MapPublicIpOnLaunch`. |
| Security groups | ✅ | Rules with `sgr-` ids, the legacy flat form and `IpPermissions`, group references, `ModifySecurityGroupRules`, descriptions, duplicate and limit errors. |
| Route tables and gateways | ✅ | Routes to internet gateways, NAT gateways on Elastic IPs, interfaces and instances; main and subnet associations. |
| Network ACLs, DHCP options, interfaces, Elastic IPs | ✅ | Managed with EC2's rules. |
| Traffic filtering | 🟡 | Security groups, network ACLs and routes do not filter real traffic; VPCs are isolated by their Docker networks. |
| VPC endpoints, peering, transit gateways | ❌ | Not yet. |

## Compute

| Feature | Status | Details |
| --- | :---: | --- |
| Key pairs | ✅ | RSA and ED25519 with real key material and AWS's fingerprints; imports. |
| AMIs | ✅ | A public catalogue (Amazon Linux, Ubuntu, Debian, a small Alpine image) whose ids match SSM's `/aws/service/ami-*` parameters; `CreateImage`, `RegisterImage` with `ImageLocation: docker:<image>`, `CopyImage`, launch permissions. |
| Instances | ✅ | EC2's states (terminated instances stay visible for an hour on the emulated clock), private IPs from their subnet, private DNS names, public IPs, root volumes, stop and termination protection, attributes and metadata options. |
| Docker backend | ✅ | `MWS_EC2_BACKEND=docker` runs each instance as a container: the AMI's image on a Docker network per VPC with the instance's IP and hostname, CPU and memory limits from the instance type, the key pair in `authorized_keys`, user data at first boot, `docker logs` as console output, `CreateImage` as `docker commit`. Podman works too. |
| Metadata backend | ✅ | `MWS_EC2_BACKEND=metadata` runs nothing; instances only change state. |
| Instance metadata service | ✅ | `/_aws/ec2/metadata/<instance-id>/` with IMDSv1 and IMDSv2 tokens, network, placement, public keys, tags, user data and the identity document. |
| Instance profiles | ✅ | Role credentials assumed by `ec2.amazonaws.com`; `RunInstances` checks `iam:PassRole`. |
| Quotas | ✅ | Pending and running instances count against the On-Demand vCPU quota of their instance class (1152 vCPUs per class by default, or AWS's new-account 5 standard vCPUs with `MWS_QUOTA_PROFILE=new-account`: `VcpuLimitExceeded`), and Elastic IPs, VPCs and security group rules against theirs; raise them with [Service Quotas](servicequotas.md). |
| EBS volumes and snapshots | 🟡 | Metadata only; volumes are not mounted. |
| Launch templates, Spot, Auto Scaling | ❌ | Not yet. |

## Access control

| Feature | Status | Details |
| --- | :---: | --- |
| Authorization errors | ✅ | `UnauthorizedOperation` with an encoded message that `sts:DecodeAuthorizationMessage` decodes. |
| Tags | ✅ | Tags on create, `CreateTags`, `DeleteTags` and `DescribeTags`. |

See also: [all services](README.md) · [authentication and authorization](../security.md).
