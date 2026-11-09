# Amazon EC2 and Amazon VPC

> Crate: [`mws-ec2`](../../crates/services/mws-ec2) · Tests: [`tests/e2e-rust/tests/e2e/ec2.rs`](../../tests/e2e-rust/tests/e2e/ec2.rs), [`ec2_gateways.rs`](../../tests/e2e-rust/tests/e2e/ec2_gateways.rs), [`ec2_capacity.rs`](../../tests/e2e-rust/tests/e2e/ec2_capacity.rs)

279 of the model's 811 operations are generated (ec2Query) and implemented; the rest answer `NotImplemented`. Responses use EC2's filters, pagination, `DryRun`, id formats and `InvalidXxx.Malformed`/`.NotFound` errors.

✅ supported · 🟡 partial · ❌ not supported

## Networking

| Feature | Status | Details |
| --- | :---: | --- |
| Default VPC | ✅ | Every account and Region starts with one: 172.31.0.0/16, a default subnet per Availability Zone, an internet gateway, the main route table, and the default network ACL, security group and DHCP options. |
| VPCs and subnets | ✅ | Secondary CIDR blocks, DNS attributes, CIDR checks against the VPC and its other subnets, five reserved addresses, `MapPublicIpOnLaunch`. |
| Security groups | ✅ | Rules with `sgr-` ids, the legacy flat form and `IpPermissions`, group references, `ModifySecurityGroupRules`, descriptions, duplicate and limit errors. |
| Route tables and gateways | ✅ | Routes to internet gateways, NAT gateways on Elastic IPs, interfaces and instances; main and subnet associations. |
| Network ACLs, DHCP options, interfaces, Elastic IPs | ✅ | Managed with EC2's rules. |
| NAT gateways | ✅ | On Elastic IPs; deleting one leaves blackhole routes, and deleted gateways stay listed for an hour. Internet gateways cannot be detached while the VPC has public addresses. |
| Elastic IP reverse DNS | ✅ | `ModifyAddressAttribute`, `DescribeAddressesAttribute`, `ResetAddressAttribute`. |
| Gateway endpoints | ✅ | S3 and DynamoDB: routes to the service's AWS-managed prefix list (`pl-63a5400a` for S3 in us-east-1, as in AWS) in the route tables named; one per service and VPC. |
| Interface endpoints | ✅ | A requester-managed interface per subnet (one per Availability Zone) in the endpoint's security groups, regional and zonal `vpce.amazonaws.com` DNS entries, private DNS (on by default) that needs the VPC's DNS support and hostnames and conflicts with another private-DNS endpoint for the service. `DescribeVpcEndpointServices` lists about 45 AWS services. |
| Endpoint policies | 🟡 | Stored, changed and reset; not enforced. Private DNS names are not resolved inside instances (they reach MWS through `AWS_ENDPOINT_URL`). |
| Prefix lists | ✅ | AWS-managed lists, and customer-managed lists with versions (`ModifyManagedPrefixList` with `CurrentVersion`, entries at any version, associations), usable in security group rules and routes. |
| Security groups filter traffic | ✅ | With the Docker backend: stateful ingress and egress rules by CIDR, prefix list or referenced group (every interface in it), protocol, ports, ICMP type and code, written as iptables rules into each instance's network namespace by a short-lived helper container (`MWS_EC2_NETFILTER_IMAGE`) and kept in step with VPC changes. `MWS_EC2_FIREWALL=off` turns filtering off. |
| Network ACLs filter traffic | ✅ | Stateless, by rule number, for traffic crossing the subnet's boundary, replies included (return traffic needs ephemeral ports, as in AWS). |
| Routes decide traffic leaving the VPC | ✅ | Longest prefix first: an internet gateway route works for instances with a public address, a NAT gateway route while the gateway is available and its subnet routes to an attached internet gateway, gateway endpoint routes work, blackhole and missing routes drop. |
| Unfiltered traffic | 🟡 | MWS itself (APIs and instance metadata) and DNS are always reachable, as metadata and the Amazon DNS server are in AWS; so a private subnet reaches the AWS APIs without a NAT gateway or endpoint. IPv6 is not filtered (Docker networks are IPv4). |
| IPv6 | 🟡 | Amazon-provided /56 blocks on VPCs, /64 blocks on subnets, IPv6 addresses on interfaces and egress-only internet gateways. Docker networks are IPv4, so IPv6 carries no traffic. |
| Interface addressing | ✅ | Secondary private IPs and /28 prefixes (`AssignPrivateIpAddresses`), IPv6 addresses, subnet CIDR reservations, `DescribeNetworkInterfaceAttribute`. |
| VPC peering | 🟡 | Requests, accept, reject, delete, expiry and the failed state for overlapping CIDRs, across accounts and Regions, with options; routes need an active connection. Control plane only: peered VPCs carry no traffic between Docker instances. |
| Transit gateways | 🟡 | Gateways with default association and propagation route tables, VPC, VPN and peering attachments, associations, propagations (VPC CIDRs and VPN static routes), static and blackhole routes, `SearchTransitGatewayRoutes`. Control plane only: no traffic. Connect, multicast and policy tables are not implemented. |
| Site-to-Site VPN | 🟡 | Customer gateways, virtual private gateways (attach, detach, route propagation), VPN connections with tunnel options, the customer gateway configuration and static routes. No tunnels come up. |
| Carrier gateways | 🟡 | Created, described and deleted, and usable as route targets. |
| Flow logs | 🟡 | Configuration for VPCs, subnets, interfaces and transit gateways is stored and validated; no flow log records are written. |
| VPC endpoint services (PrivateLink) | ✅ | Services behind Network or Gateway Load Balancers (checked against ELB, zones taken from them), allowed principals, cross-account interface and Gateway Load Balancer endpoints that wait in `pendingAcceptance`, accept/reject, private DNS names (verification always succeeds: MWS does not look the TXT record up). Endpoints get interfaces and DNS names; traffic is not carried through them. |
| Private NAT gateways | ❌ | Not yet. |

## Compute

| Feature | Status | Details |
| --- | :---: | --- |
| Key pairs | ✅ | RSA and ED25519 with real key material and AWS's fingerprints; imports. |
| AMIs | ✅ | A public catalogue (Amazon Linux, Ubuntu, Debian, a small Alpine image) whose ids match SSM's `/aws/service/ami-*` parameters; `CreateImage`, `RegisterImage` with `ImageLocation: docker:<image>`, `CopyImage`, launch permissions. |
| Instances | ✅ | EC2's states (terminated instances stay visible for an hour on the emulated clock), private IPs from their subnet, private DNS names, public IPs, root volumes, stop and termination protection, attributes and metadata options. |
| Docker backend | ✅ | The default (`MWS_EC2_BACKEND=auto`) uses Docker whenever a daemon answers, and `MWS_EC2_BACKEND=docker` always does. If no daemon answers when MWS starts (Docker Desktop not open yet), MWS logs a warning, launches instances without containers and keeps asking every two seconds; once the daemon answers, new instances run as containers without restarting MWS (instances launched before stay container-less). Each instance runs as a container: the AMI's image on a Docker network per VPC with the instance's IP and hostname, CPU and memory limits from the instance type, the key pair in `authorized_keys`, user data at first boot, `docker logs` as console output, `CreateImage` as `docker commit`. Podman works too. |
| Metadata backend | ✅ | `MWS_EC2_BACKEND=metadata` runs nothing; instances only change state. |
| Instance metadata service | ✅ | `/_aws/ec2/metadata/<instance-id>/` with IMDSv1 and IMDSv2 tokens, network, placement, public keys, tags, user data and the identity document. |
| Launch extensions | ✅ | Other services add to launches: [EFS](efs.md) shares its file systems into Docker instances and installs a mount helper; its mount targets are requester-managed interfaces in your subnets. |
| Instance profiles | ✅ | Role credentials assumed by `ec2.amazonaws.com`; `RunInstances` checks `iam:PassRole`. |
| Quotas | ✅ | Pending and running instances count against the On-Demand vCPU quota of their instance class (1152 vCPUs per class by default, or AWS's new-account 5 standard vCPUs with `MWS_QUOTA_PROFILE=new-account`: `VcpuLimitExceeded`), and Elastic IPs, VPCs and security group rules against theirs; raise them with [Service Quotas](servicequotas.md). |
| EBS volumes and snapshots | ✅ | Volumes, snapshots and their copies, modifications, attributes, sharing, locks, archive tiers, fast snapshot restores, the Recycle Bin, encryption by default and root volume replacement. With the Docker backend each volume is a Docker volume mounted at its device path in the instance, and snapshots copy its data. |
| Launch templates | ✅ | Versions (from a source version), `$Latest` and `$Default`, `ModifyLaunchTemplate`, `GetLaunchTemplateData`; `RunInstances` with a launch template merges its data under the call's parameters and tags instances with `aws:ec2launchtemplate:*`. |
| Spot Instances | 🟡 | `RequestSpotInstances` (one-time and persistent, `ValidFrom`/`ValidUntil`, maximum prices), `DescribeSpotInstanceRequests` and `CancelSpotInstanceRequests`, with AWS's states and status codes (`pending-evaluation`, `fulfilled`, `price-too-low`, `instance-terminated-by-user`, `request-canceled-and-instance-running`, ...). Spot `RunInstances` makes a request too and fails with `SpotMaxPriceTooLow` below the market. Requests are re-evaluated whenever they are described: persistent requests launch again after their instance ends. MWS never interrupts Spot Instances, and launch and Availability Zone groups are stored only. |
| Spot market | 🟡 | `DescribeSpotPriceHistory` from a simulated market: each instance type, zone and product has a deterministic price between 25% and 45% of its On-Demand rate (us-east-1 list prices) that changes every six hours on the emulated clock. |
| Spot Fleet | 🟡 | `RequestSpotFleet` with launch specifications (comma-separated subnets and zones) or launch templates with overrides, weighted capacity, On-Demand capacity, the `lowestPrice`, `diversified`, capacity-optimized and prioritized strategies; `maintain` fleets replace instances that end; `ModifySpotFleetRequest` launches or terminates the difference; `CancelSpotFleetRequests` with or without terminating; history; `aws:ec2spot:fleet-request-id` tags. Load balancer registration and capacity rebalancing are not done. |
| EC2 Fleet | 🟡 | `CreateFleet` of type `instant` (launches and reports instances and errors, honouring minimum target capacity), `request` and `maintain` (replaces instances that end), On-Demand and Spot capacity with weighted overrides and allocation strategies, `ModifyFleet`, `DeleteFleets`, `DescribeFleetInstances`, `DescribeFleetHistory`, `aws:ec2:fleet-id` tags. Capacity reservations and `InstanceRequirements` (attribute-based selection) are not supported. |
| Instance extras | ✅ | Credit specifications for burstable types, `GetPasswordData` (empty without a Windows password), `GetInstanceUefiData` for UEFI instances. |
| Dedicated Hosts | ✅ | `AllocateHosts` for an instance type or a whole family (sockets, cores and vCPUs of AWS's host sizes), auto-placement, `RunInstances` with `Placement.HostId` or `Tenancy: host`, capacity per instance type from the instances on the host, `ModifyHosts`, `ReleaseHosts` (refused while occupied; released hosts stay listed for an hour) and `ModifyInstancePlacement` for stopped instances. Host reservations and host resource groups are not supported. |
| Reserved Instances | 🟡 | `DescribeReservedInstancesOfferings` from a catalogue priced off the On-Demand rates (Standard and Convertible, one and three years, No/Partial/All Upfront, Region or zone scope, default or dedicated tenancy), `PurchaseReservedInstancesOffering` (queued until `PurchaseTime`), `DescribeReservedInstances` (retired when the term ends on the emulated clock). Purchases skip `payment-pending`; no billing discount is applied and the Marketplace, modifications and exchanges are not supported. |

## Terminal and files

The console's Terminal and Files tabs for a running instance use `/_aws/ec2/instances/<instance-id>/...`. This endpoint is MWS's own, not an AWS API. It needs `ssm:StartSession` on the instance ARN, the permission Session Manager asks for. Only the Docker backend has a machine to connect to; the metadata backend answers 409. The Logs tab shows `GetConsoleOutput`.

Requests are SigV4 signed like any AWS call. Each one runs a short `sh` script in the container with `docker exec` as root; it is not an interactive PTY. The routes, relative to the resource:

| Request | Effect |
| --- | --- |
| `POST exec` `{"command", "cwd"?}` | Runs a command. Returns `{"stdout", "stderr", "exitCode", "cwd"}`; `cwd` is the directory after the command, so `cd` carries over. |
| `GET files?path=` | Lists a directory: name, `file`/`dir`/`link`, size, modified time, mode. |
| `GET file?path=` | Returns the file's bytes, up to 8 MiB. `x-mws-truncated` is set when the file is longer. |
| `PUT file?path=` | Writes the body to the file, creating its directory. |
| `DELETE file?path=` | Removes the file or directory. |
| `POST dir?path=` | Creates a directory. |

## Access control

| Feature | Status | Details |
| --- | :---: | --- |
| Authorization errors | ✅ | `UnauthorizedOperation` with an encoded message that `sts:DecodeAuthorizationMessage` decodes. |
| Tags | ✅ | Tags on create, `CreateTags`, `DeleteTags` and `DescribeTags`. |

See also: [all services](README.md) · [authentication and authorization](../security.md).
