# Amazon EC2 and Amazon VPC

> Crate: [`mws-ec2`](../../crates/services/mws-ec2) · Tests: [`tests/e2e-rust/tests/e2e/ec2.rs`](../../tests/e2e-rust/tests/e2e/ec2.rs)

107 of the model's 811 operations are generated (ec2Query) and implemented; the
rest answer `NotImplemented`.

## Behaviour

Every account and Region starts with EC2's default VPC (172.31.0.0/16, a default
subnet per Availability Zone, an internet gateway, the main route table, the
default network ACL, security group and DHCP options). VPCs (secondary CIDR
blocks, DNS attributes), subnets (CIDR checks against the VPC and its other
subnets, five reserved addresses, `MapPublicIpOnLaunch`), security groups and
their rules (`sgr-` ids, the legacy flat form and `IpPermissions`, group
references, `ModifySecurityGroupRules`, descriptions, duplicate and limit
errors), route tables (routes to gateways, NAT gateways, interfaces and
instances; main and subnet associations), internet gateways, NAT gateways on
Elastic IPs, network ACLs and entries, DHCP options, network interfaces, Elastic
IPs, key pairs (RSA and ED25519 with real key material and AWS's fingerprints;
imports), AMIs (a public catalogue with Amazon Linux, Ubuntu, Debian and a small
Alpine image, whose ids match SSM's `/aws/service/ami-*` parameters;
`CreateImage`, `RegisterImage` with `ImageLocation: docker:<image>`,
`CopyImage`, launch permissions), EBS volumes and snapshots (metadata), tags and
`DescribeTags`, with EC2's filters, pagination, `DryRun`, id formats and
`InvalidXxx.Malformed`/`.NotFound` errors.

Instances go through EC2's states (`pending`, `running`, `stopping`, `stopped`,
`shutting-down`, `terminated`, visible for an hour after termination on the
emulated clock) with private IPs from their subnet, private DNS names, public
IPs when the subnet or interface asks, root volumes, termination and stop
protection, attributes and metadata options. What runs an instance is a
pluggable compute backend (`MWS_EC2_BACKEND`): `docker` runs each instance as a
container (the AMI's container image, on a Docker network per VPC with the
instance's private IP and hostname, CPU and memory limits from the instance
type, the key pair's public key in `authorized_keys`, user data run once at
first boot, `docker logs` as the console output, `CreateImage` as `docker
commit`; `MWS_EC2_DOCKER=podman` works too), `metadata` runs nothing.

Instances reach the instance metadata service at
`/_aws/ec2/metadata/<instance-id>/` (IMDSv1 and IMDSv2 tokens, `meta-data/` with
network, placement, public keys and tags, user data, the identity document)
through `AWS_EC2_METADATA_SERVICE_ENDPOINT`, with their instance profile's role
credentials assumed by `ec2.amazonaws.com` (`RunInstances` checks
`iam:PassRole`), and MWS itself through `AWS_ENDPOINT_URL`. Authorization
failures are `UnauthorizedOperation` with an encoded message that
`sts:DecodeAuthorizationMessage` decodes.

## Known gaps

Security groups, network ACLs and routes do not filter real traffic (VPCs are
isolated by their Docker networks), volumes are not mounted, launch templates,
Spot, Auto Scaling, VPC endpoints, peering, transit gateways and the other 700
operations.

See also: [all services](README.md) · [authentication and authorization](../security.md).
