# AWS Global Accelerator

> Crate: [`mws-globalaccelerator`](../../crates/services/mws-globalaccelerator) · Tests: [`tests/e2e-rust/tests/e2e/globalaccelerator.rs`](../../tests/e2e-rust/tests/e2e/globalaccelerator.rs)

All 56 operations are generated from the AWS model (awsJson1.1). Global
Accelerator is a global service: ARNs have no Region
(`arn:aws:globalaccelerator::<account>:accelerator/<id>`), and any Region in the
client works.

✅ supported · 🟡 partial · ❌ not supported

## Accelerators

| Feature | Status | Details |
| --- | :---: | --- |
| Static IP addresses | ✅ | Two IPv4 addresses per accelerator, one from each network zone (`75.2.0.0/17`, `99.83.128.0/17`), never shared between accelerators or accounts, kept for the accelerator's life |
| Dual stack | ✅ | `DUAL_STACK` adds two IPv6 addresses (`2600:9000:a...`) and a `DualStackDnsName`; switching back releases them |
| DNS names | ✅ | `a<16 hex>.awsglobalaccelerator.com` and `a<16 hex>.dualstack.awsglobalaccelerator.com` |
| Deployment status | ✅ | Every change sets `IN_PROGRESS`; it becomes `DEPLOYED` a second later on the emulated clock |
| Delete rules | ✅ | `AcceleratorNotDisabledException` until the accelerator is disabled and deployed, `AssociatedListenerFoundException` while it has listeners |
| Idempotency tokens | ✅ | A repeated `IdempotencyToken` returns the resource it made |
| Flow log attributes | 🟡 | Stored and validated (a bucket is required when enabled); no flow logs are written, since no traffic flows |
| Route 53 aliases | ✅ | Alias records to an accelerator's DNS name (hosted zone `Z2BJ6XQ5FK7U4H`) answer with its IPv4 addresses, and the dual-stack name with IPv6 too, in `TestDNSAnswer` and the DNS responder |
| Tags | ✅ | Accelerators and cross-account attachments, with `aws:RequestTag`/`aws:ResourceTag` conditions |
| Limits | ✅ | 20 accelerators per account, 10 listeners per accelerator, 10 port ranges per listener, 10 endpoints per endpoint group |

## Listeners and endpoint groups

| Feature | Status | Details |
| --- | :---: | --- |
| Listeners | ✅ | TCP and UDP port ranges (unique per protocol on an accelerator, `InvalidPortRangeException`), client affinity |
| Endpoint groups | ✅ | One per Region per listener; traffic dial, health check port (defaults to the lowest listener port), protocol, path, interval (10 or 30), threshold, port overrides on listener ports |
| Endpoint validation | ✅ | Ids must be ALB/NLB ARNs, instance ids or Elastic IP allocation ids; instances and Elastic IPs must exist in EC2 in the group's Region; load balancers must be in that Region, and Application Load Balancers can't sit behind UDP |
| Endpoint health | ✅ | `INITIAL` for a second after an endpoint is added, then from EC2: a running instance (or an Elastic IP on one) is `HEALTHY`, a stopped or terminated one `UNHEALTHY` with a reason |
| Load balancer endpoints | ✅ | Application and Network Load Balancers must exist in Elastic Load Balancing; they are `HEALTHY` while active with at least one healthy target, `UNHEALTHY` with a reason otherwise |
| Client IP preservation | ✅ | Defaults per endpoint type (on for ALBs and instances); refused for Elastic IPs |

## Custom routing

| Feature | Status | Details |
| --- | :---: | --- |
| Subnet endpoints | ✅ | Real VPC subnets from EC2; each gets a block of listener ports (addresses × destination ports) at the lowest free offset, so mappings stay put as other subnets come and go |
| Port mappings | ✅ | `ListCustomRoutingPortMappings` (paginated, per endpoint group) and `ListCustomRoutingPortMappingsByDestination` with the accelerator's socket addresses |
| Traffic allow/deny | ✅ | Denied by default; allow or deny all, or by addresses and ports, applied in order |
| Capacity checks | ✅ | A subnet that doesn't fit the listener's free ports is refused; a listener can't shrink below its mapped ports |

## BYOIP and cross-account

| Feature | Status | Details |
| --- | :---: | --- |
| BYOIP ranges | 🟡 | `/8`–`/24` ranges move through `PENDING_PROVISIONING` → `READY` → `PENDING_ADVERTISING` → `ADVERTISING` (and back, and to `DEPROVISIONED`) on the emulated clock, with events; the ROA and signed authorization message are not verified |
| BYOIP addresses on accelerators | ✅ | `IpAddresses` must be in a range the account (or an attachment) provides; a range in use can't be deprovisioned |
| Cross-account attachments | ✅ | Principals (accounts or accelerator ARNs) and resources (endpoints the owner has, or its BYOIP ranges); adding another account's endpoint needs an attachment that names you, `AccessDeniedException` otherwise |
| Shared resource listings | ✅ | `ListCrossAccountResourceAccounts` and `ListCrossAccountResources` |

## Not emulated

| Feature | Status | Details |
| --- | :---: | --- |
| Data plane | ❌ | The static IPs don't carry traffic, so there are no flow logs, and health comes from the endpoints' state rather than real health checks. |

See also: [all services](README.md) · [authentication and authorization](../security.md).
