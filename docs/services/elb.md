# Elastic Load Balancing

> Crate: [`mws-elb`](../../crates/services/mws-elb) · Tests: [`elbv2.rs`](../../tests/e2e-rust/tests/e2e/elbv2.rs), [`elbv2_api.rs`](../../tests/e2e-rust/tests/e2e/elbv2_api.rs), [`elb_classic.rs`](../../tests/e2e-rust/tests/e2e/elb_classic.rs), [`elbv2_auth.rs`](../../tests/e2e-rust/tests/e2e/elbv2_auth.rs), [`elb_logs.rs`](../../tests/e2e-rust/tests/e2e/elb_logs.rs)

All 51 ELBv2 operations (Application, Network and Gateway Load Balancers, API
version 2015-12-01) and all 29 Classic Load Balancer operations (2012-06-01),
both awsQuery. Both APIs sign as `elasticloadbalancing` and MWS tells them apart
by `Version`, as AWS does. Listeners are real sockets: requests and connections
reach the registered targets.

✅ supported · 🟡 partial · ❌ not supported

## Control plane

| Feature | Status | Details |
| --- | :---: | --- |
| Load balancers | ✅ | ARNs (`app/`, `net/`, `gwy/`), DNS names and canonical hosted zone ids per Region and type, `internal-` names, subnets resolved through EC2 (ALBs need two Availability Zones), the VPC's default security group, idempotent create, deletion protection, `SetSubnets`, `SetSecurityGroups`, `SetIpAddressType`. |
| Attributes | ✅ | Load balancer, listener and target group attributes with each type's defaults and AWS's value checks. |
| Listeners and rules | ✅ | Protocols per load balancer type, `DuplicateListener`, default rules, priorities and `SetRulePriorities`, condition and action validation (one terminal action, redirect loops, target group VPC and protocol), transforms. |
| Target groups and targets | ✅ | Health check defaults per protocol, `instance`, `ip` (inside the VPC's CIDRs, or `AvailabilityZone: all` for other private ranges), `lambda` and `alb` targets, `ResourceInUse` while a listener forwards to them, draining for `deregistration_delay.timeout_seconds`. |
| Certificates | ✅ | HTTPS and TLS listeners take ISSUED ACM certificates in the same account and Region; ACM reports them in `InUseBy` and refuses to delete them. |
| Trust stores | ✅ | CA bundles and CRLs read from S3 with the caller's permissions, revocations, associations, content links served at `/_aws/elb/trust-stores/`. |
| SSL policies, limits | ✅ | AWS's predefined policies (protocols and ciphers) and account limits. |
| Capacity reservations, IPAM pools | ✅ | Validated and reported; they change nothing locally. |
| Tags and authorization | ✅ | `elasticloadbalancing:*` actions on resource ARNs with `aws:ResourceTag`, `aws:RequestTag` and `elasticloadbalancing:CreateAction`. |
| Resource policies (RAM sharing) | ❌ | Nothing is shared, so `GetResourcePolicy` finds none. |

## Data plane

| Feature | Status | Details |
| --- | :---: | --- |
| Listener sockets | ✅ | Each listener binds `MWS_ELB_BIND` (127.0.0.1) on an ephemeral port, or its own port with `MWS_ELB_LISTENER_PORTS=listener`. `GET /_aws/elb/listeners` lists the addresses; requests to the endpoint whose `Host` is a load balancer's DNS name are served by its HTTP listener. |
| ALB routing | ✅ | Host, path (wildcards), header, method, query string and source IP conditions, regex values, host and URL rewrites, weighted forwards with target group stickiness, redirects with `#{}` placeholders, fixed responses. |
| ALB proxying | ✅ | HTTP/1.1 and HTTP/2 to targets (HTTP or HTTPS), `X-Forwarded-For`/`-Proto`/`-Port` (with the XFF processing modes), `X-Amzn-Trace-Id`, TLS version and cipher headers, preserve-host, round robin, least outstanding requests and weighted random, `AWSALB`/`AWSALBAPP` stickiness, ELB's own error pages (`server: awselb/2.0`). |
| HTTPS and mutual TLS | ✅ | ACM certificates chosen by SNI, protocol versions from the SSL policy, ALPN; mTLS `verify` (trust store and CRLs, `x-amzn-mtls-clientcert-*` headers) and `passthrough`. |
| Lambda targets | ✅ | ALB's Lambda event (single or multi-value headers), invoked as `elasticloadbalancing.amazonaws.com` (the function's policy must allow it, as `RegisterTargets` checks), 1 MB request limit. |
| NLB | ✅ | TCP, TLS (termination and TLS to targets), UDP and TCP_UDP flows, source IP stickiness, proxy protocol v2. |
| Health checks | ✅ | Real HTTP(S), TCP and Lambda probes on each target group's interval, thresholds and matcher; AWS's states and reason codes (`Elb.InitialHealthChecking`, `Target.FailedHealthChecks`, `Target.Timeout`, ...). When no target is healthy, ALB and NLB route to all of them, as AWS fails open. |
| Classic Load Balancers | ✅ | HTTP/HTTPS and TCP/SSL listeners to registered instances, the health check, `InService`/`OutOfService`, LB cookie stickiness (`AWSELB`), proxy protocol policies, SSL negotiation policies. |
| CloudWatch metrics | ✅ | `AWS/ApplicationELB`, `AWS/NetworkELB`, `AWS/GatewayELB` and `AWS/ELB` with AWS's dimensions: request counts, HTTP code classes, response times, connection errors, flows, processed bytes, healthy and unhealthy host counts. |
| Loopback targets | 🟡 | MWS also accepts `127.0.0.0/8` IP targets so processes on the host can sit behind a load balancer; AWS refuses them. |
| Instance targets | 🟡 | Reached at the instance's private IP, so only instances that really run (the EC2 Docker backend) answer. |
| OIDC authentication | ✅ | `authenticate-oidc` runs the authorization code flow: unauthenticated requests are redirected to the IdP (`state`, `scope`, extra params), `/oauth2/idpresponse` exchanges the code at the token endpoint (client secret as HTTP Basic, ID token issuer and audience checked) and reads the user info endpoint, then sets `AWSELBAuthSessionCookie-0` and returns to the original URL. Targets get `x-amzn-oidc-accesstoken`, `-identity` and `-data` (ES256, padded base64url, `signer`/`kid` header); the public keys are served at `public-keys.auth.elb.<region>.amazonaws.com/<kid>` and `/_aws/elb/public-keys/<region>/<kid>`. `deny` answers 401, `allow` passes through, IdP failures answer 561. The client secret is never returned by the API; `UseExistingClientSecret` keeps it. |
| JWT validation | ✅ | `jwt-validation` checks the `Authorization: Bearer` token's signature against the JWKS endpoint (RS256/384/512, ES256/384, cached five minutes), `iss`, `exp`, `nbf` and the additional claims (`single-string`, `string-array`, `space-separated-values`), answering 401 with `WWW-Authenticate: Bearer error=...`. |
| IdP TLS | 🟡 | ELB does not verify the IdP's server certificate, so local IdPs with self-signed certificates work. |
| Cognito authentication | ❌ | MWS has no Cognito user pools, so requests reaching `authenticate-cognito` get a 500. |
| Gateway Load Balancer traffic | ❌ | Traffic reaches a GWLB through Gateway Load Balancer endpoints used as VPC route targets. MWS does not route VPC packets (EC2 containers use Docker networking), so nothing could send GWLB traffic; GENEVE forwarding is therefore not emulated and GWLB listeners exist only in the control plane. |
| Access logs | ✅ | ALB (one line per request, AWS's field order including rule priority, actions run, trace and connection ids), NLB TLS listeners and Classic (HTTP and TCP/SSL) logs, written as AWS names them under `{prefix/}AWSLogs/{account}/elasticloadbalancing/{region}/yyyy/mm/dd/` when each interval (5 minutes; Classic 5 or 60) ends on the emulated clock; gzip except Classic. The bucket policy must allow `logdelivery.elasticloadbalancing.amazonaws.com` or the Region's ELB account; turning logging on writes `ELBAccessLogTestFile` and fails with `Access Denied for bucket` otherwise. |
| Connection logs | ✅ | ALB HTTPS listeners log each TLS handshake (protocol, cipher, latency, client certificate, verify status, connection trace id). |
| Health check logs | ✅ | Application Load Balancers write one line per health check (`type time latency target_addr target_group_id status status_code reason_code`) every 5 minutes under `health_log.` files. |
| Log details | 🟡 | `error_reason` and `classification` are always `-`; `chosen_cert_arn` is the listener's default certificate; byte counts are estimated from headers and `Content-Length`. |
| Security groups on traffic | ✅ | Connections (and UDP datagrams) to a listener are dropped unless one of the load balancer's security groups allows the client address on the listener port, as in a VPC. Clients on the host come from `127.0.0.1`, so a rule for `0.0.0.0/0` or `127.0.0.0/8` lets them in; load balancers made without security groups get the VPC's default group, which lets in only its own members. Network Load Balancers made without security groups are not filtered. `MWS_ELB_SECURITY_GROUPS=off` turns this off. |

See also: [all services](README.md) · [configuration](../configuration.md).
