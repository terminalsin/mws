# Amazon Route 53

> Crate: [`mws-route53`](../../crates/services/mws-route53) · Tests: [`tests/e2e-rust/tests/e2e/route53.rs`](../../tests/e2e-rust/tests/e2e/route53.rs)

All 71 operations are generated from the AWS model (restXml).

## Behaviour

Implemented: public and private hosted zones (create, get, list, list by name
and by VPC, count, comment, delete, VPC associate/disassociate), atomic
`ChangeResourceRecordSets` (CREATE, UPSERT, DELETE with Route 53's
`InvalidChangeBatch` messages, CNAME conflicts, apex rules, record value checks
for A, AAAA, CNAME, NS, PTR, MX, SRV, CAA and TXT, routing policy rules:
`SetIdentifier` with exactly one policy, one policy per name and type, unique
failover roles, regions and locations, and aliases to the zone's own records
must find their target), `ListResourceRecordSets` in Route 53's order with
pagination and `\052` escaping, `GetChange`, health checks that really probe
(HTTP, HTTPS without certificate checks, string matching and TCP, from the first
second and then every `RequestInterval`, turning unhealthy after
`FailureThreshold` failures; calculated checks follow their children; `Inverted`
and `Disabled` apply; CloudWatch alarm checks report their
`InsufficientDataHealthStatus`), traffic policies and instances, DNSSEC
key-signing keys backed by real KMS keys (the key policy must allow
`dnssec-route53.amazonaws.com`; DNSKEY and DS records come from the key's public
key), reusable delegation sets, CIDR collections, query logging configs (the
CloudWatch Logs group must exist and allow Route 53; the DNS responder writes
query logs to it), VPC association authorizations, limits, `TestDNSAnswer`, geo
locations, and tags.

Changes report `PENDING` and then `INSYNC`. Resources belong to the account that
created them: other accounts neither list nor count them, and get `AccessDenied`
for their ids; another account's VPC joins a private zone once the owner
authorizes it, and `ListHostedZonesByVPC` then shows it to that account with the
owner. An optional DNS responder (UDP and TCP) serves every account's zones like
Route 53's name servers: weighted, failover, multivalue, IP-based (the resolver
or EDNS client subnet against the CIDR collection) routing that skips unhealthy
record sets and aliases with `EvaluateTargetHealth`, geolocation from the
default location and latency from `us-east-1` (MWS answers from one place),
wildcards at the closest encloser, CNAMEs followed inside the zone, referrals
for delegated subdomains, SOA in negative answers, truncation and EDNS(0);
`TestDNSAnswer` gives the same answers.

## Known gaps

DNSSEC-signed answers, health check metrics in CloudWatch, CloudWatch alarm
state for alarm-based checks.

See also: [all services](README.md) · [authentication and authorization](../security.md).
