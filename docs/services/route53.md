# Amazon Route 53

> Crate: [`mws-route53`](../../crates/services/mws-route53) · Tests: [`tests/e2e-rust/tests/e2e/route53.rs`](../../tests/e2e-rust/tests/e2e/route53.rs)

All 71 operations are generated from the AWS model (restXml) and implemented. Resources belong to the account that created them; other accounts neither list nor count them and get `AccessDenied` for their ids.

✅ supported · 🟡 partial · ❌ not supported

## Hosted zones and records

| Feature | Status | Details |
| --- | :---: | --- |
| Public and private hosted zones | ✅ | Create, get, list (by name and by VPC), count, comment and delete; VPC associations, including another account's VPC once the owner authorizes it. |
| `ChangeResourceRecordSets` | ✅ | Atomic CREATE, UPSERT and DELETE with Route 53's `InvalidChangeBatch` messages, CNAME conflicts, apex rules and value checks for A, AAAA, CNAME, NS, PTR, MX, SRV, CAA and TXT. |
| Routing policies | ✅ | Weighted, failover, multivalue, latency, geolocation and IP-based records, with Route 53's rules (one `SetIdentifier` policy, unique failover roles, valid regions and locations). |
| Aliases | ✅ | Aliases to the zone's own records must find their target; `EvaluateTargetHealth`. |
| `ListResourceRecordSets` | ✅ | Route 53's ordering, pagination and `\052` escaping. |
| Changes | ✅ | `GetChange` reports `PENDING`, then `INSYNC`. |
| Traffic policies and instances | ✅ | Versions, instances and their records. |
| Delegation sets, CIDR collections, geo locations, limits, tags | ✅ | As in Route 53. |

## Health checks

| Feature | Status | Details |
| --- | :---: | --- |
| Probing | ✅ | HTTP, HTTPS (without certificate checks), string matching and TCP, from the first second and then every `RequestInterval`, unhealthy after `FailureThreshold` failures. |
| Calculated checks | ✅ | Follow their children; `Inverted` and `Disabled` apply. |
| CloudWatch alarm checks | 🟡 | Report their `InsufficientDataHealthStatus`; the alarm's actual state is not read. |
| Health check metrics | ❌ | Not published to CloudWatch. |

## DNS

| Feature | Status | Details |
| --- | :---: | --- |
| DNS responder | ✅ | Optional (`MWS_DNS_LISTEN`), UDP and TCP, serving every account's zones like Route 53's name servers: routing policies that skip unhealthy records, wildcards at the closest encloser, CNAMEs followed inside the zone, referrals, SOA in negative answers, truncation and EDNS(0). |
| Geolocation and latency | 🟡 | Answered from the default location and from `us-east-1`, since MWS answers from one place; IP-based routing uses the resolver or EDNS client subnet. |
| `TestDNSAnswer` | ✅ | Gives the same answers as the responder. |
| Query logging | ✅ | The CloudWatch Logs group must exist and allow Route 53; the responder writes query logs to it. |
| DNSSEC key-signing keys | ✅ | Backed by real KMS keys (the key policy must allow `dnssec-route53.amazonaws.com`); DNSKEY and DS records come from the key. |
| DNSSEC-signed answers | ❌ | The responder does not sign answers. |

See also: [all services](README.md) · [authentication and authorization](../security.md).
