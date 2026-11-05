# AWS Certificate Manager

> Crate: [`mws-acm`](../../crates/services/mws-acm) · Tests: [`tests/e2e-rust/tests/e2e/acm.rs`](../../tests/e2e-rust/tests/e2e/acm.rs)

All 40 operations are generated from the AWS model (awsJson1.1) and implemented. Certificates are real X.509 with real keys.

✅ supported · 🟡 partial · ❌ not supported

## Certificates

| Feature | Status | Details |
| --- | :---: | --- |
| Public certificates | ✅ | Signed by issuing CAs MWS makes for itself (`Amazon RSA 2048 M01`, `Amazon ECDSA 256/384 M01` under `MWS Root CA 1`, so `Issuer` reads `Amazon`), valid for 198 days. |
| DNS validation | ✅ | Real: ACM hands out the per-account CNAME record (wildcards share their base domain's) and issues once the record exists in a public hosted zone in MWS's Route 53. |
| Email validation | ✅ | Sent to the usual five addresses; MWS logs each "validation email" with an approval link (`/_acm/approvals?certificate=<arn>&domain=<domain>`). |
| HTTP validation | ❌ | Not supported (CloudFront only on AWS). |
| Private certificates | ✅ | Issued by MWS's Private CA with the requester's `acm-pca:IssueCertificate` permission (failures show as `PCA_*` reasons) and renewed by `acm.amazonaws.com` when the CA grants it. |
| Imports and exports | ✅ | Imports check that the key (PKCS#8, PKCS#1 or SEC1) matches and support reimport; exports return PBES2-encrypted PKCS#8 for private and exportable public certificates. |
| Lifecycle | ✅ | On the emulated clock: validation times out after 72 hours, certificates expire, managed renewal starts 60 days before expiry. |
| Listing and search | ✅ | `ListCertificates` filters, `SearchCertificates` with nested `And`/`Or`/`Not` statements and every sort key, tags and account configuration. |
| Validation migration | ✅ | `UpdateCertificateOptions` and `ListCertificateDomainValidations` for email-to-DNS migration. |
| IAM condition keys | ✅ | `acm:ValidationMethod`, `acm:DomainNames`, `acm:KeyAlgorithm`, `acm:CertificateAuthority`, `acm:Export` and `aws:ResourceTag`. |
| Integrated services | ❌ | `InUseBy` is always empty. |

## ACME

| Feature | Status | Details |
| --- | :---: | --- |
| Managed ACME endpoints | ✅ | A real RFC 8555 server at `/_acme/<id>/directory` with external account binding (HS256). |
| Prevalidation and orders | ✅ | Domain prevalidations write their CNAME into the hosted zone; orders for covered identifiers are ready at once and issued for the client's own key with key pair origin `ACME`. |
| Accounts | ✅ | Updated, deactivated, rekeyed (`key-change`) and revoked; ACM assumes the binding's role as `acm.amazonaws.com`. |

## Events and metrics

| Feature | Status | Details |
| --- | :---: | --- |
| Expiry events | ✅ | A daily "ACM Certificate Approaching Expiration" event to EventBridge from the account's `DaysBeforeExpiry`. |
| `DaysToExpiry` metric | ✅ | Published to CloudWatch in `AWS/CertificateManager`. |
| Other ACM events | ❌ | Not yet. |

See also: [all services](README.md) · [authentication and authorization](../security.md).
