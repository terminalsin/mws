# AWS Certificate Manager

> Crate: [`mws-acm`](../../crates/services/mws-acm) · Tests: [`tests/e2e-rust/tests/e2e/acm.rs`](../../tests/e2e-rust/tests/e2e/acm.rs)

All 40 operations are generated from the AWS model (awsJson1.1).

## Behaviour

Certificates are real X.509 with real keys. Public certificates are signed by
issuing CAs MWS makes for itself (`Amazon RSA 2048 M01`, `Amazon ECDSA 256/384
M01` under `MWS Root CA 1`, so `Issuer` reads `Amazon`), valid for 198 days. DNS
validation is real: ACM hands out the per-account CNAME record (wildcards share
their base domain's) and issues once the record exists in a public hosted zone
in MWS's Route 53. Email validation goes to the usual five addresses; MWS logs
each "validation email" with its approval link
(`/_acm/approvals?certificate=<arn>&domain=<domain>`, unsigned) that approves
the domain.

Private certificates (`CertificateAuthorityArn`) are issued by MWS's Private CA
with the requester's `acm-pca:IssueCertificate` permission (failures show as
`PCA_*` failure reasons) and renewed by `acm.amazonaws.com` when the CA grants
it with `CreatePermission`. Imports check that the key (PKCS#8, PKCS#1 or SEC1)
matches the certificate and support reimport; exports return the key as
PBES2-encrypted PKCS#8 under the passphrase, for private and exportable public
certificates, and exported public certificates can be revoked.

The lifecycle follows the emulated clock: validation times out after 72 hours,
certificates expire, and managed renewal starts 60 days before expiry (public
ones renew while their DNS records still validate). Also: email-to-DNS
validation migration (`UpdateCertificateOptions`,
`ListCertificateDomainValidations`), `ListCertificates` filters (RSA_2048 by
default, ACME certificates only when asked), `SearchCertificates` with nested
`And`/`Or`/`Not` filter statements and every sort key, tags, account
configuration, failure reasons for non-public domains, and IAM condition keys
(`acm:ValidationMethod`, `acm:DomainNames`, `acm:KeyAlgorithm`,
`acm:CertificateAuthority`, `acm:Export`, `aws:ResourceTag`).

Managed ACME endpoints run a real RFC 8555 server at `<MWS
endpoint>/_acme/<id>/directory`: external account binding (HS256) is required,
domain prevalidations write their CNAME into the hosted zone as the caller and
become `VALID` once it resolves, orders for covered identifiers are `ready` at
once (`PRE_APPROVED`), and finalized orders are issued for the client's own key
and appear in ACM with key pair origin `ACME`.

ACM assumes the binding's role as `acm.amazonaws.com`, which needs
`acm:RequestCertificate` to order and `acm:RevokeCertificate` to revoke.
Accounts can be updated, deactivated, rekeyed (`key-change`) and revoked. Issued
certificates send a daily "ACM Certificate Approaching Expiration" event to
EventBridge from the account's `DaysBeforeExpiry` on (emulated clock).

## Known gaps

Integrated services (`InUseBy` is always empty), other ACM events, and HTTP
validation (CloudFront only).

See also: [all services](README.md) · [authentication and authorization](../security.md).
