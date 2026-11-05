# AWS Private Certificate Authority

> Crate: [`mws-acmpca`](../../crates/services/mws-acmpca) · Tests: [`tests/e2e-rust/tests/e2e/acmpca.rs`](../../tests/e2e-rust/tests/e2e/acmpca.rs)

All 23 operations are generated from the AWS model (awsJson1.1) and implemented. Certificates are real X.509 and verify with standard tooling.

✅ supported · 🟡 partial · ❌ not supported

| Feature | Status | Details |
| --- | :---: | --- |
| Root and subordinate CAs | ✅ | Real keys (RSA 2048/3072/4096, EC P-256/P-384/P-521), CSRs, self-issued root certificates, and imports with chain checks. |
| `IssueCertificate` | ✅ | ACM Private CA templates (end-entity, server and client auth, code signing, OCSP, root, subordinate path lengths) and validity rules. |
| Passthrough templates | ✅ | API and CSR passthrough take their extensions from the request and the CSR, with AWS's precedence (template, then API, then CSR). |
| `GetCertificate` | ✅ | Certificates with their chains. |
| Revocation and CRLs | ✅ | CRLs are written into S3 buckets as `acm-pca.amazonaws.com`, so the bucket policy must allow it, as on AWS; refreshed at half their validity. |
| OCSP | 🟡 | Answered, but unsigned. |
| Audit reports | 🟡 | JSON or CSV reports written to S3 as `acm-pca.amazonaws.com`; they complete synchronously. |
| Lifecycle | ✅ | Disable, delete and restore; CAs expire and are permanently deleted on the emulated clock. |
| Permissions and resource policies | ✅ | Evaluated by the IAM engine, scoped by account and Region. |
| Sharing through RAM | ✅ | CAs shared with other accounts or with Connector for SCEP through [RAM](ram.md); the share's policy is evaluated alongside the CA's own, and a `PutPolicy` appears in RAM as a share created from policy. |
| Resource policy actions | 🟡 | Not limited to the actions AWS allows in them. |
| ML-DSA, SM2 and RSA-PSS keys | ❌ | Not supported. |
| EC keys with other hashes | ❌ | Only the natural hash for each curve. |
| Partitioned CRLs | ❌ | `CrlType` is not implemented. |
| Path-length limits | ❌ | Not enforced on subordinate issuance. |

See also: [all services](README.md) · [authentication and authorization](../security.md).
