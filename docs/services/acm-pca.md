# AWS Private Certificate Authority

> Crate: [`mws-acmpca`](../../crates/services/mws-acmpca) · Tests: [`tests/e2e-rust/tests/e2e/acmpca.rs`](../../tests/e2e-rust/tests/e2e/acmpca.rs)

All 23 operations are generated from the AWS model (awsJson1.1).

## Behaviour

Implemented: root and subordinate CAs with real keys (RSA 2048/3072/4096, EC
P-256/P-384/P-521), CSRs, self-issued root certificates, import with chain
checks, `IssueCertificate` with ACM PCA templates (end-entity, server/client
auth, code signing, OCSP, root, subordinate path lengths), validity rules,
`GetCertificate` with chains, revocation, disable/delete/restore, tags,
permissions, and CA resource policies evaluated by the IAM engine.

Certificates verify with standard X.509 tooling. CRLs and audit reports (JSON or
CSV) are written into S3 buckets as `acm-pca.amazonaws.com`, so the bucket
policy must allow it as in AWS (checked when the CRL bucket is configured and
when a report is requested); OCSP is answered unsigned. API passthrough and CSR
passthrough templates take their extensions from the request and the CSR, with
AWS's precedence (template, then API, then CSR), and CAs expire, refresh their
CRLs and are permanently deleted on the emulated clock.

## Known gaps

ML-DSA, SM2 and RSA-PSS keys, EC keys with a hash other than the natural one for
their curve, partitioned CRLs, path-length limits enforced on subordinate
issuance, and resource policies limited to the allowed actions; audit reports
complete synchronously.

See also: [all services](README.md) · [authentication and authorization](../security.md).
