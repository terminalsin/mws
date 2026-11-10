# AWS Key Management Service

> Crate: [`mws-kms`](../../crates/services/mws-kms) · Tests: [`tests/e2e-rust/tests/e2e/kms.rs`](../../tests/e2e-rust/tests/e2e/kms.rs), [`kms_lifecycle.rs`](../../tests/e2e-rust/tests/e2e/kms_lifecycle.rs), [`kms_xks.rs`](../../tests/e2e-rust/tests/e2e/kms_xks.rs)

All 56 operations are generated from the AWS model (awsJson1.1) and implemented. Keys do real cryptography: results check out in standard tooling.

✅ supported · 🟡 partial · ❌ not supported

## Keys and cryptography

| Feature | Status | Details |
| --- | :---: | --- |
| Symmetric keys | ✅ | AES-256-GCM, bound to the encryption context; `Decrypt` finds the key from the ciphertext. |
| Asymmetric keys | ✅ | RSA, ECC (P-256/384/521, secp256k1), Ed25519 and ML-DSA keys sign and verify; RSA keys encrypt. |
| HMAC, ECDH and ML-KEM | ✅ | `GenerateMac`/`VerifyMac`, `DeriveSharedSecret`, and key encapsulation. |
| Data keys | ✅ | Data keys and data key pairs, with and without plaintext; `ReEncrypt`, `GenerateRandom`. |
| Imported key material | ✅ | All wrapping algorithms, expiry, re-import of the same material only. |
| Multi-Region keys | ✅ | Primary keys, replicas and primary region updates. As on AWS these finish asynchronously: a new replica is `Creating`, and during `UpdatePrimaryRegion` both keys are `Updating` (still usable for cryptography, but not enabled, disabled, deleted or replicated), until the settle window passes (`MWS_ASYNC_DELAY_MS`, default 500 ms, on the emulated clock); operations they block fail with `KMSInvalidStateException` ("... is creating." / "... is updating."). `ReplicateKey` also needs `kms:CreateKey` in the replica Region, from IAM policies. |
| Lifecycle | ✅ | Enable/disable, scheduled deletion, automatic and on-demand rotation (old ciphertexts keep decrypting), all on the emulated clock; aliases, tags and `DryRun`. |
| SM2, `ED25519_PH_SHA_512`, ML-DSA `EXTERNAL_MU` | ❌ | Not supported (SM2 exists only in China Regions). |
| Nitro Enclaves `Recipient` | ❌ | Attestation documents are not supported. |
| External key stores | ✅ | Real XKS proxies: connecting checks the proxy's health over HTTPS with SigV4-signed requests (`kms-xks-proxy`) and reports AWS's connection error codes; `CreateKey` asks the proxy for the external key's metadata (`XksKeyNotFoundException`, `XksKeyInvalidConfigurationException`, `XksKeyAlreadyInUseException`); keys double encrypt, first with KMS key material and then through the proxy, which sees each request's metadata. Proxies on other ports or with private CAs: `MWS_KMS_XKS_CONNECT_TO` and `MWS_KMS_XKS_CA_FILE`. |
| CloudHSM key stores | ❌ | There is no CloudHSM cluster to connect to (`CloudHsmClusterNotFoundException`). |

## Access control

| Feature | Status | Details |
| --- | :---: | --- |
| Tags on new keys | ✅ | `CreateKey` and `ReplicateKey` with `Tags` also need `kms:TagResource` on the new key from IAM policies (there is no key policy yet), with `aws:RequestTag` conditions. |
| Key policies | ✅ | Evaluated as KMS does: the key policy must allow the caller, directly or by delegating to IAM; the policy lockout safety check applies. |
| Key policy principals | ✅ | IAM users and roles a key policy names must exist ("Policy contains a statement with one or more invalid principals."). |
| Grants | ✅ | Grantees, operations and encryption context constraints; grants created through grants. |
| Service principal grants | ✅ | Grants to a service principal (`GranteeServicePrincipal`) let that service use the key when the key policy doesn't. |
| Grant tokens | 🟡 | Accepted and ignored: MWS grants take effect immediately, so tokens are never needed. |
| AWS managed keys | ✅ | `alias/aws/<service>` keys created on first use, as on AWS; `DescribeKey` on a predefined alias creates the key. |
| `ListAliases` | ✅ | Lists the predefined AWS aliases, without a target key until a service creates it. |
| Use by other services | ✅ | `kms:ViaService`, `kms:CallerAccount` and service principals for S3, SQS, SNS, Secrets Manager, SSM, Logs, Kinesis, Firehose and others. |

See also: [all services](README.md) · [authentication and authorization](../security.md).
