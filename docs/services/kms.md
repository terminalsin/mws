# AWS Key Management Service

> Crate: [`mws-kms`](../../crates/services/mws-kms) · Tests: [`tests/e2e-rust/tests/e2e/kms.rs`](../../tests/e2e-rust/tests/e2e/kms.rs)

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
| Multi-Region keys | ✅ | Primary keys, replicas and primary region updates. |
| Lifecycle | ✅ | Enable/disable, scheduled deletion, automatic and on-demand rotation (old ciphertexts keep decrypting), all on the emulated clock; aliases, tags and `DryRun`. |
| SM2, `ED25519_PH_SHA_512`, ML-DSA `EXTERNAL_MU` | ❌ | Not supported (SM2 exists only in China Regions). |
| Nitro Enclaves `Recipient` | ❌ | Attestation documents are not supported. |
| Custom key stores | 🟡 | Managed, but never connect (no CloudHSM, no reachable XKS proxy). |

## Access control

| Feature | Status | Details |
| --- | :---: | --- |
| Key policies | ✅ | Evaluated as KMS does: the key policy must allow the caller, directly or by delegating to IAM; the policy lockout safety check applies. |
| Key policy principals | 🟡 | Not checked against IAM, while AWS rejects unknown principals. |
| Grants | ✅ | Grantees, operations and encryption context constraints; grants created through grants. |
| Grant tokens and service principal grants | 🟡 | Grant tokens are ignored, and grants to service principals are not honoured. |
| AWS managed keys | ✅ | `alias/aws/<service>` keys created on first use, as on AWS; `DescribeKey` on a predefined alias creates the key. |
| `ListAliases` | 🟡 | Omits predefined AWS aliases that have no key yet. |
| Use by other services | ✅ | `kms:ViaService`, `kms:CallerAccount` and service principals for S3, SQS, SNS, Secrets Manager, SSM, Logs, Kinesis, Firehose and others. |

See also: [all services](README.md) · [authentication and authorization](../security.md).
