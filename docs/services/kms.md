# AWS Key Management Service

> Crate: [`mws-kms`](../../crates/services/mws-kms) · Tests: [`tests/e2e-rust/tests/e2e/kms.rs`](../../tests/e2e-rust/tests/e2e/kms.rs)

All 56 operations are generated from the AWS model (awsJson1.1).

## Behaviour

Keys do real cryptography: symmetric keys encrypt with AES-256-GCM and bind the
encryption context, `Decrypt` finds the key from the ciphertext, and RSA, ECC
(P-256/384/521, secp256k1), Ed25519, ML-DSA, HMAC, ECDH and ML-KEM keys sign,
verify, encrypt, MAC, agree and encapsulate with results that check out in
standard tooling. Data keys and data key pairs, `ReEncrypt`, `GenerateRandom`,
aliases, tags, enable/disable, scheduled deletion (on the emulated clock),
automatic and on-demand rotation (old ciphertexts keep decrypting), imported key
material (all wrapping algorithms, expiry, re-import of the same material only),
multi-Region keys and replicas, and `DryRun`.

Key policies are evaluated the way KMS does (the key policy must allow the
caller, directly or by delegating to IAM), with the policy lockout safety check,
and grants (with encryption context constraints) allow their grantees. Other
services use KMS keys through the crate's API (`kms:ViaService`, AWS managed
`alias/aws/*` keys, service principals).

## Known gaps

Not supported: SM2 (China Regions only), Nitro Enclaves `Recipient`,
`ED25519_PH_SHA_512` and ML-DSA `EXTERNAL_MU`; custom key stores can be managed
but never connect (no CloudHSM, no reachable XKS proxy). Key policy principals
are not checked against IAM (AWS rejects unknown principals), `ListAliases`
omits predefined AWS aliases that have no key yet, grants to service principals
are not honoured, and grant tokens are ignored.

See also: [all services](README.md) · [authentication and authorization](../security.md).
