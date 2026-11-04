# app-config

How a service loads its configuration and protects sensitive data.

- [`src/setup.ts`](src/setup.ts) is what a deployment pipeline would create: a
  KMS key with an alias, a Secrets Manager secret with database credentials,
  and a Parameter Store hierarchy (`String`, `StringList`, `SecureString`).
- [`src/config.ts`](src/config.ts) loads `/<app>/<stage>/...` with the
  `GetParametersByPath` paginator and decryption, the database credentials
  (any version stage), and reads a secret through
  `/aws/reference/secretsmanager/...`.
- [`src/envelope.ts`](src/envelope.ts) encrypts records locally with
  AES-256-GCM under KMS data keys, bound to an encryption context.

The tests cover typed loading, pagination past 10 parameters, encrypted
`SecureString` values, `AWSCURRENT`/`AWSPREVIOUS` across a rotation, envelope
round trips, `InvalidCiphertextException` for the wrong context, and an IAM
user that can read parameters but is denied the KMS key.
