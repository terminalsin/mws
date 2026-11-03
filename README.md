# MWS

A lightweight local stand-in for AWS, written in Rust, for testing code that
talks to AWS. Point an unmodified AWS SDK at it and it should behave like the
real service: same wire protocol, same validation messages, same error codes,
real SigV4 authentication.

It is not meant to carry load or store data durably. It is meant to tell you
whether your code would work against AWS.

## Status

| Service | State |
| --- | --- |
| IAM | All 180 operations are generated from the AWS model and validate input like AWS. Users and access keys are implemented; the rest return `NotImplemented`. |
| STS | Planned (step 2) |
| Route 53 | Planned (step 3) |
| Private CA | Planned (step 4) |

Authentication is real: requests must carry a valid SigV4 signature (header or
presigned URL) from a known access key. Authorization currently allows every
authenticated call; real IAM policy evaluation arrives in step 2.

## Running

```sh
cargo run -p mws            # listens on 0.0.0.0:4566
```

| Variable | Default |
| --- | --- |
| `MWS_LISTEN` | `0.0.0.0:4566` |
| `MWS_ACCOUNT_ID` | `123456789012` |
| `MWS_ROOT_ACCESS_KEY_ID` | `AKIAMWSROOTEXAMPLE00` |
| `MWS_ROOT_SECRET_ACCESS_KEY` | `mwsRootSecretAccessKeyEXAMPLEKEY00000000` |
| `RUST_LOG` | `info` |

Then use any SDK or the CLI with the endpoint overridden:

```sh
export AWS_ENDPOINT_URL=http://localhost:4566
export AWS_ACCESS_KEY_ID=AKIAMWSROOTEXAMPLE00
export AWS_SECRET_ACCESS_KEY=mwsRootSecretAccessKeyEXAMPLEKEY00000000
export AWS_REGION=us-east-1
aws iam create-user --user-name alice
aws iam create-access-key --user-name alice   # these keys now authenticate as alice
```

## Layout

```
crates/
  mws-core          service-agnostic contracts: ServiceError, RequestContext, Caller,
                    Authorizer, CredentialStore, Service
  mws-sigv4         SigV4 verification (header + presigned query)
  mws-smithy        reads Smithy JSON AST models
  mws-codegen       generates server stubs from Smithy models (build-time)
  mws-proto-query   awsQuery protocol runtime (form decoding, XML, errors)
  mws-server        HTTP front door: authenticates, routes by signing name
  mws               the binary; the only crate that knows which services exist
  services/
    mws-iam         IAM: model/iam.json + behaviour
tests/
  e2e-rust          official Rust SDK against an in-process MWS
  e2e-python        boto3 against the mws binary
```

Each service is its own crate that depends only on generic crates. Shared
crates are protocol or infrastructure code, never service logic.

## Testing

```sh
cargo test --workspace
cargo build -p mws && pip install -r tests/e2e-python/requirements.txt && pytest tests/e2e-python
```
