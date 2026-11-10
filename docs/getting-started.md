# Getting started

This guide takes you from a fresh checkout to an SDK talking to MWS, and then
to calling as identities other than the root user.

## Requirements

- Rust 1.85 or newer (`rustup` recommended).
- Optional: Docker (or Podman) to run Lambda functions in AWS's own runtime
  images (every managed runtime: Node.js, Python, Java, .NET, Ruby, custom)
  and EC2 instances as containers. Without Docker, Lambda's Python and
  Node.js functions run on the `python3` and `node` on `PATH`.

## Build and run

```sh
git clone https://github.com/terminalsin/mws
cd mws
cargo run --release -p mws
```

MWS listens on `0.0.0.0:4566`. Check that it is up:

```sh
curl http://localhost:4566/_mws/health
```

The binary is a single self-contained executable. `cargo build --release -p mws`
leaves it at `target/release/mws` if you want to copy it elsewhere, for
example into a CI image.

## Credentials

MWS starts with one AWS account (`123456789012` unless `MWS_ACCOUNT_ID` says
otherwise) whose root user has these access keys:

| Variable | Value |
| --- | --- |
| `AWS_ACCESS_KEY_ID` | `AKIAMWSROOTEXAMPLE00` |
| `AWS_SECRET_ACCESS_KEY` | `mwsRootSecretAccessKeyEXAMPLEKEY00000000` |

Both can be changed with `MWS_ROOT_ACCESS_KEY_ID` and
`MWS_ROOT_SECRET_ACCESS_KEY`. Requests must be signed with SigV4 by a known
key, exactly as on AWS: unsigned requests and wrong secrets are refused.

Any Region name is accepted. Resources are scoped to the Region a request is
signed for, as on AWS.

## Point an SDK at MWS

Current AWS SDKs and the AWS CLI read `AWS_ENDPOINT_URL`, so the simplest
setup is the environment (`AWS_DEFAULT_REGION` is for boto3 and the CLI,
`AWS_REGION` for the other SDKs):

```sh
export AWS_ENDPOINT_URL=http://localhost:4566
export AWS_ACCESS_KEY_ID=AKIAMWSROOTEXAMPLE00
export AWS_SECRET_ACCESS_KEY=mwsRootSecretAccessKeyEXAMPLEKEY00000000
export AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1
```

### AWS CLI

Use AWS CLI v2. Version 1 ignores `AWS_ENDPOINT_URL` for some commands (such
as `aws sqs`) and sends them to AWS instead.

```sh
aws sts get-caller-identity
aws s3 mb s3://my-bucket
aws s3 cp ./README.md s3://my-bucket/
aws sqs create-queue --queue-name jobs
```

### Python (boto3)

```python
import boto3
from botocore.config import Config

s3 = boto3.client("s3", config=Config(s3={"addressing_style": "path"}))
s3.create_bucket(Bucket="my-bucket")
s3.put_object(Bucket="my-bucket", Key="hello.txt", Body=b"hello")
```

### Rust

```rust
use aws_config::BehaviorVersion;

#[tokio::main]
async fn main() -> Result<(), aws_sdk_s3::Error> {
    // Reads AWS_ENDPOINT_URL, AWS_REGION and the credentials from the environment.
    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let s3 = aws_sdk_s3::Client::from_conf(
        aws_sdk_s3::config::Builder::from(&config).force_path_style(true).build(),
    );
    s3.create_bucket().bucket("my-bucket").send().await?;
    Ok(())
}
```

### JavaScript (AWS SDK v3)

```ts
import { S3Client, CreateBucketCommand } from "@aws-sdk/client-s3";

const s3 = new S3Client({ forcePathStyle: true });
await s3.send(new CreateBucketCommand({ Bucket: "my-bucket" }));
```

## S3 addressing and host prefixes

S3 supports both path-style (`localhost:4566/my-bucket/key`) and
virtual-hosted-style (`my-bucket.localhost:4566/key`) requests. Virtual-hosted
requests only work if `*.localhost` resolves to MWS on your machine, so the
examples above force path-style addressing.

Some SDK calls put a name in front of the endpoint's host, as AWS does:

- S3 Control requests go to `{account-id}.localhost:4566`.
- S3 requests that name an access point or Object Lambda access point ARN go
  to `{name}-{account-id}.localhost:4566`.

Those names must resolve to MWS (wildcard DNS for the endpoint host, or a
custom resolver in the SDK's HTTP client). Access point aliases need no DNS:
they are used as bucket names. Code running inside Lambda functions gets
`AWS_DISABLE_HOST_PREFIX_INJECTION`, so that `WriteGetObjectResponse` goes
straight to the endpoint.

## Calling as other identities

The root user may do everything. To exercise your IAM policies, create
principals and use their credentials, just as you would on AWS:

```sh
aws iam create-user --user-name alice
aws iam put-user-policy --user-name alice --policy-name read-only \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:Get*","Resource":"*"}]}'
aws iam create-access-key --user-name alice     # sign with these keys to act as alice
```

Roles work through STS: `AssumeRole`, `AssumeRoleWithWebIdentity`,
`AssumeRoleWithSAML` and the rest return real temporary credentials that MWS
recognizes. Lambda functions and EC2 instances receive their execution role's
or instance profile's credentials the same way AWS provides them.

Organizations can create member accounts, each with its own IAM namespace and
an `OrganizationAccountAccessRole` you can assume. See
[Authentication and authorization](security.md) for what is enforced.

## Next steps

- [Configuration](configuration.md): every environment variable.
- [State, scenarios and snapshots](state.md): seed data, resets and the
  emulated clock.
- [Testing](testing.md): patterns for using MWS in a test suite.
- [Services](services/README.md): what each service does and its known gaps.
