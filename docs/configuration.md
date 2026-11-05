# Configuration

MWS is configured entirely through environment variables. All are optional.

## Server

| Variable | Default | Description |
| --- | --- | --- |
| `MWS_LISTEN` | `0.0.0.0:4566` | Address and port of the HTTP endpoint. Every service and the `/_mws` control API share it. |
| `RUST_LOG` | `info` | Log filter, in [`tracing-subscriber`](https://docs.rs/tracing-subscriber) `EnvFilter` syntax (for example `mws=debug`). |

## Identity

| Variable | Default | Description |
| --- | --- | --- |
| `MWS_ACCOUNT_ID` | `123456789012` | The id of the account MWS starts with. |
| `MWS_ROOT_ACCESS_KEY_ID` | `AKIAMWSROOTEXAMPLE00` | Access key id of that account's root user. |
| `MWS_ROOT_SECRET_ACCESS_KEY` | `mwsRootSecretAccessKeyEXAMPLEKEY00000000` | Its secret access key. |
| `MWS_SKIP_FEDERATION_SIGNATURE_VERIFICATION` | unset | `1` accepts web identity tokens and SAML responses without checking their signatures, for test suites that hand-craft them. By default signatures are verified as AWS verifies them. |

## State

| Variable | Default | Description |
| --- | --- | --- |
| `MWS_DB` | unset (in memory) | Path of a SQLite file, such as `.mws/state.db`, that keeps every service's state across restarts. |
| `MWS_SCENARIO` | unset | A [scenario file](state.md#scenarios) run at startup. Its result becomes the baseline that `POST /_mws/reset` returns to. |

See [State, scenarios and snapshots](state.md) for how the two interact.

## Service integrations

| Variable | Default | Description |
| --- | --- | --- |
| `MWS_DNS_LISTEN` | unset | An address such as `127.0.0.1:5353` starts the Route 53 DNS responder (UDP and TCP), which answers queries from the emulated hosted zones. |
| `MWS_LAMBDA_PYTHON` | `python3.x`, then `python3` from `PATH` | Interpreter that runs Python Lambda functions. |
| `MWS_LAMBDA_NODE` | `node` from `PATH` | Interpreter that runs Node.js Lambda functions. |
| `MWS_EC2_BACKEND` | `auto` | How EC2 instances run. `docker` runs each instance as a container, `metadata` runs nothing (instances only change state), and `auto` uses Docker when a daemon answers and `metadata` otherwise. |
| `MWS_EC2_DOCKER` | `docker` | The Docker-compatible CLI the EC2 backend drives (for example `podman`). |
| `MWS_QUOTA_PROFILE` | `established` | Which [Service Quotas](services/servicequotas.md) values accounts start with. `established` uses AWS's defaults except EC2 vCPU quotas of 1152 per instance class, so many instances can run without increases; `new-account` uses AWS's exact new-account defaults (5 standard vCPUs). |

EC2 instances reach the instance metadata service and the AWS endpoint
through the host, so when using the Docker backend MWS must listen on an
address containers can reach (the default `0.0.0.0` does).

## Client-side settings

These are read by the AWS SDKs, not by MWS, but are the usual way to point
an application at it:

| Variable | Typical value |
| --- | --- |
| `AWS_ENDPOINT_URL` | `http://localhost:4566` |
| `AWS_ACCESS_KEY_ID` | `AKIAMWSROOTEXAMPLE00`, or keys created in MWS |
| `AWS_SECRET_ACCESS_KEY` | `mwsRootSecretAccessKeyEXAMPLEKEY00000000` |
| `AWS_REGION`, `AWS_DEFAULT_REGION` | `us-east-1` or any other Region (boto3 and the CLI read `AWS_DEFAULT_REGION`) |
