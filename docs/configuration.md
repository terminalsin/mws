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

EC2 instances reach the instance metadata service and the AWS endpoint
through the host, so when using the Docker backend MWS must listen on an
address containers can reach (the default `0.0.0.0` does).

## Bedrock

What answers Bedrock model invocations. The default echo model is
deterministic and needs no network, so tests can assert on its answers; queue
scripted answers with `POST /_aws/bedrock/responses` (see
[Bedrock](services/bedrock.md#scripted-answers)).

| Variable | Default | Description |
| --- | --- | --- |
| `MWS_BEDROCK_BACKEND` | `echo` | `echo`, `openai` (any OpenAI-compatible chat completions API: OpenAI, Ollama, vLLM, LM Studio) or `anthropic` (the Anthropic Messages API). |
| `MWS_BEDROCK_BACKEND_URL` | `https://api.openai.com/v1` or `https://api.anthropic.com` | Base URL of the provider (for example `http://localhost:11434/v1` for Ollama). |
| `MWS_BEDROCK_BACKEND_API_KEY` | `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` | API key sent to the provider. |
| `MWS_BEDROCK_BACKEND_MODEL` | derived from the Bedrock model id | Provider model to use for every request (for example `llama3.2`). Without it, Anthropic gets the Claude model matching the Bedrock id and OpenAI-compatible servers get the Bedrock id. |
| `MWS_BEDROCK_MODELS` | unset | A JSON file with extra foundation models to add to the catalog (an array in `GetFoundationModel`'s shape plus `family`). |

Embeddings, images and rerank are always answered locally.

## Client-side settings

These are read by the AWS SDKs, not by MWS, but are the usual way to point
an application at it:

| Variable | Typical value |
| --- | --- |
| `AWS_ENDPOINT_URL` | `http://localhost:4566` |
| `AWS_ACCESS_KEY_ID` | `AKIAMWSROOTEXAMPLE00`, or keys created in MWS |
| `AWS_SECRET_ACCESS_KEY` | `mwsRootSecretAccessKeyEXAMPLEKEY00000000` |
| `AWS_REGION`, `AWS_DEFAULT_REGION` | `us-east-1` or any other Region (boto3 and the CLI read `AWS_DEFAULT_REGION`) |
