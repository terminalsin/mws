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
| `MWS_LAMBDA_RUNTIME_EXECUTOR` | `auto` | What runs Lambda functions of managed runtimes (`nodejs*`, `python*`, `java*`, `dotnet*`, `ruby*`, `provided*`). `docker` runs each execution environment as a container of AWS's own Lambda base image for the runtime (`public.ecr.aws/lambda/nodejs:22`, ...), pulled on first use; `local` runs Python and Node.js functions on local interpreters and custom runtimes' `bootstrap` directly (Java, .NET and Ruby need `docker`); `auto` uses Docker when a daemon answers and local interpreters otherwise, or when the image cannot be pulled. |
| `MWS_LAMBDA_IMAGE_REPOSITORY` | `public.ecr.aws/lambda` | Where the base images come from (a mirror with the same repository names and tags). |
| `MWS_LAMBDA_DOCKER_NETWORK` | `host` on Linux, `bridge` elsewhere | How Lambda containers reach MWS. `host` shares the host's network; `bridge` points the Runtime API and `AWS_ENDPOINT_URL` at `host.docker.internal`, which Docker Desktop routes to the host. |
| `MWS_LAMBDA_PYTHON` | `python3.x`, then `python3` from `PATH` | Interpreter that runs Python Lambda functions as local processes. |
| `MWS_LAMBDA_NODE` | `node` from `PATH` | Interpreter that runs Node.js Lambda functions as local processes. |
| `MWS_LAMBDA_DOCKER` | `docker` | The Docker-compatible CLI that runs Lambda containers (for example `podman`). |
| `MWS_EC2_BACKEND` | `auto` | How EC2 instances run. `docker` runs each instance as a container, `metadata` runs nothing (instances only change state), and `auto` uses Docker when a daemon answers and `metadata` otherwise. `auto` keeps checking in the background, so a daemon started after MWS (Docker Desktop, colima, OrbStack) is picked up for later launches. |
| `MWS_EC2_DOCKER` | `docker` | The Docker-compatible CLI the EC2 backend drives (for example `podman`). |
| `MWS_QUOTA_PROFILE` | `established` | Which [Service Quotas](services/servicequotas.md) values accounts start with. `established` uses AWS's defaults except EC2 vCPU quotas of 1152 per instance class, so many instances can run without increases; `new-account` uses AWS's exact new-account defaults (5 standard vCPUs). |
| `MWS_EC2_FIREWALL` | `on` | With the Docker backend, whether security groups, network ACLs and route tables filter instances' traffic (`off` leaves it unfiltered). |
| `MWS_EC2_NETFILTER_IMAGE` | `rancher/klipper-lb:v0.4.13` | The helper image (any image with `/bin/sh` and `iptables-restore`) that writes instances' firewall rules into their network namespaces. |
| `MWS_EC2_HELPER_IMAGE` | `alpine:3.20` | With the Docker backend, the small image that copies EBS volume data when snapshots are taken and volumes are restored or copied. |
| `MWS_ELB_BIND` | `127.0.0.1` | Address load balancer listeners bind. `GET /_aws/elb/listeners` lists where each listener is. |
| `MWS_ELB_LISTENER_PORTS` | `ephemeral` | `listener` binds each listener on its own port (80, 443, ...) when free, falling back to an ephemeral port; `ephemeral` always picks a free port. |
| `MWS_ELB_SECURITY_GROUPS` | `on` | `off` stops load balancers dropping connections their security groups don't allow. |
| `MWS_SES_SMTP_LISTEN` | unset | An address such as `127.0.0.1:2525` starts the SES SMTP listener: unauthenticated mail goes to receipt rules, and clients authenticating with SES SMTP credentials send through SES. |
| `MWS_SSM_SESSION_LISTEN` | unset | The address of the Session Manager data channel listener (for example `0.0.0.0:4580`). By default it binds a free port on the endpoint's host when the first session starts. |
| `MWS_KMS_XKS_CONNECT_TO` | unset | `host=address` pairs (comma-separated) that send KMS's requests for an external key store proxy at `https://host` to `address` (for example `xks.example.com=127.0.0.1:8443`), since AWS only allows port 443. |
| `MWS_KMS_XKS_CA_FILE` | unset | A PEM file of extra CA certificates KMS trusts for external key store proxies. |
| `MWS_SES_AUTO_VERIFY` | unset | `1` verifies SES identities as soon as they are created, without DNS records or verification links. |
| `MWS_RDS_BACKEND` | `auto` | How RDS databases run. `docker` runs each DB instance (or Aurora cluster) as a PostgreSQL, MySQL or MariaDB container, `metadata` runs nothing (resources only change state), and `auto` uses Docker when a daemon answers and `metadata` otherwise. |
| `MWS_RDS_DOCKER` | `MWS_EC2_DOCKER`, then `docker` | The Docker-compatible CLI the RDS backend drives. |
| `MWS_RDS_BIND` | `127.0.0.1` | The host address database ports are published on. Endpoints report this address and the published port. |
| `MWS_EKS_BACKEND` | `auto` | What runs EKS clusters' Kubernetes API servers. `k3s` runs a k3s server container per cluster, `metadata` runs none (clusters are EKS metadata only), and `auto` uses k3s when a Docker daemon answers and `metadata` otherwise. |
| `MWS_EKS_DOCKER` | `MWS_EC2_DOCKER`, then `docker` | The Docker-compatible CLI the EKS backend drives. |
| `MWS_EKS_BIND` | `127.0.0.1` | The host address API server ports are published on; cluster endpoints report it. |
| `MWS_EKS_K3S_IMAGE` | `rancher/k3s:<tag for the version>` | The API server image; `{version}` is replaced by the cluster's Kubernetes minor version. |
| `MWS_EFS_DIR` | `mws-efs` in the temp directory | Where EFS keeps file system data, one directory per file system. EC2 instances in Docker mount it at `/var/lib/mws-efs`. |
| `MWS_CODEARTIFACT_<CONNECTION>_URL` | the public registry | Where a CodeArtifact external connection fetches packages, such as `MWS_CODEARTIFACT_NPMJS_URL=http://localhost:4873` for `public:npmjs` (or `_PYPI_URL`, `_MAVEN_CENTRAL_URL`, `_CRATES_IO_URL`, `_RUBY_GEMS_ORG_URL`; `_NUGET_ORG_URL` names a V3 service index). An empty value turns the connection off. |
| `MWS_ECR_REGISTRY_HOST` | unset (AWS's `<account>.dkr.ecr.<region>.amazonaws.com`) | The registry host ECR repository URIs and `proxyEndpoint` name, such as `localhost:4566`, so `docker push $(repositoryUri)` reaches MWS. `{account}` and `{region}` are replaced. |
| `MWS_ECR_PUBLIC_REGISTRY_HOST` | unset (`public.ecr.aws`) | The registry host and path ECR Public repository URIs name, such as `localhost:4566/public.ecr.aws`. |
| `MWS_ELASTICACHE_BACKEND` | `auto` | How ElastiCache nodes run. `docker` runs each node as a Valkey, Redis OSS or Memcached container, `metadata` runs nothing, and `auto` uses Docker when a daemon answers. |
| `MWS_ELASTICACHE_DOCKER` | `docker` | The Docker-compatible CLI the ElastiCache backend drives. |
| `MWS_ELASTICACHE_HOST` | `127.0.0.1` | The address ElastiCache endpoints name; node ports are published on the host. |
| `MWS_ELASTICACHE_REDIS_IMAGE`, `MWS_ELASTICACHE_VALKEY_IMAGE`, `MWS_ELASTICACHE_MEMCACHED_IMAGE` | by engine version | Images to run instead of `redis:<version>-alpine`, `valkey/valkey:<version>-alpine` and `memcached:1.6-alpine`. |
| `MWS_ECR_UPSTREAM_ENDPOINTS` | unset | Comma-separated `host=url` pairs that point ECR pull-through cache upstreams at other API bases, such as `quay.io=http://127.0.0.1:5000/v2`, instead of `https://<host>/v2`. |

EC2 instances reach the instance metadata service and the AWS endpoint
through the host, and EKS API servers call MWS's token and authorization
webhooks at `host.docker.internal`, so with the Docker backends MWS must
listen on an address containers can reach (the default `0.0.0.0` does).
| `MWS_ECS_BACKEND` | `auto` | How ECS tasks run. `docker` runs each container as a Docker container, `metadata` runs nothing (tasks only change state), and `auto` uses Docker when a daemon answers and `metadata` otherwise. |
| `MWS_ECS_DOCKER` | `MWS_EC2_DOCKER`, then `docker` | The Docker-compatible CLI the ECS backend drives. |
| `MWS_ECS_PAUSE_IMAGE` | `alpine:3.20` | The image of the container that holds an `awsvpc` task's network namespace. |

EC2 instances and ECS tasks reach the instance or task metadata service and the AWS endpoint
through the host, so when using the Docker backend MWS must listen on an
address containers can reach (the default `0.0.0.0` does).

## Bedrock

What answers Bedrock model invocations. The default echo model is
deterministic and needs no network, so tests can assert on its answers; queue
scripted answers with `POST /_aws/bedrock/responses` (see
[Bedrock](services/bedrock.md#scripted-answers)).

| Variable | Default | Description |
| --- | --- | --- |
| `MWS_BEDROCK_PROVIDER_<NAME>_<SETTING>` | unset | One setting of the provider `<name>` (lowercased, `_` becomes `-`). Settings: `KIND` (`openai`, `anthropic` or `echo`; inferred from the name otherwise), `URL`, `API_KEY`, `MODEL` (upstream model for every request), `MODELS` (comma-separated Bedrock model ids this provider answers, `*` wildcards), `MODEL_MAP` (`bedrock-id=upstream-model,...` or a JSON object), `PARAMS` (JSON object of request-body defaults such as `temperature`, `max_tokens`, `top_p`, `seed`), `HEADERS` (`name=value,...` or JSON), `TIMEOUT_SECONDS` (default 300), `ANTHROPIC_VERSION` (default `2023-06-01`). |
| `MWS_BEDROCK_PROVIDERS` | unset | Every provider at once as JSON: `{"default": "local", "providers": {"local": {"kind": "openai", "url": "...", "apiKey": "...", "models": ["meta.*"], "modelMap": {...}, "params": {...}, "headers": {...}, "timeoutSeconds": 60}}}`. The per-setting variables above win over it. |
| `MWS_BEDROCK_DEFAULT_PROVIDER` | `echo` | The provider for models no `MODELS` pattern claims. |
| `MWS_BEDROCK_BACKEND` | `echo` | Shorthand for one provider named `openai` (any OpenAI-compatible chat completions API: OpenAI, Ollama, vLLM, LM Studio) or `anthropic` (the Anthropic Messages API) that answers every model. |
| `MWS_BEDROCK_BACKEND_URL` | `https://api.openai.com/v1` or `https://api.anthropic.com` | Its base URL (for example `http://localhost:11434/v1` for Ollama). |
| `MWS_BEDROCK_BACKEND_API_KEY` | `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` | Its API key. Providers pointing at `api.openai.com` or `api.anthropic.com` also fall back to those two variables. |
| `MWS_BEDROCK_BACKEND_MODEL` | derived from the Bedrock model id | Its upstream model. Without one, Anthropic gets the Claude model matching the Bedrock id and OpenAI-compatible servers get the Bedrock id. |
| `MWS_BEDROCK_MODELS` | unset | A JSON file with extra foundation models to add to the catalog (an array in `GetFoundationModel`'s shape plus `family`). |

Embeddings, images and rerank are always answered locally.

Provider settings can also be stored at runtime, from the console's Bedrock
Settings page or the unsigned `/_aws/bedrock/providers` endpoint (see
[Bedrock](services/bedrock.md#model-providers)). Stored settings override the
environment's field by field and are saved with the rest of MWS state, so
`MWS_DB` keeps them across restarts. API keys stored this way sit in the
state file in plain text, as everything else there does.

```sh
# Llama models from a local Ollama, Claude from Anthropic, the rest echo.
MWS_BEDROCK_PROVIDER_OLLAMA_MODELS='meta.*' \
MWS_BEDROCK_PROVIDER_OLLAMA_MODEL_MAP='meta.llama3-8b-instruct-v1:0=llama3:8b' \
MWS_BEDROCK_PROVIDER_OLLAMA_PARAMS='{"temperature":0.2}' \
MWS_BEDROCK_PROVIDER_ANTHROPIC_MODELS='anthropic.*' \
ANTHROPIC_API_KEY=sk-ant-... cargo run -p mws
```

## Client-side settings

These are read by the AWS SDKs, not by MWS, but are the usual way to point
an application at it:

| Variable | Typical value |
| --- | --- |
| `AWS_ENDPOINT_URL` | `http://localhost:4566` |
| `AWS_ACCESS_KEY_ID` | `AKIAMWSROOTEXAMPLE00`, or keys created in MWS |
| `AWS_SECRET_ACCESS_KEY` | `mwsRootSecretAccessKeyEXAMPLEKEY00000000` |
| `AWS_REGION`, `AWS_DEFAULT_REGION` | `us-east-1` or any other Region (boto3 and the CLI read `AWS_DEFAULT_REGION`) |
