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
| `MWS_EC2_FIREWALL` | `on` | With the Docker backend, whether security groups, network ACLs and route tables filter instances' traffic (`off` leaves it unfiltered). |
| `MWS_EC2_NETFILTER_IMAGE` | `rancher/klipper-lb:v0.4.13` | The helper image (any image with `/bin/sh` and `iptables-restore`) that writes instances' firewall rules into their network namespaces. |
| `MWS_EC2_HELPER_IMAGE` | `alpine:3.20` | With the Docker backend, the small image that copies EBS volume data when snapshots are taken and volumes are restored or copied. |
| `MWS_ELB_BIND` | `127.0.0.1` | Address load balancer listeners bind. `GET /_aws/elb/listeners` lists where each listener is. |
| `MWS_ELB_LISTENER_PORTS` | `ephemeral` | `listener` binds each listener on its own port (80, 443, ...) when free, falling back to an ephemeral port; `ephemeral` always picks a free port. |
| `MWS_SES_SMTP_LISTEN` | unset | An address such as `127.0.0.1:2525` starts the SES SMTP listener: unauthenticated mail goes to receipt rules, and clients authenticating with SES SMTP credentials send through SES. |
| `MWS_SES_AUTO_VERIFY` | unset | `1` verifies SES identities as soon as they are created, without DNS records or verification links. |
| `MWS_RDS_BACKEND` | `auto` | How RDS databases run. `docker` runs each DB instance (or Aurora cluster) as a PostgreSQL, MySQL or MariaDB container, `metadata` runs nothing (resources only change state), and `auto` uses Docker when a daemon answers and `metadata` otherwise. |
| `MWS_RDS_DOCKER` | `MWS_EC2_DOCKER`, then `docker` | The Docker-compatible CLI the RDS backend drives. |
| `MWS_RDS_BIND` | `127.0.0.1` | The host address database ports are published on. Endpoints report this address and the published port. |
| `MWS_EKS_BACKEND` | `auto` | What runs EKS clusters' Kubernetes API servers. `k3s` runs a k3s server container per cluster, `metadata` runs none (clusters are EKS metadata only), and `auto` uses k3s when a Docker daemon answers and `metadata` otherwise. |
| `MWS_EKS_DOCKER` | `MWS_EC2_DOCKER`, then `docker` | The Docker-compatible CLI the EKS backend drives. |
| `MWS_EKS_BIND` | `127.0.0.1` | The host address API server ports are published on; cluster endpoints report it. |
| `MWS_EKS_K3S_IMAGE` | `rancher/k3s:<tag for the version>` | The API server image; `{version}` is replaced by the cluster's Kubernetes minor version. |
| `MWS_EFS_DIR` | `mws-efs` in the temp directory | Where EFS keeps file system data, one directory per file system. EC2 instances in Docker mount it at `/var/lib/mws-efs`. |

EC2 instances reach the instance metadata service and the AWS endpoint
through the host, and EKS API servers call MWS's token and authorization
webhooks at `host.docker.internal`, so with the Docker backends MWS must
listen on an address containers can reach (the default `0.0.0.0` does).

## Client-side settings

These are read by the AWS SDKs, not by MWS, but are the usual way to point
an application at it:

| Variable | Typical value |
| --- | --- |
| `AWS_ENDPOINT_URL` | `http://localhost:4566` |
| `AWS_ACCESS_KEY_ID` | `AKIAMWSROOTEXAMPLE00`, or keys created in MWS |
| `AWS_SECRET_ACCESS_KEY` | `mwsRootSecretAccessKeyEXAMPLEKEY00000000` |
| `AWS_REGION`, `AWS_DEFAULT_REGION` | `us-east-1` or any other Region (boto3 and the CLI read `AWS_DEFAULT_REGION`) |
