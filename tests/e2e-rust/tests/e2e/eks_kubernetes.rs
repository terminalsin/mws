//! EKS clusters with a real Kubernetes API server: k3s in Docker, reached at
//! the endpoint and CA DescribeCluster reports, authenticating IAM
//! principals with `aws eks get-token` tokens and authorizing them by their
//! access entries. Skipped when no Docker daemon answers.

use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aws_credential_types::Credentials;
use aws_sdk_eks::types::{
    AccessScope, AccessScopeType, AuthenticationMode, CreateAccessConfigRequest, LogSetup, LogType, Logging,
    NodegroupScalingConfig, VpcConfigRequest,
};
use aws_sigv4::http_request::{sign, SignableBody, SignableRequest, SignatureLocation, SigningSettings};
use base64::Engine;
use mws_e2e::Mws;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::eks::env;

fn docker_available() -> bool {
    Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Containers MWS runs for the cluster.
fn containers(cluster_arn: &str) -> Vec<String> {
    let out = Command::new("docker")
        .args(["ps", "-a", "--filter", &format!("label=mws.eks.cluster={cluster_arn}"), "--format", "{{.Names}}"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).lines().map(str::to_string).collect()
}

/// What `aws eks get-token` produces: a presigned STS GetCallerIdentity URL
/// that signs the cluster name in `x-k8s-aws-id`, base64url-encoded. Signed
/// with the official SigV4 signer, not MWS's.
fn get_token(key: &str, secret: &str, cluster: &str) -> String {
    let identity = Credentials::new(key, secret, None, None, "test").into();
    let mut settings = SigningSettings::default();
    settings.signature_location = SignatureLocation::QueryParams;
    settings.expires_in = Some(Duration::from_secs(60));
    let params = aws_sigv4::sign::v4::SigningParams::builder()
        .identity(&identity)
        .region("us-east-1")
        .name("sts")
        .time(SystemTime::now())
        .settings(settings)
        .build()
        .unwrap()
        .into();
    let base = "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15";
    let headers = [("x-k8s-aws-id", cluster)];
    let request = SignableRequest::new("GET", base, headers.into_iter(), SignableBody::Bytes(&[])).unwrap();
    let (instructions, _) = sign(request, &params).unwrap().into_parts();
    let mut url = base.to_string();
    for (k, v) in instructions.params() {
        url.push_str(&format!("&{k}={}", urlencoding::encode(v)));
    }
    format!("k8s-aws-v1.{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(url))
}

/// A Kubernetes API client that trusts only the cluster's CA.
struct Kube {
    addr: String,
    tls: tokio_rustls::TlsConnector,
}

impl Kube {
    fn new(endpoint: &str, ca_pem: &[u8]) -> Self {
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pki_types::pem::PemObject::pem_slice_iter(ca_pem) {
            let cert: rustls_pki_types::CertificateDer<'static> = cert.unwrap();
            roots.add(cert).unwrap();
        }
        let config =
            rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        let addr = endpoint.strip_prefix("https://").unwrap().to_string();
        Self { addr, tls: tokio_rustls::TlsConnector::from(Arc::new(config)) }
    }

    async fn call(&self, method: &str, path: &str, token: &str, body: Option<Value>) -> (u16, Value) {
        let tcp = TcpStream::connect(&self.addr).await.unwrap();
        let host = self.addr.rsplit_once(':').unwrap().0.to_string();
        let name = rustls_pki_types::ServerName::try_from(host.clone()).unwrap();
        let mut tls = self.tls.connect(name, tcp).await.expect("the API server's certificate chains to the CA");
        let body = body.map(|b| b.to_string()).unwrap_or_default();
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {token}\r\nAccept: application/json\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.addr,
            body.len()
        );
        tls.write_all(request.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        let _ = tls.read_to_end(&mut raw).await;
        let text = String::from_utf8_lossy(&raw).to_string();
        let (head, rest) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let status: u16 = head.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let chunked = head.to_ascii_lowercase().contains("transfer-encoding: chunked");
        let body = if chunked { dechunk(rest) } else { rest.to_string() };
        (status, serde_json::from_str(&body).unwrap_or(Value::Null))
    }

    async fn get(&self, path: &str, token: &str) -> (u16, Value) {
        self.call("GET", path, token, None).await
    }
}

fn dechunk(mut s: &str) -> String {
    let mut out = String::new();
    while let Some((size, rest)) = s.split_once("\r\n") {
        let n = usize::from_str_radix(size.trim(), 16).unwrap_or(0);
        if n == 0 || rest.len() < n {
            break;
        }
        out.push_str(&rest[..n]);
        s = rest[n..].trim_start_matches("\r\n");
    }
    out
}

async fn user_keys(iam: &aws_sdk_iam::Client, name: &str) -> (String, String, String) {
    let u = iam.create_user().user_name(name).send().await.unwrap();
    let arn = u.user().unwrap().arn().to_string();
    let k = iam.create_access_key().user_name(name).send().await.unwrap();
    let k = k.access_key().unwrap();
    (arn, k.access_key_id().to_string(), k.secret_access_key().to_string())
}

/// The names of the cluster's Nodes, once there are `want` of them.
async fn node_names(kube: &Kube, token: &str, want: usize) -> Vec<Value> {
    let mut items = Vec::new();
    for _ in 0..120 {
        let (status, nodes) = kube.get("/api/v1/nodes", token).await;
        assert_eq!(status, 200, "{nodes}");
        items = nodes["items"].as_array().cloned().unwrap_or_default();
        if items.len() == want {
            return items;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("the cluster has {} nodes, not {want}", items.len());
}

#[tokio::test(flavor = "multi_thread")]
async fn clusters_run_a_kubernetes_api_server() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let config = mws::Config { eks_backend: mws_eks::kube::BackendChoice::K3s, ..Default::default() };
    let mws = Mws::start_on_all_interfaces(config).await;
    let e = env(&mws).await;

    let created = e
        .eks
        .create_cluster()
        .name("kube")
        .role_arn(&e.cluster_role)
        .resources_vpc_config(VpcConfigRequest::builder().set_subnet_ids(Some(e.subnets.clone())).build())
        .access_config(CreateAccessConfigRequest::builder().authentication_mode(AuthenticationMode::Api).build())
        .logging(
            Logging::builder()
                .cluster_logging(
                    LogSetup::builder()
                        .types(LogType::Api)
                        .types(LogType::Audit)
                        .types(LogType::Authenticator)
                        .types(LogType::ControllerManager)
                        .types(LogType::Scheduler)
                        .enabled(true)
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    let arn = created.cluster().unwrap().arn().unwrap().to_string();
    assert_eq!(created.cluster().unwrap().status().map(|s| s.as_str()), Some("CREATING"));

    // The cluster becomes ACTIVE once its API server answers (pulling the
    // k3s image the first time can take a while).
    let mut cluster = None;
    for _ in 0..600 {
        let c = e.eks.describe_cluster().name("kube").send().await.unwrap().cluster().unwrap().clone();
        match c.status().map(|s| s.as_str()) {
            Some("ACTIVE") => {
                cluster = Some(c);
                break;
            }
            Some("FAILED") => panic!("cluster failed: {:?}", c.health()),
            _ => tokio::time::sleep(Duration::from_millis(500)).await,
        }
    }
    let cluster = cluster.expect("the cluster becomes ACTIVE");
    let endpoint = cluster.endpoint().unwrap().to_string();
    assert!(endpoint.starts_with("https://127.0.0.1:"), "{endpoint}");
    assert_eq!(containers(&arn).len(), 1);
    let ca = base64::engine::general_purpose::STANDARD
        .decode(cluster.certificate_authority().unwrap().data().unwrap())
        .unwrap();
    let pem = x509_parser::pem::parse_x509_pem(&ca).unwrap().1;
    let cert = pem.parse_x509().unwrap();
    assert!(cert.is_ca());
    assert!(cert.subject().to_string().contains("k3s-server-ca"), "{}", cert.subject());
    let kube = Kube::new(&endpoint, &ca);

    // IAM principals with access entries, and one without.
    let (admin_arn, admin_key, admin_secret) = user_keys(&e.iam, "kube-admin").await;
    let (viewer_arn, viewer_key, viewer_secret) = user_keys(&e.iam, "kube-viewer").await;
    let (_, stranger_key, stranger_secret) = user_keys(&e.iam, "kube-stranger").await;
    e.eks.create_access_entry().cluster_name("kube").principal_arn(&admin_arn).send().await.unwrap();
    e.eks
        .associate_access_policy()
        .cluster_name("kube")
        .principal_arn(&admin_arn)
        .policy_arn("arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy")
        .access_scope(AccessScope::builder().r#type(AccessScopeType::Cluster).build())
        .send()
        .await
        .unwrap();
    e.eks
        .create_access_entry()
        .cluster_name("kube")
        .principal_arn(&viewer_arn)
        .username("viewer:{{AccountID}}")
        .kubernetes_groups("readers")
        .send()
        .await
        .unwrap();
    e.eks
        .associate_access_policy()
        .cluster_name("kube")
        .principal_arn(&viewer_arn)
        .policy_arn("arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy")
        .access_scope(AccessScope::builder().r#type(AccessScopeType::Namespace).namespaces("default").build())
        .send()
        .await
        .unwrap();
    let admin = get_token(&admin_key, &admin_secret, "kube");
    let viewer = get_token(&viewer_key, &viewer_secret, "kube");
    let stranger = get_token(&stranger_key, &stranger_secret, "kube");

    // The API server knows who the token belongs to.
    let review = json!({"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview"});
    let (status, me) =
        kube.call("POST", "/apis/authentication.k8s.io/v1/selfsubjectreviews", &admin, Some(review.clone())).await;
    assert_eq!(status, 201, "{me}");
    assert_eq!(me["status"]["userInfo"]["username"], admin_arn);
    assert_eq!(me["status"]["userInfo"]["extra"]["arn"][0], admin_arn);
    assert!(me["status"]["userInfo"]["uid"].as_str().unwrap().starts_with("aws-iam-authenticator:123456789012:AIDA"));
    let (_, me) = kube.call("POST", "/apis/authentication.k8s.io/v1/selfsubjectreviews", &viewer, Some(review)).await;
    assert_eq!(me["status"]["userInfo"]["username"], "viewer:123456789012");
    let groups: Vec<_> = me["status"]["userInfo"]["groups"].as_array().unwrap().to_vec();
    assert!(groups.contains(&json!("readers")), "{groups:?}");

    // Cluster admins can do anything.
    let cm = |ns: &str| {
        json!({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "settings", "namespace": ns},
               "data": {"color": "blue"}})
    };
    let (status, out) =
        kube.call("POST", "/api/v1/namespaces/kube-system/configmaps", &admin, Some(cm("kube-system"))).await;
    assert_eq!(status, 201, "{out}");
    let (status, out) = kube.call("POST", "/api/v1/namespaces/default/configmaps", &admin, Some(cm("default"))).await;
    assert_eq!(status, 201, "{out}");
    let (status, _) = kube.get("/api/v1/namespaces", &admin).await;
    assert_eq!(status, 200);

    // The view policy, scoped to `default`, reads there and nowhere else,
    // and cannot write.
    let (status, out) = kube.get("/api/v1/namespaces/default/configmaps/settings", &viewer).await;
    assert_eq!(status, 200, "{out}");
    assert_eq!(out["data"]["color"], "blue");
    let (status, out) = kube.get("/api/v1/namespaces/kube-system/configmaps/settings", &viewer).await;
    assert_eq!(status, 403, "{out}");
    let (status, _) = kube.call("DELETE", "/api/v1/namespaces/default/configmaps/settings", &viewer, None).await;
    assert_eq!(status, 403);
    // The view policy does not read Secrets.
    let (status, _) = kube.get("/api/v1/namespaces/default/secrets", &viewer).await;
    assert_eq!(status, 403);

    // No access entry, a token for another cluster, or a forged signature:
    // unauthenticated.
    let (status, _) = kube.get("/api/v1/namespaces", &stranger).await;
    assert_eq!(status, 401);
    let (status, _) = kube.get("/api/v1/namespaces", &get_token(&admin_key, &admin_secret, "other")).await;
    assert_eq!(status, 401);
    let (status, _) = kube.get("/api/v1/namespaces", &get_token(&admin_key, "wrong-secret", "kube")).await;
    assert_eq!(status, 401);

    // Removing the access entry revokes access (after the API server's
    // short authentication cache).
    e.eks.delete_access_entry().cluster_name("kube").principal_arn(&viewer_arn).send().await.unwrap();
    let mut revoked = false;
    for _ in 0..60 {
        let fresh = get_token(&viewer_key, &viewer_secret, "kube");
        if kube.get("/api/v1/namespaces/default/configmaps", &fresh).await.0 == 401 {
            revoked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(revoked, "the deleted access entry still authenticates");

    // The control plane's logs reach CloudWatch Logs, in EKS's streams.
    let logs = aws_sdk_cloudwatchlogs::Client::new(&mws.root_sdk_config().await);
    let events = |prefix: &'static str| {
        let logs = logs.clone();
        async move {
            let streams = logs
                .describe_log_streams()
                .log_group_name("/aws/eks/kube/cluster")
                .log_stream_name_prefix(prefix)
                .send()
                .await
                .map(|s| s.log_streams().to_vec())
                .unwrap_or_default();
            let mut out = Vec::new();
            for stream in streams.iter().filter(|s| {
                // `kube-apiserver-` also prefixes the audit stream.
                let name = s.log_stream_name().unwrap_or_default();
                prefix != "kube-apiserver-" || !name.starts_with("kube-apiserver-audit-")
            }) {
                let name = stream.log_stream_name().unwrap().to_string();
                assert_eq!(name.len(), prefix.len() + 32, "{name}");
                let got = logs
                    .get_log_events()
                    .log_group_name("/aws/eks/kube/cluster")
                    .log_stream_name(&name)
                    .start_from_head(true)
                    .send()
                    .await
                    .unwrap();
                out.extend(got.events().iter().map(|e| e.message().unwrap_or_default().to_string()));
            }
            out
        }
    };
    let mut found = false;
    for _ in 0..60 {
        let audit = events("kube-apiserver-audit-").await;
        let authenticator = events("authenticator-").await;
        let created_by_admin = audit.iter().any(|line| {
            let v: Value = serde_json::from_str(line).unwrap();
            v["kind"] == "Event"
                && v["verb"] == "create"
                && v["objectRef"]["resource"] == "configmaps"
                && v["objectRef"]["namespace"] == "kube-system"
                && v["user"]["username"] == admin_arn
        });
        let granted = authenticator
            .iter()
            .any(|l| l.contains("msg=\"access granted\"") && l.contains(&format!("arn=\"{admin_arn}\"")));
        let denied = authenticator.iter().any(|l| l.contains("level=warning msg=\"access denied\""));
        if created_by_admin && granted && denied {
            found = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(found, "audit and authenticator events in CloudWatch Logs");
    assert!(events("kube-apiserver-").await.iter().any(|l| l.contains("Running kube-apiserver") || l.contains(".go:")));
    assert!(events("kube-scheduler-").await.iter().any(|l| l.contains("Running kube-scheduler")));
    assert!(events("kube-controller-manager-").await.iter().any(|l| l.contains("Running kube-controller-manager")));

    // Turning a log type off stops its stream.
    e.eks
        .update_cluster_config()
        .name("kube")
        .logging(
            Logging::builder()
                .cluster_logging(LogSetup::builder().types(LogType::Authenticator).enabled(false).build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    let before = events("authenticator-").await.len();
    let (status, _) = kube.get("/api/v1/namespaces", &get_token(&admin_key, &admin_secret, "kube")).await;
    assert_eq!(status, 200);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(events("authenticator-").await.len(), before);

    // Managed node group instances register as Nodes.
    e.eks
        .create_nodegroup()
        .cluster_name("kube")
        .nodegroup_name("workers")
        .node_role(&e.node_role)
        .set_subnets(Some(e.subnets.clone()))
        .instance_types("m5.large")
        .labels("tier", "web")
        .scaling_config(NodegroupScalingConfig::builder().min_size(1).max_size(3).desired_size(2).build())
        .send()
        .await
        .unwrap();
    let nodes = node_names(&kube, &admin, 2).await;
    for node in &nodes {
        let labels = &node["metadata"]["labels"];
        assert_eq!(labels["eks.amazonaws.com/nodegroup"], "workers");
        assert_eq!(labels["tier"], "web");
        assert_eq!(labels["node.kubernetes.io/instance-type"], "m5.large");
        assert!(node["spec"]["providerID"].as_str().unwrap().starts_with("aws:///us-east-1"));
        let ready = node["status"]["conditions"].as_array().unwrap().iter().find(|c| c["type"] == "Ready").unwrap();
        assert_eq!(ready["status"], "True");
        assert!(node["status"]["nodeInfo"]["kubeletVersion"].as_str().unwrap().contains("-eks-"));
    }
    let instances: Vec<String> =
        e.instances("workers").await.iter().map(|i| i.private_dns_name().unwrap().to_string()).collect();
    for node in &nodes {
        assert!(instances.iter().any(|n| node["metadata"]["name"] == *n), "{instances:?}");
    }

    // Scaling the node group removes the Node of the terminated instance.
    e.eks
        .update_nodegroup_config()
        .cluster_name("kube")
        .nodegroup_name("workers")
        .scaling_config(NodegroupScalingConfig::builder().min_size(1).max_size(3).desired_size(1).build())
        .send()
        .await
        .unwrap();
    node_names(&kube, &admin, 1).await;

    // Deleting the cluster removes its API server.
    e.eks.delete_nodegroup().cluster_name("kube").nodegroup_name("workers").send().await.unwrap();
    for _ in 0..120 {
        if e.eks.describe_nodegroup().cluster_name("kube").nodegroup_name("workers").send().await.is_err() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    e.eks.delete_cluster().name("kube").send().await.unwrap();
    for _ in 0..120 {
        if containers(&arn).is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(containers(&arn).is_empty(), "the API server container outlives the cluster");
}
