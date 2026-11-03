//! Helpers to start MWS on a random port and build SDK configs for it.

use std::sync::Arc;

use aws_config::{BehaviorVersion, Region, SdkConfig};
use aws_credential_types::Credentials;

pub struct Mws {
    pub endpoint: String,
    pub config: mws::Config,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl Mws {
    pub async fn start() -> Self {
        let config = mws::Config::default();
        let gateway = Arc::new(mws::build_gateway(config.clone()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(mws_server::serve(listener, gateway, async {
            let _ = rx.await;
        }));
        Self { endpoint, config, _shutdown: tx }
    }

    /// SDK config signed with the account root keys.
    pub async fn root_sdk_config(&self) -> SdkConfig {
        let iam = &self.config.iam;
        self.sdk_config(&iam.root_access_key_id, &iam.root_secret_access_key, None).await
    }

    pub async fn sdk_config(&self, akid: &str, secret: &str, token: Option<&str>) -> SdkConfig {
        aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .endpoint_url(&self.endpoint)
            .credentials_provider(Credentials::new(akid, secret, token.map(str::to_string), None, "mws-e2e"))
            .load()
            .await
    }
}

/// Create a user with the given inline policy and return a client signed
/// with that user's own new access key.
pub async fn user_with_policy(mws: &Mws, name: &str, policy: Option<&str>) -> (aws_sdk_iam::Client, SdkConfig) {
    let root = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    root.create_user().user_name(name).send().await.unwrap();
    if let Some(doc) = policy {
        root.put_user_policy().user_name(name).policy_name("inline").policy_document(doc).send().await.unwrap();
    }
    let key = root.create_access_key().user_name(name).send().await.unwrap();
    let key = key.access_key().unwrap();
    let cfg = mws.sdk_config(key.access_key_id(), key.secret_access_key(), None).await;
    (aws_sdk_iam::Client::new(&cfg), cfg)
}

/// SDK config for a set of STS temporary credentials.
pub async fn sts_config(mws: &Mws, creds: &aws_sdk_sts::types::Credentials) -> SdkConfig {
    mws.sdk_config(creds.access_key_id(), creds.secret_access_key(), Some(creds.session_token())).await
}

/// An unsigned-looking OIDC ID token: header.payload.signature.
pub fn jwt(claims: serde_json::Value) -> String {
    use base64::Engine;
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!("{}.{}.{}", e.encode(br#"{"alg":"RS256","typ":"JWT"}"#), e.encode(claims.to_string()), e.encode(b"sig"))
}
