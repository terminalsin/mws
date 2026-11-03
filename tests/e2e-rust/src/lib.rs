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
