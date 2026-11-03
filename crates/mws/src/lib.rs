//! Composition root. This is the only crate that knows which services exist.

use std::sync::Arc;

use mws_core::Environment;
use mws_iam::{Iam, IamConfig};
use mws_server::Gateway;
use mws_sts::Sts;

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub iam: IamConfig,
}

impl Config {
    /// Read settings from `MWS_*` environment variables, falling back to
    /// defaults.
    pub fn from_env() -> Self {
        let mut iam = IamConfig::default();
        if let Ok(v) = std::env::var("MWS_ACCOUNT_ID") {
            iam.account_id = v;
        }
        if let Ok(v) = std::env::var("MWS_ROOT_ACCESS_KEY_ID") {
            iam.root_access_key_id = v;
        }
        if let Ok(v) = std::env::var("MWS_ROOT_SECRET_ACCESS_KEY") {
            iam.root_secret_access_key = v;
        }
        Self { iam }
    }
}

/// Build the gateway with every service MWS emulates.
pub fn build_gateway(config: Config) -> Gateway {
    let iam = Iam::new(config.iam.clone());
    let sts = Sts::new(iam.clone());
    Gateway::builder()
        .environment(Environment { partition: config.iam.partition.clone(), ..Environment::default() })
        .authorizer(iam.authorizer())
        .credentials(iam.credential_store())
        .credentials(sts.credential_store())
        .service(Arc::new(iam))
        .service(Arc::new(sts))
        .build()
}
