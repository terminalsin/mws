//! Composition root. This is the only crate that knows which services exist.

use std::sync::Arc;

use mws_acmpca::PrivateCa;
use mws_core::Environment;
use mws_iam::{Iam, IamConfig};
use mws_route53::Route53;
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

/// The gateway plus handles to services that have side channels (the
/// Route 53 DNS responder).
pub struct Mws {
    pub gateway: Gateway,
    pub route53: Route53,
}

/// Build the gateway with every service MWS emulates.
pub fn build_gateway(config: Config) -> Gateway {
    build(config).gateway
}

/// Build every service and the gateway in front of them.
pub fn build(config: Config) -> Mws {
    let iam = Iam::new(config.iam.clone());
    let sts = Sts::new(iam.clone());
    let route53 = Route53::new();
    let gateway = Gateway::builder()
        .environment(Environment { partition: config.iam.partition.clone(), ..Environment::default() })
        .authorizer(iam.authorizer())
        .credentials(iam.credential_store())
        .credentials(sts.credential_store())
        .service(Arc::new(iam))
        .service(Arc::new(sts))
        .service(Arc::new(route53.clone()))
        .service(Arc::new(PrivateCa::new()))
        .build();
    Mws { gateway, route53 }
}
