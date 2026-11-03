//! Composition root. This is the only crate that knows which services exist.

use std::path::PathBuf;
use std::sync::Arc;

use mws_acmpca::PrivateCa;
use mws_core::Environment;
use mws_iam::{Iam, IamConfig};
use mws_kms::Kms;
use mws_lambda::Lambda;
use mws_organizations::Organizations;
use mws_route53::Route53;
use mws_s3::S3;
use mws_s3control::S3Control;
use mws_server::{Gateway, Scenario, Store};
use mws_sts::Sts;

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub iam: IamConfig,
    /// SQLite file to persist state in (`MWS_DB`). In-memory when unset.
    pub db: Option<PathBuf>,
    /// Scenario file applied at startup and used as the reset baseline
    /// (`MWS_SCENARIO`).
    pub scenario: Option<PathBuf>,
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
        let path = |var: &str| std::env::var_os(var).filter(|v| !v.is_empty()).map(PathBuf::from);
        Self { iam, db: path("MWS_DB"), scenario: path("MWS_SCENARIO") }
    }
}

/// The gateway plus handles to services that have side channels (the
/// Route 53 DNS responder) or that tests reach into.
pub struct Mws {
    pub gateway: Gateway,
    pub route53: Route53,
    pub kms: Kms,
    pub s3: S3,
    pub s3control: S3Control,
    pub lambda: Lambda,
}

/// Build the gateway with every service MWS emulates.
pub fn build_gateway(config: Config) -> Gateway {
    build(config).gateway
}

/// Build every service and the gateway in front of them, in memory and
/// without running a scenario. [`start`] honours `db` and `scenario`.
pub fn build(config: Config) -> Mws {
    build_with_store(config, None)
}

/// Build MWS as `config` describes: open the state database if one is
/// configured, restore saved state or run the scenario, and set the reset
/// baseline.
pub async fn start(config: Config) -> Result<Mws, String> {
    let scenario_source = match &config.scenario {
        Some(path) => std::fs::read_to_string(path).map_err(|e| format!("reading scenario {}: {e}", path.display()))?,
        None => String::new(),
    };
    let scenario = match &config.scenario {
        Some(path) => Some(Scenario::parse(&scenario_source).map_err(|e| format!("{}: {e}", path.display()))?),
        None => None,
    };
    let store = match &config.db {
        Some(path) => {
            if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
            }
            Some(Arc::new(Store::open(path).map_err(|e| format!("{}: {e}", path.display()))?))
        }
        None => None,
    };
    let mws = build_with_store(config, store);
    mws.gateway.initialize_state(scenario.as_ref(), &scenario_source).await?;
    Ok(mws)
}

fn build_with_store(config: Config, store: Option<Arc<Store>>) -> Mws {
    let iam = Iam::new(config.iam.clone());
    let sts = Sts::new(iam.clone());
    let kms = Kms::new();
    let route53 = Route53::new().with_kms(kms.clone());
    let organizations = Organizations::new(iam.clone());
    iam.set_organizations(organizations.view());
    let s3 = S3::new().with_kms(kms.clone());
    let s3control = S3Control::for_s3(s3.clone());
    let lambda = Lambda::with_services(sts.clone(), s3.clone());
    s3.set_object_lambda_invoker(Arc::new(lambda.clone()));
    let mut gateway = Gateway::builder();
    if let Some(store) = store {
        gateway = gateway.store(store);
    }
    let gateway = gateway
        .scenario_principal(config.iam.root_access_key_id.clone())
        .environment(Environment { partition: config.iam.partition.clone(), ..Environment::default() })
        .authorizer(iam.authorizer())
        .credentials(iam.credential_store())
        .credentials(sts.credential_store())
        .credentials(s3.credential_store())
        .service(Arc::new(iam))
        .service(Arc::new(sts))
        .service(Arc::new(route53.clone()))
        .service(Arc::new(PrivateCa::new().with_s3(s3.clone())))
        .service(Arc::new(kms.clone()))
        .service(Arc::new(organizations))
        // S3 Control signs as `s3` too; it claims its `/v20180820/` paths.
        .service(Arc::new(s3control.clone()))
        .service(Arc::new(s3.clone()))
        .service(Arc::new(lambda.clone()))
        .build();
    Mws { gateway, route53, kms, s3, s3control, lambda }
}
