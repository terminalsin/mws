//! Composition root. This is the only crate that knows which services exist.

mod autoscaling;
mod eks;
mod links;
mod ses;
mod sinks;

use std::path::PathBuf;
use std::sync::Arc;

use mws_acm::Acm;
use mws_acmpca::PrivateCa;
use mws_amplify::Amplify;
use mws_autoscaling::AutoScaling;
use mws_cloudwatch::CloudWatch;
use mws_codeartifact::CodeArtifact;
use mws_core::Environment;
use mws_ec2::{BackendChoice, Ec2};
use mws_eks::Eks;
use mws_elb::{Elb, ElbConfig};
use mws_events::Events;
use mws_firehose::Firehose;
use mws_globalaccelerator::GlobalAccelerator;
use mws_iam::{Iam, IamConfig};
use mws_imagebuilder::ImageBuilder;
use mws_kinesis::Kinesis;
use mws_kms::Kms;
use mws_lambda::Lambda;
use mws_logs::Logs;
use mws_marketplace_entitlement::Entitlement;
use mws_marketplace_metering::Metering;
use mws_organizations::Organizations;
use mws_pca_connector_scep::ScepConnector;
use mws_ram::Ram;
use mws_rds::Rds;
use mws_route53::Route53;
use mws_s3::S3;
use mws_s3control::S3Control;
use mws_secretsmanager::SecretsManager;
use mws_securityhub::SecurityHub;
use mws_server::{Gateway, Scenario, Store};
use mws_ses::Ses;
use mws_sns::Sns;
use mws_sqs::Sqs;
use mws_ssm::Ssm;
use mws_sts::Sts;

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub iam: IamConfig,
    /// SQLite file to persist state in (`MWS_DB`). In-memory when unset.
    pub db: Option<PathBuf>,
    /// Scenario file applied at startup and used as the reset baseline
    /// (`MWS_SCENARIO`).
    pub scenario: Option<PathBuf>,
    /// Accept web identity tokens and SAML responses without verifying
    /// their signatures (`MWS_SKIP_FEDERATION_SIGNATURE_VERIFICATION=1`),
    /// for test suites that hand-craft them. AWS always verifies them.
    pub skip_federation_signature_verification: bool,
    /// What runs EC2 instances (`MWS_EC2_BACKEND`: `auto`, `docker` or
    /// `metadata`). The binary defaults to `auto` (Docker when a daemon
    /// answers); the library default runs nothing.
    pub ec2_backend: BackendChoice,
    /// The Docker-compatible CLI (`MWS_EC2_DOCKER`, e.g. `podman`).
    pub ec2_docker_cli: Option<String>,
    /// Treat SES identities as verified as soon as they are created
    /// (`MWS_SES_AUTO_VERIFY=1`), instead of waiting for the verification
    /// link to be followed or the DNS records to appear. AWS never does.
    pub ses_auto_verify: bool,
    /// What runs RDS databases (`MWS_RDS_BACKEND`: `auto`, `docker` or
    /// `metadata`). The binary defaults to `auto`; the library default runs
    /// nothing.
    pub rds_backend: mws_rds::BackendChoice,
    /// The Docker-compatible CLI for RDS (`MWS_RDS_DOCKER`; falls back to
    /// `MWS_EC2_DOCKER`).
    pub rds_docker_cli: Option<String>,
    /// The host address database ports are published on (`MWS_RDS_BIND`,
    /// default `127.0.0.1`).
    pub rds_bind: Option<String>,
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
        let skip = std::env::var("MWS_SKIP_FEDERATION_SIGNATURE_VERIFICATION")
            .is_ok_and(|v| matches!(v.as_str(), "1" | "true" | "yes"));
        let ec2_backend = match std::env::var("MWS_EC2_BACKEND") {
            Ok(v) => BackendChoice::parse(&v).unwrap_or_else(|| {
                tracing::warn!("unknown MWS_EC2_BACKEND {v:?}; using auto");
                BackendChoice::Auto
            }),
            Err(_) => BackendChoice::Auto,
        };
        let rds_backend = match std::env::var("MWS_RDS_BACKEND") {
            Ok(v) => mws_rds::BackendChoice::parse(&v).unwrap_or_else(|| {
                tracing::warn!("unknown MWS_RDS_BACKEND {v:?}; using auto");
                mws_rds::BackendChoice::Auto
            }),
            Err(_) => mws_rds::BackendChoice::Auto,
        };
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        Self {
            iam,
            db: path("MWS_DB"),
            scenario: path("MWS_SCENARIO"),
            skip_federation_signature_verification: skip,
            ec2_backend,
            ec2_docker_cli: std::env::var("MWS_EC2_DOCKER").ok().filter(|v| !v.is_empty()),
            ses_auto_verify: std::env::var("MWS_SES_AUTO_VERIFY")
                .is_ok_and(|v| matches!(v.as_str(), "1" | "true" | "yes")),
            rds_backend,
            rds_docker_cli: var("MWS_RDS_DOCKER").or_else(|| var("MWS_EC2_DOCKER")),
            rds_bind: var("MWS_RDS_BIND"),
        }
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
    pub logs: Logs,
    pub sqs: Sqs,
    pub ssm: Ssm,
    pub events: Events,
    pub secretsmanager: SecretsManager,
    pub sns: Sns,
    pub acm: Acm,
    pub kinesis: Kinesis,
    pub firehose: Firehose,
    pub cloudwatch: CloudWatch,
    pub ec2: Ec2,
    pub amplify: Amplify,
    pub globalaccelerator: GlobalAccelerator,
    pub marketplace_entitlement: Entitlement,
    pub marketplace_metering: Metering,
    pub ram: Ram,
    pub scep: ScepConnector,
    pub securityhub: SecurityHub,
    pub imagebuilder: ImageBuilder,
    pub elb: Elb,
    pub autoscaling: AutoScaling,
    pub ses: Ses,
    pub rds: Rds,
    pub eks: Eks,
    pub codeartifact: CodeArtifact,
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
    let sts = if config.skip_federation_signature_verification {
        Sts::without_federation_signature_verification(iam.clone())
    } else {
        Sts::new(iam.clone())
    };
    let kms = Kms::new();
    let organizations = Organizations::new(iam.clone());
    iam.set_organizations(organizations.view());
    let ram = Ram::new(iam.clone(), organizations.clone());
    let s3 = S3::new().with_kms(kms.clone());
    let logs = Logs::new().with_s3(s3.clone()).with_kms(kms.clone()).with_sts(sts.clone());
    let route53 = Route53::new().with_kms(kms.clone()).with_logs(logs.clone());
    let sqs = Sqs::new().with_kms(kms.clone());
    let kinesis = Kinesis::new().with_kms(kms.clone());
    let s3control = S3Control::for_s3(s3.clone());
    let pca = PrivateCa::new().with_s3(s3.clone());
    ram.register_resource_type(Arc::new(links::RamCertificateAuthorities(pca.clone())));
    pca.set_policy_listener(Arc::new(links::CaPoliciesToRam(ram.clone())));
    let scep = ScepConnector::new(pca.clone());
    let acm = Acm::new().with_private_ca(pca.clone()).with_route53(route53.clone()).with_sts(sts.clone());
    let lambda = Lambda::with_services(sts.clone(), s3.clone());
    let firehose = Firehose::new()
        .with_s3(s3.clone())
        .with_sts(sts.clone())
        .with_kms(kms.clone())
        .with_lambda(lambda.clone())
        .with_kinesis(kinesis.clone());
    firehose.set_logs(logs.clone());
    lambda.set_logs(logs.clone());
    s3control.set_sts(sts.clone());
    s3control.set_lambda(lambda.clone());
    s3.set_object_lambda_invoker(Arc::new(lambda.clone()));
    let ssm = Ssm::new(kms.clone());
    let codeartifact = CodeArtifact::new(Some(kms.clone()));
    let events = Events::new().with_lambda(lambda.clone()).with_logs(logs.clone()).with_sts(sts.clone());
    events.register_target_sink("sqs", Arc::new(sinks::SqsTarget(sqs.clone())));
    events.set_health_checks(Arc::new(sinks::Route53HealthChecks(route53.clone())));
    let secretsmanager = SecretsManager::new(kms.clone()).with_lambda(lambda.clone());
    ssm.set_secrets_manager(Arc::new(SsmSecretReferences(secretsmanager.clone())));
    firehose.set_secrets_manager(secretsmanager.clone());
    let sns = Sns::new()
        .with_lambda(lambda.clone())
        .with_kms(kms.clone())
        .with_firehose(firehose.clone())
        .with_s3(s3.clone());
    s3.add_notification_destination(Arc::new(sns.clone()));
    s3.add_notification_destination(Arc::new(lambda.clone()));
    sns.set_queues(Arc::new(links::SnsToSqs(sqs.clone())));
    s3.add_notification_destination(Arc::new(links::S3ToSqs(sqs.clone())));
    events.register_target_sink("sns", Arc::new(sinks::SnsTarget(sns.clone())));
    s3.set_eventbridge_sink(Arc::new(sinks::S3ToEvents(events.clone())));
    ssm.set_change_sink(Arc::new(sinks::SsmChangeEvents(events.clone())));
    events.register_clock_source(Arc::new(sinks::SsmPolicyEvents {
        ssm: ssm.clone(),
        partition: config.iam.partition.clone(),
    }));
    lambda.set_queue_source(Arc::new(links::LambdaFromSqs(sqs.clone())));
    lambda.add_destination_sink(Arc::new(links::LambdaDestination::Sqs(sqs.clone())));
    lambda.add_destination_sink(Arc::new(links::LambdaDestination::Sns(sns.clone())));
    lambda.add_destination_sink(Arc::new(links::LambdaDestination::Events(events.clone())));
    logs.add_subscription_target(Arc::new(links::LogsToLambda(lambda.clone())));
    logs.add_subscription_target(Arc::new(links::LogsToKinesis { kinesis: kinesis.clone(), sts: sts.clone() }));
    logs.add_subscription_target(Arc::new(links::LogsToFirehose { firehose: firehose.clone(), sts: sts.clone() }));
    lambda.set_stream_source(Arc::new(links::LambdaFromKinesis(kinesis.clone())));
    events.register_target_sink("kinesis", Arc::new(sinks::KinesisTarget(kinesis.clone())));
    events.register_target_sink("firehose", Arc::new(sinks::FirehoseTarget(firehose.clone())));
    sns.set_delivery_status_logs(logs.clone(), sts.clone());
    let cloudwatch = CloudWatch::new()
        .with_sns(sns.clone())
        .with_lambda(lambda.clone())
        .with_events(events.clone())
        .with_logs(logs.clone())
        .with_kms(kms.clone());
    events.register_clock_source(Arc::new(sinks::AcmEvents {
        acm: acm.clone(),
        cloudwatch: cloudwatch.clone(),
        partition: config.iam.partition.clone(),
    }));
    logs.set_metric_publisher(Arc::new(links::LogsToCloudWatch(cloudwatch.clone())));
    firehose.set_metric_publisher(Arc::new(links::FirehoseToCloudWatch(cloudwatch.clone())));
    kinesis.set_metric_publisher(Arc::new(links::KinesisToCloudWatch(cloudwatch.clone())));
    sqs.set_metric_publisher(Arc::new(links::SqsToCloudWatch(cloudwatch.clone())));
    cloudwatch.set_metric_stream_delivery(Arc::new(links::MetricStreamsToFirehose {
        firehose: firehose.clone(),
        sts: sts.clone(),
    }));
    let ec2 = Ec2::new(config.ec2_backend.resolve(config.ec2_docker_cli.as_deref()));
    tracing::info!(backend = ec2.backend_name(), "EC2 compute backend");
    ec2.set_instance_roles(Arc::new(links::Ec2InstanceRoles { iam: iam.clone(), sts: sts.clone() }));
    let amplify = Amplify::with_services(s3.clone(), route53.clone());
    let globalaccelerator = GlobalAccelerator::new();
    globalaccelerator.add_endpoint_directory(Arc::new(links::GlobalAcceleratorEc2(ec2.clone())));
    route53.add_alias_resolver(Arc::new(links::Route53ToGlobalAccelerator(globalaccelerator.clone())));
    let marketplace_entitlement = Entitlement::new(config.iam.account_id.clone());
    let marketplace_metering = Metering::new(marketplace_entitlement.clone());
    let securityhub = SecurityHub::new();
    securityhub.set_organizations(Arc::new(links::SecurityHubOrganizations(organizations.clone())));
    securityhub.set_event_sink(Arc::new(links::SecurityHubToEvents(events.clone())));
    securityhub.set_export_sink(Arc::new(links::SecurityHubExports(s3.clone())));
    let imagebuilder = ImageBuilder::with_ec2(ec2.clone());
    imagebuilder.set_s3(Arc::new(s3.clone()));
    imagebuilder.set_ssm(Arc::new(ssm.clone()));
    imagebuilder.set_sns(Arc::new(sns.clone()));
    imagebuilder.set_logs(Arc::new(logs.clone()));
    imagebuilder.set_events(Arc::new(sinks::ImageBuilderEvents(events.clone())));
    let elb = Elb::new(ElbConfig::from_env())
        .with_ec2(ec2.clone())
        .with_acm(acm.clone())
        .with_lambda(lambda.clone())
        .with_s3(s3.clone());
    elb.set_metric_sink(Arc::new(links::ElbToCloudWatch(cloudwatch.clone())));
    globalaccelerator.add_endpoint_directory(Arc::new(links::GlobalAcceleratorElb(elb.clone())));
    let autoscaling = AutoScaling::new(ec2.clone());
    autoscaling::wire(&autoscaling, &sns, &sqs, &events, &cloudwatch, &elb);
    let ses = if config.ses_auto_verify { Ses::with_auto_verify() } else { Ses::new() };
    ses.set_links(Arc::new(ses::SesLinks {
        route53: route53.clone(),
        s3: s3.clone(),
        sns: sns.clone(),
        lambda: lambda.clone(),
        events: events.clone(),
        firehose: firehose.clone(),
        cloudwatch: cloudwatch.clone(),
        sts: sts.clone(),
        partition: config.iam.partition.clone(),
    }));
    ses.set_credentials(vec![iam.credential_store(), sts.credential_store()]);
    ses.set_authorizer(iam.authorizer());
    let rds = Rds::new(
        config.rds_backend.resolve(config.rds_docker_cli.as_deref(), config.rds_bind.as_deref()),
        kms.clone(),
        secretsmanager.clone(),
    );
    tracing::info!(backend = rds.backend_name(), "RDS database backend");
    rds.set_network(Arc::new(links::RdsNetwork(ec2.clone())));
    rds.set_event_sink(Arc::new(links::RdsEvents { events: events.clone(), sns: sns.clone() }));
    rds.set_export_store(Arc::new(links::RdsExports { sts: sts.clone(), s3: s3.clone() }));
    let eks = Eks::with_sts(sts.clone());
    eks.set_infrastructure(Arc::new(eks::EksInfrastructure {
        ec2: ec2.clone(),
        iam: iam.clone(),
        autoscaling: autoscaling.clone(),
    }));
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
        .credentials(s3.object_lambda_credential_store())
        .service(Arc::new(iam))
        .service(Arc::new(sts))
        .service(Arc::new(route53.clone()))
        .service(Arc::new(pca))
        .service(Arc::new(acm.clone()))
        .service(Arc::new(kms.clone()))
        .service(Arc::new(organizations))
        // S3 Control signs as `s3` too; it claims its `/v20180820/` paths.
        .service(Arc::new(s3control.clone()))
        .service(Arc::new(s3.clone()))
        .service(Arc::new(lambda.clone()))
        .service(Arc::new(logs.clone()))
        .service(Arc::new(sqs.clone()))
        .service(Arc::new(ssm.clone()))
        .service(Arc::new(events.clone()))
        .service(Arc::new(secretsmanager.clone()))
        .service(Arc::new(sns.clone()))
        .service(Arc::new(kinesis.clone()))
        .service(Arc::new(firehose.clone()))
        .service(Arc::new(cloudwatch.clone()))
        .service(Arc::new(ec2.clone()))
        .service(Arc::new(amplify.clone()))
        .service(Arc::new(globalaccelerator.clone()))
        .service(Arc::new(rds.clone()))
        // Both Marketplace services sign as `aws-marketplace`; each claims
        // its own `X-Amz-Target`.
        .service(Arc::new(marketplace_metering.clone()))
        .service(Arc::new(marketplace_entitlement.clone()))
        .service(Arc::new(ram.clone()))
        .service(Arc::new(scep.clone()))
        .service(Arc::new(securityhub.clone()))
        .service(Arc::new(imagebuilder.clone()))
        // Both ELB APIs sign as `elasticloadbalancing`; the Classic one
        // claims requests with its `2012-06-01` Version.
        .service(Arc::new(elb.clone()))
        .service(Arc::new(elb.classic()))
        .service(Arc::new(autoscaling.clone()))
        // SES v2 signs as `ses` too; it claims its `/v2/email/` paths.
        .service(Arc::new(ses.v2()))
        .service(Arc::new(ses.clone()))
        .service(Arc::new(eks.clone()))
        .service(Arc::new(codeartifact.clone()))
        .build();
    Mws {
        gateway,
        route53,
        kms,
        s3,
        s3control,
        lambda,
        logs,
        sqs,
        ssm,
        events,
        secretsmanager,
        sns,
        acm,
        kinesis,
        firehose,
        cloudwatch,
        ec2,
        amplify,
        globalaccelerator,
        marketplace_entitlement,
        marketplace_metering,
        ram,
        scep,
        securityhub,
        imagebuilder,
        elb,
        autoscaling,
        ses,
        rds,
        eks,
        codeartifact,
    }
}

/// Parameter Store's `/aws/reference/secretsmanager/` parameters, read
/// from Secrets Manager as the caller.
struct SsmSecretReferences(SecretsManager);

impl mws_ssm::SecretsManagerReferences for SsmSecretReferences {
    fn get_secret(
        &self,
        ctx: &mws_core::RequestContext,
        secret_id: &str,
        selector: Option<&str>,
    ) -> Result<mws_ssm::ReferencedSecret, mws_core::ServiceError> {
        let s = self.0.read_for_reference(ctx, secret_id, selector)?;
        Ok(mws_ssm::ReferencedSecret {
            arn: s.arn,
            secret_string: s.secret_string,
            last_changed_date: s.last_changed_date,
            describe_secret: s.describe_secret,
        })
    }
}
