//! Service Quotas through the official Rust SDK: AWS's quota codes and
//! defaults, increase requests that are approved and then enforced by the
//! services (EC2 vCPUs, IAM managed policies, Lambda concurrency),
//! `AWS/Usage` metrics with CloudWatch's `SERVICE_QUOTA()`, utilization
//! reports, tags, automatic management and the organization's template;
//! large increases that become support cases and are decided through the
//! control endpoint, and quotas of ECS, Fargate, ECR and Lambda.

use std::time::Duration;

use aws_sdk_cloudwatch::types::{Dimension, Metric, MetricDataQuery, MetricStat};
use aws_sdk_ec2::types::{Filter, InstanceType};
use aws_sdk_eks::client::Waiters;
use aws_sdk_servicequotas::error::ProvideErrorMetadata;
use aws_sdk_servicequotas::types::{RequestStatus, Tag};
use aws_sdk_servicequotas::Client;
use mws_e2e::{sts_config, user_with_policy, Mws};

const ACCOUNT: &str = "123456789012";
const VCPUS: &str = "L-1216C47A";

fn code<E: ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

async fn alpine_ami(ec2: &aws_sdk_ec2::Client) -> String {
    let filter = Filter::builder().name("name").values("mws-alpine-*").build();
    let images = ec2.describe_images().owners("amazon").filters(filter).send().await.unwrap();
    images.images()[0].image_id().unwrap().to_string()
}

async fn run(ec2: &aws_sdk_ec2::Client, ami: &str, count: i32) -> Result<(), String> {
    ec2.run_instances()
        .image_id(ami)
        .instance_type(InstanceType::T3Micro)
        .min_count(count)
        .max_count(count)
        .send()
        .await
        .map(|_| ())
        .map_err(|e| format!("{}: {}", e.code().unwrap_or_default(), e.message().unwrap_or_default()))
}

/// MWS with AWS's exact new-account quotas (5 standard vCPUs).
async fn new_account() -> Mws {
    Mws::start_with(mws::Config { quota_profile: mws::QuotaProfile::NewAccount, ..Default::default() }).await
}

/// Wait for a request to be approved.
async fn approved(sq: &Client, id: &str) {
    for _ in 0..50 {
        let r = sq.get_requested_service_quota_change().request_id(id).send().await.unwrap();
        if r.requested_quota().unwrap().status() == Some(&RequestStatus::Approved) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("request {id} was never approved");
}

#[tokio::test]
async fn catalog_and_defaults() {
    let mws = Mws::start().await;
    let sq = Client::new(&mws.root_sdk_config().await);

    let services = sq.list_services().max_results(100).send().await.unwrap();
    let codes: Vec<_> = services.services().iter().filter_map(|s| s.service_code()).collect();
    for c in ["ec2", "vpc", "s3", "lambda", "iam", "eks", "rds", "elasticache"] {
        assert!(codes.contains(&c), "{c} missing from {codes:?}");
    }
    let page = sq.list_services().max_results(2).send().await.unwrap();
    assert_eq!(page.services().len(), 2);
    let next = sq.list_services().max_results(2).next_token(page.next_token().unwrap()).send().await.unwrap();
    assert_ne!(next.services()[0].service_code(), page.services()[0].service_code());
    let e = sq.list_services().next_token("garbage").send().await.unwrap_err();
    assert_eq!(code(&e), "InvalidPaginationTokenException");

    let d = sq.get_aws_default_service_quota().service_code("ec2").quota_code(VCPUS).send().await.unwrap();
    let q = d.quota().unwrap();
    assert_eq!(q.value(), Some(5.0));
    assert_eq!(q.quota_name(), Some("Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances"));
    assert!(q.adjustable());
    // By default accounts start established, with room for real fleets.
    let applied = sq.get_service_quota().service_code("ec2").quota_code(VCPUS).send().await.unwrap();
    assert_eq!(applied.quota().unwrap().value(), Some(1152.0));
    assert_eq!(q.quota_arn(), Some(format!("arn:aws:servicequotas:us-east-1:{ACCOUNT}:ec2/{VCPUS}").as_str()));
    let metric = q.usage_metric().unwrap();
    assert_eq!(metric.metric_namespace(), Some("AWS/Usage"));
    assert_eq!(metric.metric_name(), Some("ResourceCount"));
    assert_eq!(metric.metric_dimensions().unwrap().get("Class").map(String::as_str), Some("Standard/OnDemand"));

    let vpc = sq.list_aws_default_service_quotas().service_code("vpc").send().await.unwrap();
    assert!(vpc.quotas().iter().any(|q| q.quota_code() == Some("L-F678F1CE") && q.value() == Some(5.0)));
    let roles = sq.get_service_quota().service_code("iam").quota_code("L-FE177D64").send().await.unwrap();
    assert!(roles.quota().unwrap().global_quota());

    let e = sq.get_service_quota().service_code("nope").quota_code("L-12345678").send().await.unwrap_err();
    assert_eq!(code(&e), "NoSuchResourceException");
    let e = sq.get_service_quota().service_code("ec2").quota_code("L-00000000").send().await.unwrap_err();
    assert_eq!(code(&e), "NoSuchResourceException");
}

#[tokio::test]
async fn increases_are_approved_and_enforced() {
    let mws = new_account().await;
    let cfg = mws.root_sdk_config().await;
    let sq = Client::new(&cfg);
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let ami = alpine_ami(&ec2).await;

    // t3.micro has 2 vCPUs: two fit in the default 5, a third does not.
    run(&ec2, &ami, 2).await.unwrap();
    let e = run(&ec2, &ami, 1).await.unwrap_err();
    assert!(
        e.starts_with("VcpuLimitExceeded: You have requested more vCPU capacity than your current vCPU limit of 5"),
        "{e}"
    );

    let e = sq
        .request_service_quota_increase()
        .service_code("ec2")
        .quota_code(VCPUS)
        .desired_value(4.0)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e), "IllegalArgumentException");
    let e = sq
        .request_service_quota_increase()
        .service_code("lambda")
        .quota_code("L-9FEEFFC0")
        .desired_value(2000.0)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e), "IllegalArgumentException");

    let req = sq
        .request_service_quota_increase()
        .service_code("ec2")
        .quota_code(VCPUS)
        .desired_value(32.0)
        .send()
        .await
        .unwrap();
    let req = req.requested_quota().unwrap();
    assert_eq!(req.status(), Some(&RequestStatus::Pending));
    assert_eq!(req.desired_value(), Some(32.0));
    assert!(req.requester().unwrap().contains(ACCOUNT));
    let id = req.id().unwrap().to_string();
    let e = sq
        .request_service_quota_increase()
        .service_code("ec2")
        .quota_code(VCPUS)
        .desired_value(64.0)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e), "ResourceAlreadyExistsException");
    approved(&sq, &id).await;

    let applied = sq.get_service_quota().service_code("ec2").quota_code(VCPUS).send().await.unwrap();
    assert_eq!(applied.quota().unwrap().value(), Some(32.0));
    let default = sq.get_aws_default_service_quota().service_code("ec2").quota_code(VCPUS).send().await.unwrap();
    assert_eq!(default.quota().unwrap().value(), Some(5.0));
    run(&ec2, &ami, 1).await.unwrap();

    let history = sq.list_requested_service_quota_change_history().service_code("ec2").send().await.unwrap();
    assert_eq!(history.requested_quotas().len(), 1);
    let by_quota = sq
        .list_requested_service_quota_change_history_by_quota()
        .service_code("ec2")
        .quota_code(VCPUS)
        .status(RequestStatus::Approved)
        .send()
        .await
        .unwrap();
    assert_eq!(by_quota.requested_quotas()[0].id(), Some(id.as_str()));

    // AWS/Usage: the vCPUs in use, and SERVICE_QUOTA() over them.
    let cw = aws_sdk_cloudwatch::Client::new(&cfg);
    let dims = [("Class", "Standard/OnDemand"), ("Resource", "vCPU"), ("Service", "EC2"), ("Type", "Resource")];
    let metric = Metric::builder()
        .namespace("AWS/Usage")
        .metric_name("ResourceCount")
        .set_dimensions(Some(dims.iter().map(|(k, v)| Dimension::builder().name(*k).value(*v).build()).collect()))
        .build();
    let now = aws_sdk_cloudwatch::primitives::DateTime::from_secs(chrono::Utc::now().timestamp() + 60);
    let start = aws_sdk_cloudwatch::primitives::DateTime::from_secs(chrono::Utc::now().timestamp() - 600);
    let data = cw
        .get_metric_data()
        .metric_data_queries(
            MetricDataQuery::builder()
                .id("usage")
                .metric_stat(MetricStat::builder().metric(metric).period(60).stat("Maximum").build())
                .build(),
        )
        .metric_data_queries(MetricDataQuery::builder().id("quota").expression("SERVICE_QUOTA(usage)").build())
        .metric_data_queries(
            MetricDataQuery::builder().id("pct").expression("usage / SERVICE_QUOTA(usage) * 100").build(),
        )
        .start_time(start)
        .end_time(now)
        .send()
        .await
        .unwrap();
    let values = |id: &str| data.metric_data_results().iter().find(|r| r.id() == Some(id)).unwrap().values().to_vec();
    assert!(values("usage").contains(&6.0), "{:?}", values("usage"));
    assert!(values("quota").iter().all(|v| *v == 32.0) && !values("quota").is_empty());
    assert!(values("pct").contains(&18.75), "{:?}", values("pct"));

    // Every call is counted in AWS/Usage CallCount.
    let calls = cw.list_metrics().namespace("AWS/Usage").metric_name("CallCount").send().await.unwrap();
    assert!(calls
        .metrics()
        .iter()
        .any(|m| m.dimensions().iter().any(|d| d.name() == Some("Resource") && d.value() == Some("RunInstances"))));

    // Utilization report.
    let started = sq.start_quota_utilization_report().send().await.unwrap();
    let report = sq.get_quota_utilization_report().report_id(started.report_id().unwrap()).send().await.unwrap();
    assert_eq!(report.status().map(|s| s.as_str()), Some("COMPLETED"));
    let vcpu = report.quotas().iter().find(|q| q.quota_code() == Some(VCPUS)).unwrap();
    assert_eq!(vcpu.utilization(), Some(18.75));
    assert_eq!(vcpu.applied_value(), Some(32.0));
}

#[tokio::test]
async fn iam_lambda_and_elastic_ip_limits_follow_quotas() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let sq = Client::new(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
    iam.create_role().role_name("many").assume_role_policy_document(trust).send().await.unwrap();
    let mut policies = Vec::new();
    for i in 0..11 {
        let doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#;
        let p = iam.create_policy().policy_name(format!("p{i}")).policy_document(doc).send().await.unwrap();
        policies.push(p.policy().unwrap().arn().unwrap().to_string());
    }
    for p in &policies[..10] {
        iam.attach_role_policy().role_name("many").policy_arn(p).send().await.unwrap();
    }
    let e = iam.attach_role_policy().role_name("many").policy_arn(&policies[10]).send().await.unwrap_err();
    assert_eq!(e.code(), Some("LimitExceeded"));
    assert_eq!(e.message(), Some("Cannot exceed quota for PoliciesPerRole: 10"));
    let r = sq
        .request_service_quota_increase()
        .service_code("iam")
        .quota_code("L-0DA4ABF3")
        .desired_value(20.0)
        .send()
        .await
        .unwrap();
    approved(&sq, r.requested_quota().unwrap().id().unwrap()).await;
    iam.attach_role_policy().role_name("many").policy_arn(&policies[10]).send().await.unwrap();

    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let settings = lambda.get_account_settings().send().await.unwrap();
    assert_eq!(settings.account_limit().unwrap().concurrent_executions(), 1000);
    let r = sq
        .request_service_quota_increase()
        .service_code("lambda")
        .quota_code("L-B99A9384")
        .desired_value(3000.0)
        .send()
        .await
        .unwrap();
    approved(&sq, r.requested_quota().unwrap().id().unwrap()).await;
    let settings = lambda.get_account_settings().send().await.unwrap();
    assert_eq!(settings.account_limit().unwrap().concurrent_executions(), 3000);

    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    for _ in 0..5 {
        ec2.allocate_address().send().await.unwrap();
    }
    let e = ec2.allocate_address().send().await.unwrap_err();
    assert_eq!(e.code(), Some("AddressLimitExceeded"));
    let r = sq
        .request_service_quota_increase()
        .service_code("ec2")
        .quota_code("L-0263D0A3")
        .desired_value(6.0)
        .send()
        .await
        .unwrap();
    approved(&sq, r.requested_quota().unwrap().id().unwrap()).await;
    ec2.allocate_address().send().await.unwrap();

    // Four VPCs fit next to the default one.
    for i in 0..4 {
        ec2.create_vpc().cidr_block(format!("10.{i}.0.0/16")).send().await.unwrap();
    }
    let e = ec2.create_vpc().cidr_block("10.9.0.0/16").send().await.unwrap_err();
    assert_eq!(e.code(), Some("VpcLimitExceeded"));
}

#[tokio::test]
async fn tags_support_cases_and_auto_management() {
    let mws = Mws::start().await;
    let sq = Client::new(&mws.root_sdk_config().await);
    let arn = format!("arn:aws:servicequotas:us-east-1:{ACCOUNT}:ec2/{VCPUS}");
    sq.tag_resource()
        .resource_arn(&arn)
        .tags(Tag::builder().key("team").value("infra").build().unwrap())
        .send()
        .await
        .unwrap();
    let tags = sq.list_tags_for_resource().resource_arn(&arn).send().await.unwrap();
    assert_eq!(tags.tags()[0].key(), "team");
    sq.untag_resource().resource_arn(&arn).tag_keys("team").send().await.unwrap();
    assert!(sq.list_tags_for_resource().resource_arn(&arn).send().await.unwrap().tags().is_empty());
    let e = sq
        .tag_resource()
        .resource_arn(format!("arn:aws:servicequotas:us-east-1:{ACCOUNT}:ec2/L-00000000"))
        .tags(Tag::builder().key("a").value("b").build().unwrap())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e), "NoSuchResourceException");

    let r = sq
        .request_service_quota_increase()
        .service_code("vpc")
        .quota_code("L-F678F1CE")
        .desired_value(10.0)
        .send()
        .await
        .unwrap();
    let id = r.requested_quota().unwrap().id().unwrap().to_string();
    sq.create_support_case().request_id(&id).send().await.unwrap();
    let got = sq.get_requested_service_quota_change().request_id(&id).send().await.unwrap();
    assert_eq!(got.requested_quota().unwrap().status(), Some(&RequestStatus::CaseOpened));
    assert!(got.requested_quota().unwrap().case_id().is_some());
    let e = sq.create_support_case().request_id(&id).send().await.unwrap_err();
    assert_eq!(code(&e), "ResourceAlreadyExistsException");
    // Support cases are reviewed by people (a day by default); approve it.
    let (status, _) =
        mws.control("POST", &format!("/_aws/servicequotas/requests/{id}"), Some(r#"{"status":"APPROVED"}"#)).await;
    assert_eq!(status, 200);
    approved(&sq, &id).await;

    let off = sq.get_auto_management_configuration().send().await.unwrap();
    assert_eq!(off.opt_in_status().map(|s| s.as_str()), Some("DISABLED"));
    let e = sq.stop_auto_management().send().await.unwrap_err();
    assert_eq!(code(&e), "InvalidResourceStateException");
    sq.start_auto_management()
        .opt_in_level(aws_sdk_servicequotas::types::OptInLevel::Account)
        .opt_in_type(aws_sdk_servicequotas::types::OptInType::NotifyOnly)
        .exclusion_list("ec2", vec![VCPUS.to_string()])
        .send()
        .await
        .unwrap();
    sq.update_auto_management()
        .opt_in_type(aws_sdk_servicequotas::types::OptInType::NotifyAndAdjust)
        .send()
        .await
        .unwrap();
    let on = sq.get_auto_management_configuration().send().await.unwrap();
    assert_eq!(on.opt_in_status().map(|s| s.as_str()), Some("ENABLED"));
    assert_eq!(on.opt_in_type().map(|s| s.as_str()), Some("NotifyAndAdjust"));
    assert_eq!(on.exclusion_list().unwrap()["ec2"][0].quota_code(), Some(VCPUS));
    sq.stop_auto_management().send().await.unwrap();
}

#[tokio::test]
async fn organization_template_applies_to_new_accounts() {
    let mws = new_account().await;
    let cfg = mws.root_sdk_config().await;
    let sq = Client::new(&cfg);
    let e = sq.associate_service_quota_template().send().await.unwrap_err();
    assert_eq!(code(&e), "NoAvailableOrganizationException");

    let orgs = aws_sdk_organizations::Client::new(&cfg);
    orgs.create_organization().send().await.unwrap();
    sq.associate_service_quota_template().send().await.unwrap();
    let status = sq.get_association_for_service_quota_template().send().await.unwrap();
    assert_eq!(status.service_quota_template_association_status().map(|s| s.as_str()), Some("ASSOCIATED"));
    sq.put_service_quota_increase_request_into_template()
        .service_code("ec2")
        .quota_code(VCPUS)
        .aws_region("us-east-1")
        .desired_value(64.0)
        .send()
        .await
        .unwrap();
    let got = sq
        .get_service_quota_increase_request_from_template()
        .service_code("ec2")
        .quota_code(VCPUS)
        .aws_region("us-east-1")
        .send()
        .await
        .unwrap();
    assert_eq!(got.service_quota_increase_request_in_template().unwrap().desired_value(), Some(64.0));
    let listed = sq.list_service_quota_increase_requests_in_template().send().await.unwrap();
    assert_eq!(listed.service_quota_increase_request_in_template_list().len(), 1);

    let created = orgs.create_account().email("member@example.com").account_name("member").send().await.unwrap();
    let request_id = created.create_account_status().unwrap().id().unwrap();
    let status = orgs.describe_create_account_status().create_account_request_id(request_id).send().await.unwrap();
    let member = status.create_account_status().unwrap().account_id().unwrap().to_string();

    let (_, admin) = user_with_policy(
        &mws,
        "admin",
        Some(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#),
    )
    .await;
    let creds = aws_sdk_sts::Client::new(&admin)
        .assume_role()
        .role_arn(format!("arn:aws:iam::{member}:role/OrganizationAccountAccessRole"))
        .role_session_name("ops")
        .send()
        .await
        .unwrap();
    let member_sq = Client::new(&sts_config(&mws, creds.credentials().unwrap()).await);
    let history = member_sq.list_requested_service_quota_change_history().send().await.unwrap();
    let id = history.requested_quotas()[0].id().unwrap().to_string();
    approved(&member_sq, &id).await;
    let applied = member_sq.get_service_quota().service_code("ec2").quota_code(VCPUS).send().await.unwrap();
    assert_eq!(applied.quota().unwrap().value(), Some(64.0));
    // The management account's own value is unchanged.
    let own = sq.get_service_quota().service_code("ec2").quota_code(VCPUS).send().await.unwrap();
    assert_eq!(own.quota().unwrap().value(), Some(5.0));

    sq.delete_service_quota_increase_request_from_template()
        .service_code("ec2")
        .quota_code(VCPUS)
        .aws_region("us-east-1")
        .send()
        .await
        .unwrap();
    sq.disassociate_service_quota_template().send().await.unwrap();
    let e = sq.disassociate_service_quota_template().send().await.unwrap_err();
    assert_eq!(code(&e), "ServiceQuotaTemplateNotInUseException");
}

/// Raise a quota and wait for the increase to apply.
async fn raise(sq: &Client, service: &str, quota: &str, value: f64) {
    let r = sq
        .request_service_quota_increase()
        .service_code(service)
        .quota_code(quota)
        .desired_value(value)
        .send()
        .await
        .unwrap();
    approved(sq, r.requested_quota().unwrap().id().unwrap()).await;
}

#[tokio::test]
async fn auto_scaling_elb_rds_and_eks_limits_follow_quotas() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let sq = Client::new(&config);

    // Every quota of a service, with applied values.
    let elb_quotas = sq.list_service_quotas().service_code("elasticloadbalancing").send().await.unwrap();
    let alb = elb_quotas.quotas().iter().find(|q| q.quota_code() == Some("L-53DA6B97")).unwrap();
    assert_eq!(alb.value(), Some(50.0));
    assert_eq!(alb.quota_name(), Some("Application Load Balancers per Region"));

    raise(&sq, "autoscaling", "L-CDE20ADC", 600.0).await;
    raise(&sq, "autoscaling", "L-6B80B8FA", 250.0).await;
    raise(&sq, "elasticloadbalancing", "L-53DA6B97", 60.0).await;
    raise(&sq, "elasticloadbalancing", "L-B22855CB", 3500.0).await;
    raise(&sq, "rds", "L-7B6409FD", 80.0).await;
    raise(&sq, "rds", "L-952B80B8", 45.0).await;

    // The services' own account-limit APIs report the applied values.
    let asg = aws_sdk_autoscaling::Client::new(&config);
    let limits = asg.describe_account_limits().send().await.unwrap();
    assert_eq!(limits.max_number_of_auto_scaling_groups(), Some(600));
    assert_eq!(limits.max_number_of_launch_configurations(), Some(250));

    let elb = aws_sdk_elasticloadbalancingv2::Client::new(&config);
    let limits = elb.describe_account_limits().send().await.unwrap();
    let max =
        |name: &str| limits.limits().iter().find(|l| l.name() == Some(name)).and_then(|l| l.max()).map(str::to_string);
    assert_eq!(max("application-load-balancers").as_deref(), Some("60"));
    assert_eq!(max("target-groups").as_deref(), Some("3500"));
    assert_eq!(max("network-load-balancers").as_deref(), Some("50"));

    let rds = aws_sdk_rds::Client::new(&config);
    let attrs = rds.describe_account_attributes().send().await.unwrap();
    let max =
        |name: &str| attrs.account_quotas().iter().find(|q| q.account_quota_name() == Some(name)).and_then(|q| q.max());
    assert_eq!(max("DBInstances"), Some(80));
    assert_eq!(max("DBClusters"), Some(45));
    assert_eq!(max("ManualSnapshots"), Some(100));

    // EKS refuses node groups larger than the nodes-per-group quota.
    let iam = aws_sdk_iam::Client::new(&config);
    let ec2 = aws_sdk_ec2::Client::new(&config);
    let eks = aws_sdk_eks::Client::new(&config);
    let trust = |service: &str| {
        format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"{service}"}},"Action":"sts:AssumeRole"}}]}}"#
        )
    };
    let cluster_role = iam
        .create_role()
        .role_name("eks-cluster")
        .assume_role_policy_document(trust("eks.amazonaws.com"))
        .send()
        .await
        .unwrap();
    let node_role = iam
        .create_role()
        .role_name("eks-node")
        .assume_role_policy_document(trust("ec2.amazonaws.com"))
        .send()
        .await
        .unwrap();
    let vpc =
        ec2.create_vpc().cidr_block("10.30.0.0/16").send().await.unwrap().vpc().unwrap().vpc_id().unwrap().to_string();
    let mut subnets = Vec::new();
    for (i, zone) in ["us-east-1a", "us-east-1b"].iter().enumerate() {
        let s = ec2
            .create_subnet()
            .vpc_id(&vpc)
            .cidr_block(format!("10.30.{i}.0/24"))
            .availability_zone(*zone)
            .send()
            .await
            .unwrap();
        subnets.push(s.subnet().unwrap().subnet_id().unwrap().to_string());
    }
    eks.create_cluster()
        .name("quotas")
        .role_arn(cluster_role.role().unwrap().arn())
        .resources_vpc_config(
            aws_sdk_eks::types::VpcConfigRequest::builder().set_subnet_ids(Some(subnets.clone())).build(),
        )
        .send()
        .await
        .unwrap();
    // EKS clusters take minutes (of emulated time) to become ACTIVE.
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds":600}"#)).await;
    assert_eq!(status, 200);
    eks.wait_until_cluster_active().name("quotas").wait(Duration::from_secs(60)).await.unwrap();
    let nodegroup = |max: i32| {
        eks.create_nodegroup()
            .cluster_name("quotas")
            .nodegroup_name(format!("ng-{max}"))
            .node_role(node_role.role().unwrap().arn())
            .set_subnets(Some(subnets.clone()))
            .scaling_config(
                aws_sdk_eks::types::NodegroupScalingConfig::builder().min_size(0).max_size(max).desired_size(0).build(),
            )
            .send()
    };
    let err = nodegroup(500).await.unwrap_err();
    assert_eq!(err.code(), Some("InvalidParameterException"), "{err:?}");
    raise(&sq, "eks", "L-BD136A63", 600.0).await;
    nodegroup(500).await.unwrap();
}

#[tokio::test]
async fn automatic_management_raises_quotas_near_their_limit() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let sq = Client::new(&config);
    let ec2 = aws_sdk_ec2::Client::new(&config);
    sq.start_auto_management()
        .opt_in_level(aws_sdk_servicequotas::types::OptInLevel::Account)
        .opt_in_type(aws_sdk_servicequotas::types::OptInType::NotifyAndAdjust)
        .exclusion_list("vpc", vec!["L-F678F1CE".to_string()])
        .send()
        .await
        .unwrap();
    // Four of the five Elastic IPs: 80% of the quota.
    for _ in 0..4 {
        ec2.allocate_address().domain(aws_sdk_ec2::types::DomainType::Vpc).send().await.unwrap();
    }
    // Usage is checked once a minute.
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds":61}"#)).await;
    assert_eq!(status, 200);
    let mut raised = None;
    for _ in 0..100 {
        let history = sq.list_requested_service_quota_change_history().service_code("ec2").send().await.unwrap();
        if let Some(r) = history.requested_quotas().iter().find(|r| r.quota_code() == Some("L-0263D0A3")) {
            raised = Some(r.clone());
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let raised = raised.expect("automatic management requested an increase");
    assert_eq!(raised.desired_value(), Some(10.0));
    assert_eq!(raised.request_type().map(|t| t.as_str()), Some("AutomaticManagement"));
    approved(&sq, raised.id().unwrap()).await;
    for _ in 0..6 {
        ec2.allocate_address().domain(aws_sdk_ec2::types::DomainType::Vpc).send().await.unwrap();
    }
}

async fn status_of(sq: &Client, id: &str) -> RequestStatus {
    let r = sq.get_requested_service_quota_change().request_id(id).send().await.unwrap();
    r.requested_quota().unwrap().status().unwrap().clone()
}

#[tokio::test]
async fn large_increases_open_a_case_that_can_be_denied() {
    let mws = Mws::start().await;
    let sq = Client::new(&mws.root_sdk_config().await);
    // Far beyond 20 times the starting value: no automatic approval.
    let r = sq
        .request_service_quota_increase()
        .service_code("ec2")
        .quota_code(VCPUS)
        .desired_value(100_000.0)
        .send()
        .await
        .unwrap();
    let id = r.requested_quota().unwrap().id().unwrap().to_string();
    assert_eq!(r.requested_quota().unwrap().status(), Some(&RequestStatus::Pending));
    let mut opened = false;
    for _ in 0..50 {
        if status_of(&sq, &id).await == RequestStatus::CaseOpened {
            opened = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(opened, "the request became a support case");
    let got = sq.get_requested_service_quota_change().request_id(&id).send().await.unwrap();
    assert!(got.requested_quota().unwrap().case_id().is_some());

    let (status, body) =
        mws.control("POST", &format!("/_aws/servicequotas/requests/{id}"), Some(r#"{"status":"DENIED"}"#)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(status_of(&sq, &id).await, RequestStatus::Denied);
    let applied = sq.get_service_quota().service_code("ec2").quota_code(VCPUS).send().await.unwrap();
    assert_eq!(applied.quota().unwrap().value(), Some(1152.0));
    let (status, _) =
        mws.control("POST", &format!("/_aws/servicequotas/requests/{id}"), Some(r#"{"status":"APPROVED"}"#)).await;
    assert_eq!(status, 409, "a closed request can't be decided again");

    // With automatic approval off, even small requests wait for a decision.
    let (status, review) = mws.control("POST", "/_aws/servicequotas/review", Some(r#"{"autoApprove":false}"#)).await;
    assert_eq!(status, 200);
    assert_eq!(review["autoApprove"], false);
    let r = sq
        .request_service_quota_increase()
        .service_code("lambda")
        .quota_code("L-B99A9384")
        .desired_value(1500.0)
        .send()
        .await
        .unwrap();
    let small = r.requested_quota().unwrap().id().unwrap().to_string();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(status_of(&sq, &small).await, RequestStatus::Pending);
    let (_, listed) = mws.control("GET", "/_aws/servicequotas/requests", None).await;
    assert_eq!(listed["requests"].as_array().unwrap().len(), 2);
    let (status, _) =
        mws.control("POST", &format!("/_aws/servicequotas/requests/{small}"), Some(r#"{"status":"APPROVED"}"#)).await;
    assert_eq!(status, 200);
    let applied = sq.get_service_quota().service_code("lambda").quota_code("L-B99A9384").send().await.unwrap();
    assert_eq!(applied.quota().unwrap().value(), Some(1500.0));

    // Cases are reviewed for a day of emulated time, then end as the
    // policy says.
    mws.control("POST", "/_aws/servicequotas/review", Some(r#"{"autoApprove":true,"caseOutcome":"NOT_APPROVED"}"#))
        .await;
    let r = sq
        .request_service_quota_increase()
        .service_code("vpc")
        .quota_code("L-F678F1CE")
        .desired_value(10.0)
        .send()
        .await
        .unwrap();
    let case = r.requested_quota().unwrap().id().unwrap().to_string();
    sq.create_support_case().request_id(&case).send().await.unwrap();
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds": 90000}"#)).await;
    assert_eq!(status, 200);
    assert_eq!(status_of(&sq, &case).await, RequestStatus::NotApproved);
    let _ = mws.control("POST", "/_mws/clock", Some(r#"{"offsetSeconds": 0}"#)).await;
}

#[tokio::test]
async fn container_quotas_are_in_the_catalogue() {
    let mws = Mws::start().await;
    let sq = Client::new(&mws.root_sdk_config().await);
    let clusters = sq.get_service_quota().service_code("ecs").quota_code("L-21C621EB").send().await.unwrap();
    assert_eq!(clusters.quota().unwrap().quota_name(), Some("Clusters per account"));
    assert_eq!(clusters.quota().unwrap().value(), Some(10000.0));
    let fargate = sq.list_service_quotas().service_code("fargate").send().await.unwrap();
    let vcpu = fargate.quotas().iter().find(|q| q.quota_code() == Some("L-3032A538")).unwrap();
    assert_eq!(vcpu.quota_name(), Some("Fargate On-Demand vCPU resource count"));
    let ecr = sq.get_aws_default_service_quota().service_code("ecr").quota_code("L-03A36CE1").send().await.unwrap();
    assert_eq!(ecr.quota().unwrap().value(), Some(20000.0));
    let services = sq.list_services().send().await.unwrap();
    assert!(services.services().iter().any(|s| s.service_code() == Some("fargate")));
}
