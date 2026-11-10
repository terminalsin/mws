//! Elastic Load Balancing v2 through the official Rust SDK: Application and
//! Network Load Balancers whose listeners really proxy to local servers
//! registered as IP targets, rules and actions, health checks, HTTPS with
//! ACM certificates, Lambda targets and CloudWatch metrics.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use aws_sdk_elasticloadbalancingv2::error::ProvideErrorMetadata;
use aws_sdk_elasticloadbalancingv2::types::{
    Action, ActionTypeEnum, Certificate, FixedResponseActionConfig, ForwardActionConfig, LoadBalancerAttribute,
    LoadBalancerTypeEnum, Matcher, PathPatternConditionConfig, ProtocolEnum, RedirectActionConfig,
    RedirectActionStatusCodeEnum, RuleCondition, Tag, TargetDescription, TargetGroupAttribute, TargetGroupTuple,
    TargetHealthStateEnum, TargetTypeEnum,
};
use aws_sdk_elasticloadbalancingv2::Client;
use mws_e2e::Mws;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub(crate) fn code(e: &impl ProvideErrorMetadata) -> String {
    e.code().unwrap_or_default().to_string()
}

pub(crate) fn message(e: &impl ProvideErrorMetadata) -> String {
    e.message().unwrap_or_default().to_string()
}

pub(crate) async fn client(mws: &Mws) -> Client {
    Client::new(&mws.root_sdk_config().await)
}

/// The default VPC and two of its default subnets.
pub(crate) async fn default_network(mws: &Mws) -> (String, Vec<String>) {
    let ec2 = aws_sdk_ec2::Client::new(&mws.root_sdk_config().await);
    let filter = aws_sdk_ec2::types::Filter::builder().name("default-for-az").values("true").build();
    let subnets = ec2.describe_subnets().filters(filter).send().await.unwrap();
    let mut subnets: Vec<_> = subnets.subnets().to_vec();
    subnets.sort_by_key(|s| s.availability_zone().unwrap_or_default().to_string());
    let vpc = subnets[0].vpc_id().unwrap().to_string();
    // Load balancers made without security groups get the VPC's default
    // group, which only lets its own members in: open it, as a load
    // balancer reachable from outside needs.
    let groups = ec2
        .describe_security_groups()
        .filters(aws_sdk_ec2::types::Filter::builder().name("vpc-id").values(&vpc).build())
        .filters(aws_sdk_ec2::types::Filter::builder().name("group-name").values("default").build())
        .send()
        .await
        .unwrap();
    let default_sg = groups.security_groups()[0].group_id().unwrap().to_string();
    let _ = ec2
        .authorize_security_group_ingress()
        .group_id(&default_sg)
        .ip_protocol("-1")
        .cidr_ip("0.0.0.0/0")
        .send()
        .await;
    (vpc, subnets.iter().take(2).map(|s| s.subnet_id().unwrap().to_string()).collect())
}

/// A tiny HTTP server: answers every request with JSON naming the server,
/// the request path and its headers. `/health` answers 200 as well.
pub(crate) struct Backend {
    pub addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Backend {
    pub async fn start(name: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else { return };
                tokio::spawn(async move {
                    loop {
                        let Some((head, _body)) = read_request(&mut s).await else { return };
                        let mut lines = head.split("\r\n");
                        let path = lines.next().unwrap_or_default().split(' ').nth(1).unwrap_or_default().to_string();
                        let headers: BTreeMap<String, String> = lines
                            .filter_map(|l| l.split_once(':'))
                            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
                            .collect();
                        let body = serde_json::json!({ "server": name, "path": path, "headers": headers }).to_string();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nx-backend: {name}\r\n\r\n{body}",
                            body.len()
                        );
                        if s.write_all(resp.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Self { addr, task }
    }

    pub fn port(&self) -> i32 {
        self.addr.port() as i32
    }

    pub fn stop(&self) {
        self.task.abort();
    }
}

/// One HTTP/1.1 request off `s`: `(head, body)`.
async fn read_request(s: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
        let n = s.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let len: usize = head
        .lines()
        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0)))
        .unwrap_or(0);
    let mut body = buf[end + 4..].to_vec();
    while body.len() < len {
        let n = s.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some((head, body))
}

/// A response as a client sees it.
pub(crate) struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Reply {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or_else(|_| panic!("not JSON: {}", self.body))
    }
}

async fn read_reply<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> Reply {
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw).await;
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or_else(|| panic!("no response: {raw:?}"));
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Reply { status, headers, body: String::from_utf8_lossy(&raw[split + 4..]).into_owned() }
}

fn request_text(host: &str, path: &str, headers: &[(&str, &str)]) -> String {
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req
}

/// `GET path` on a listener address.
pub(crate) async fn get(addr: &str, host: &str, path: &str, headers: &[(&str, &str)]) -> Reply {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(request_text(host, path, headers).as_bytes()).await.unwrap();
    read_reply(&mut s).await
}

/// The local address of a listener, from `/_aws/elb/listeners`.
pub(crate) async fn listener_address(mws: &Mws, listener_arn: &str) -> String {
    let (status, list) = mws.control("GET", "/_aws/elb/listeners", None).await;
    assert_eq!(status, 200);
    list.as_array()
        .unwrap()
        .iter()
        .find(|l| l["listener"] == listener_arn)
        .unwrap_or_else(|| panic!("listener {listener_arn} not bound: {list}"))["address"]
        .as_str()
        .unwrap()
        .to_string()
}

pub(crate) async fn wait_for_health(elb: &Client, tg: &str, want: &[(i32, TargetHealthStateEnum)]) {
    for _ in 0..200 {
        let h = elb.describe_target_health().target_group_arn(tg).send().await.unwrap();
        let states: Vec<(i32, TargetHealthStateEnum)> = h
            .target_health_descriptions()
            .iter()
            .map(|d| (d.target().unwrap().port().unwrap(), d.target_health().unwrap().state().unwrap().clone()))
            .collect();
        if want.iter().all(|w| states.contains(w)) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let h = elb.describe_target_health().target_group_arn(tg).send().await.unwrap();
    panic!("targets never reached {want:?}: {:?}", h.target_health_descriptions());
}

pub(crate) fn forward(tg: &str) -> Action {
    Action::builder().r#type(ActionTypeEnum::Forward).target_group_arn(tg).build()
}

pub(crate) async fn ip_target_group(elb: &Client, name: &str, vpc: &str, protocol: ProtocolEnum) -> String {
    let mut req = elb
        .create_target_group()
        .name(name)
        .protocol(protocol.clone())
        .port(80)
        .vpc_id(vpc)
        .target_type(TargetTypeEnum::Ip)
        .health_check_interval_seconds(5)
        .health_check_timeout_seconds(2)
        .healthy_threshold_count(2)
        .unhealthy_threshold_count(2);
    if matches!(protocol, ProtocolEnum::Http | ProtocolEnum::Https) {
        req = req.health_check_path("/health").matcher(Matcher::builder().http_code("200").build());
    }
    let out = req.send().await.unwrap();
    out.target_groups()[0].target_group_arn().unwrap().to_string()
}

#[tokio::test]
async fn application_load_balancer_proxies_to_ip_targets() {
    let mws = Mws::start().await;
    let elb = client(&mws).await;
    let (vpc, subnets) = default_network(&mws).await;
    let a = Backend::start("a").await;
    let b = Backend::start("b").await;

    let lb = elb
        .create_load_balancer()
        .name("web")
        .set_subnets(Some(subnets.clone()))
        .tags(Tag::builder().key("team").value("web").build())
        .send()
        .await
        .unwrap();
    let lb = &lb.load_balancers()[0];
    let lb_arn = lb.load_balancer_arn().unwrap().to_string();
    let dns = lb.dns_name().unwrap().to_string();
    assert!(
        lb_arn.starts_with("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web/"),
        "{lb_arn}"
    );
    assert!(dns.starts_with("web-") && dns.ends_with(".us-east-1.elb.amazonaws.com"), "{dns}");
    assert_eq!(lb.canonical_hosted_zone_id(), Some("Z35SXDOTRQ7X7K"));
    assert_eq!(lb.r#type(), Some(&LoadBalancerTypeEnum::Application));
    assert_eq!(lb.vpc_id(), Some(vpc.as_str()));
    assert_eq!(lb.availability_zones().len(), 2);

    let tg = ip_target_group(&elb, "web", &vpc, ProtocolEnum::Http).await;
    elb.register_targets()
        .target_group_arn(&tg)
        .targets(TargetDescription::builder().id("127.0.0.1").port(a.port()).build())
        .targets(TargetDescription::builder().id("127.0.0.1").port(b.port()).build())
        .send()
        .await
        .unwrap();
    // Not yet in use by a load balancer.
    let h = elb.describe_target_health().target_group_arn(&tg).send().await.unwrap();
    let th = h.target_health_descriptions()[0].target_health().unwrap();
    assert_eq!(th.state(), Some(&TargetHealthStateEnum::Unused));
    assert_eq!(th.reason().map(|r| r.as_str()), Some("Target.NotInUse"));

    let listener = elb
        .create_listener()
        .load_balancer_arn(&lb_arn)
        .protocol(ProtocolEnum::Http)
        .port(80)
        .default_actions(forward(&tg))
        .send()
        .await
        .unwrap();
    let listener_arn = listener.listeners()[0].listener_arn().unwrap().to_string();
    let addr = listener_address(&mws, &listener_arn).await;

    // Rules: a fixed response and a redirect ahead of the default action.
    elb.create_rule()
        .listener_arn(&listener_arn)
        .priority(10)
        .conditions(
            RuleCondition::builder()
                .field("path-pattern")
                .path_pattern_config(PathPatternConditionConfig::builder().values("/teapot*").build())
                .build(),
        )
        .actions(
            Action::builder()
                .r#type(ActionTypeEnum::FixedResponse)
                .fixed_response_config(
                    FixedResponseActionConfig::builder()
                        .status_code("418")
                        .content_type("text/plain")
                        .message_body("short and stout")
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    elb.create_rule()
        .listener_arn(&listener_arn)
        .priority(20)
        .conditions(RuleCondition::builder().field("path-pattern").values("/old/*").build())
        .actions(
            Action::builder()
                .r#type(ActionTypeEnum::Redirect)
                .redirect_config(
                    RedirectActionConfig::builder()
                        .path("/new/#{path}")
                        .status_code(RedirectActionStatusCodeEnum::Http301)
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();

    wait_for_health(
        &elb,
        &tg,
        &[(a.port(), TargetHealthStateEnum::Healthy), (b.port(), TargetHealthStateEnum::Healthy)],
    )
    .await;

    // Round robin across both targets, with the forwarding headers.
    let mut seen = BTreeMap::new();
    for _ in 0..4 {
        let r = get(&addr, &dns, "/hello?x=1", &[]).await;
        assert_eq!(r.status, 200, "{}", r.body);
        let j = r.json();
        assert_eq!(j["path"], "/hello?x=1");
        assert_eq!(j["headers"]["host"], dns.as_str());
        assert_eq!(j["headers"]["x-forwarded-for"], "127.0.0.1");
        assert_eq!(j["headers"]["x-forwarded-proto"], "http");
        assert_eq!(j["headers"]["x-forwarded-port"], "80");
        assert!(j["headers"]["x-amzn-trace-id"].as_str().unwrap().starts_with("Root=1-"));
        *seen.entry(j["server"].as_str().unwrap().to_string()).or_insert(0) += 1;
    }
    assert_eq!(seen.get("a"), Some(&2));
    assert_eq!(seen.get("b"), Some(&2));

    let r = get(&addr, &dns, "/teapot/1", &[]).await;
    assert_eq!((r.status, r.body.as_str()), (418, "short and stout"));
    assert_eq!(r.header("server"), Some("awselb/2.0"));
    let r = get(&addr, &dns, "/old/page?q=1", &[]).await;
    assert_eq!(r.status, 301);
    assert_eq!(r.header("location"), Some(format!("http://{dns}:80/new/old/page?q=1").as_str()));

    // The gateway routes requests whose Host is the load balancer's name.
    let (status, headers, body) = mws.raw("GET", "/via-gateway", &[("Host", dns.as_str())], b"").await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert!(headers.iter().any(|(k, v)| k == "x-backend" && (v == "a" || v == "b")));

    // Stickiness through the AWSALB cookie.
    elb.modify_target_group_attributes()
        .target_group_arn(&tg)
        .attributes(TargetGroupAttribute::builder().key("stickiness.enabled").value("true").build())
        .attributes(TargetGroupAttribute::builder().key("stickiness.type").value("lb_cookie").build())
        .send()
        .await
        .unwrap();
    let first = get(&addr, &dns, "/", &[]).await;
    let cookie = first.header("set-cookie").expect("AWSALB cookie").split(';').next().unwrap().to_string();
    assert!(cookie.starts_with("AWSALB="), "{cookie}");
    let server = first.json()["server"].clone();
    for _ in 0..3 {
        assert_eq!(get(&addr, &dns, "/", &[("Cookie", &cookie)]).await.json()["server"], server);
    }

    // A target that stops answering fails its health checks; traffic goes
    // to the healthy one only.
    b.stop();
    wait_for_health(&elb, &tg, &[(b.port(), TargetHealthStateEnum::Unhealthy)]).await;
    let h = elb.describe_target_health().target_group_arn(&tg).send().await.unwrap();
    let bad = h.target_health_descriptions().iter().find(|d| d.target().unwrap().port() == Some(b.port())).unwrap();
    assert_eq!(bad.target_health().unwrap().reason().map(|r| r.as_str()), Some("Target.FailedHealthChecks"));
    for _ in 0..3 {
        assert_eq!(get(&addr, &dns, "/", &[]).await.json()["server"], "a");
    }

    // Deregistering drains the target for the deregistration delay.
    elb.deregister_targets()
        .target_group_arn(&tg)
        .targets(TargetDescription::builder().id("127.0.0.1").port(b.port()).build())
        .send()
        .await
        .unwrap();
    let h = elb.describe_target_health().target_group_arn(&tg).send().await.unwrap();
    let d = h.target_health_descriptions().iter().find(|d| d.target().unwrap().port() == Some(b.port())).unwrap();
    assert_eq!(d.target_health().unwrap().state(), Some(&TargetHealthStateEnum::Draining));

    // With every target gone, the load balancer answers 503 itself.
    elb.modify_target_group_attributes()
        .target_group_arn(&tg)
        .attributes(TargetGroupAttribute::builder().key("deregistration_delay.timeout_seconds").value("0").build())
        .send()
        .await
        .unwrap();
    elb.deregister_targets()
        .target_group_arn(&tg)
        .targets(TargetDescription::builder().id("127.0.0.1").port(a.port()).build())
        .send()
        .await
        .unwrap();
    let r = get(&addr, &dns, "/", &[]).await;
    assert_eq!(r.status, 503);
    assert!(r.body.contains("503 Service Temporarily Unavailable"), "{}", r.body);

    // CloudWatch has the load balancer's and target group's metrics.
    let cw = aws_sdk_cloudwatch::Client::new(&mws.root_sdk_config().await);
    let lb_dim = lb_arn.split_once(":loadbalancer/").unwrap().1.to_string();
    let tg_dim = tg.split_once(':').map(|_| tg.rsplit_once(':').unwrap().1.to_string()).unwrap();
    let metrics = cw.list_metrics().namespace("AWS/ApplicationELB").send().await.unwrap();
    let has = |name: &str, dims: &[(&str, &str)]| {
        metrics.metrics().iter().any(|m| {
            m.metric_name() == Some(name)
                && dims
                    .iter()
                    .all(|(k, v)| m.dimensions().iter().any(|d| d.name() == Some(*k) && d.value() == Some(*v)))
                && m.dimensions().len() == dims.len()
        })
    };
    assert!(has("RequestCount", &[("LoadBalancer", &lb_dim)]), "{:?}", metrics.metrics());
    assert!(has("HTTPCode_Target_2XX_Count", &[("LoadBalancer", &lb_dim)]));
    assert!(has("HTTPCode_ELB_4XX_Count", &[("LoadBalancer", &lb_dim)]));
    assert!(has("HTTPCode_ELB_3XX_Count", &[("LoadBalancer", &lb_dim)]));
    assert!(has("HTTPCode_ELB_503_Count", &[("LoadBalancer", &lb_dim)]));
    assert!(has("TargetResponseTime", &[("TargetGroup", &tg_dim), ("LoadBalancer", &lb_dim)]));
    assert!(has("RequestCountPerTarget", &[("TargetGroup", &tg_dim)]));
    let stats = cw
        .get_metric_statistics()
        .namespace("AWS/ApplicationELB")
        .metric_name("RequestCount")
        .dimensions(aws_sdk_cloudwatch::types::Dimension::builder().name("LoadBalancer").value(&lb_dim).build())
        .start_time(aws_sdk_cloudwatch::primitives::DateTime::from_secs(chrono::Utc::now().timestamp() - 600))
        .end_time(aws_sdk_cloudwatch::primitives::DateTime::from_secs(chrono::Utc::now().timestamp() + 60))
        .period(3600)
        .statistics(aws_sdk_cloudwatch::types::Statistic::Sum)
        .send()
        .await
        .unwrap();
    let total: f64 = stats.datapoints().iter().filter_map(|d| d.sum()).sum();
    assert!(total >= 12.0, "RequestCount {total}");

    // Deleting the load balancer closes its listener.
    elb.delete_load_balancer().load_balancer_arn(&lb_arn).send().await.unwrap();
    assert!(TcpStream::connect(&addr).await.is_err());
    a.stop();
}

#[tokio::test]
async fn weighted_target_groups_and_rule_conditions() {
    let mws = Mws::start().await;
    let elb = client(&mws).await;
    let (vpc, subnets) = default_network(&mws).await;
    let blue = Backend::start("blue").await;
    let green = Backend::start("green").await;
    let lb = elb.create_load_balancer().name("canary").set_subnets(Some(subnets)).send().await.unwrap();
    let lb_arn = lb.load_balancers()[0].load_balancer_arn().unwrap().to_string();
    let dns = lb.load_balancers()[0].dns_name().unwrap().to_string();
    let tg_blue = ip_target_group(&elb, "blue", &vpc, ProtocolEnum::Http).await;
    let tg_green = ip_target_group(&elb, "green", &vpc, ProtocolEnum::Http).await;
    for (tg, be) in [(&tg_blue, &blue), (&tg_green, &green)] {
        elb.register_targets()
            .target_group_arn(tg)
            .targets(TargetDescription::builder().id("127.0.0.1").port(be.port()).build())
            .send()
            .await
            .unwrap();
    }
    // All traffic to blue by weight; green only for the beta header.
    let weighted = Action::builder()
        .r#type(ActionTypeEnum::Forward)
        .forward_config(
            ForwardActionConfig::builder()
                .target_groups(TargetGroupTuple::builder().target_group_arn(&tg_blue).weight(1).build())
                .target_groups(TargetGroupTuple::builder().target_group_arn(&tg_green).weight(0).build())
                .build(),
        )
        .build();
    let listener = elb
        .create_listener()
        .load_balancer_arn(&lb_arn)
        .protocol(ProtocolEnum::Http)
        .port(8080)
        .default_actions(weighted)
        .send()
        .await
        .unwrap();
    let listener_arn = listener.listeners()[0].listener_arn().unwrap().to_string();
    let rule = elb
        .create_rule()
        .listener_arn(&listener_arn)
        .priority(5)
        .conditions(
            RuleCondition::builder()
                .field("http-header")
                .http_header_config(
                    aws_sdk_elasticloadbalancingv2::types::HttpHeaderConditionConfig::builder()
                        .http_header_name("X-Channel")
                        .values("beta*")
                        .build(),
                )
                .build(),
        )
        .conditions(
            RuleCondition::builder()
                .field("http-request-method")
                .http_request_method_config(
                    aws_sdk_elasticloadbalancingv2::types::HttpRequestMethodConditionConfig::builder()
                        .values("GET")
                        .build(),
                )
                .build(),
        )
        .actions(forward(&tg_green))
        .send()
        .await
        .unwrap();
    let rule_arn = rule.rules()[0].rule_arn().unwrap().to_string();
    let addr = listener_address(&mws, &listener_arn).await;
    wait_for_health(&elb, &tg_blue, &[(blue.port(), TargetHealthStateEnum::Healthy)]).await;
    wait_for_health(&elb, &tg_green, &[(green.port(), TargetHealthStateEnum::Healthy)]).await;

    for _ in 0..3 {
        assert_eq!(get(&addr, &dns, "/", &[]).await.json()["server"], "blue");
    }
    let r = get(&addr, &dns, "/", &[("X-Channel", "beta-2")]).await;
    assert_eq!(r.json()["server"], "green");
    assert_eq!(r.json()["headers"]["x-forwarded-port"], "8080");

    // Rules list in priority order with the default rule last.
    let rules = elb.describe_rules().listener_arn(&listener_arn).send().await.unwrap();
    let priorities: Vec<_> = rules.rules().iter().map(|r| r.priority().unwrap().to_string()).collect();
    assert_eq!(priorities, ["5", "default"]);
    assert_eq!(rules.rules()[1].is_default(), Some(true));

    // Query-string condition after ModifyRule.
    elb.modify_rule()
        .rule_arn(&rule_arn)
        .conditions(
            RuleCondition::builder()
                .field("query-string")
                .query_string_config(
                    aws_sdk_elasticloadbalancingv2::types::QueryStringConditionConfig::builder()
                        .values(
                            aws_sdk_elasticloadbalancingv2::types::QueryStringKeyValuePair::builder()
                                .key("v")
                                .value("2")
                                .build(),
                        )
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(get(&addr, &dns, "/?v=2", &[]).await.json()["server"], "green");
    assert_eq!(get(&addr, &dns, "/", &[("X-Channel", "beta")]).await.json()["server"], "blue");

    // A target group in use cannot be deleted.
    let err = elb.delete_target_group().target_group_arn(&tg_green).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "ResourceInUse");
    assert!(message(&err).contains("is currently in use by a listener or a rule"), "{}", message(&err));
    blue.stop();
    green.stop();
}

/// A server certificate imported into ACM.
pub(crate) async fn imported_certificate(mws: &Mws, name: &str) -> (String, Vec<u8>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
    params.distinguished_name.push(rcgen::DnType::CommonName, name);
    let cert = params.self_signed(&key).unwrap();
    let acm = aws_sdk_acm::Client::new(&mws.root_sdk_config().await);
    let arn = acm
        .import_certificate()
        .certificate(aws_sdk_acm::primitives::Blob::new(cert.pem().as_bytes()))
        .private_key(aws_sdk_acm::primitives::Blob::new(key.serialize_pem().as_bytes()))
        .send()
        .await
        .unwrap()
        .certificate_arn()
        .unwrap()
        .to_string();
    (arn, cert.der().to_vec())
}

/// Accepts any server certificate and remembers it.
#[derive(Debug, Default)]
struct Remember(std::sync::Mutex<Option<Vec<u8>>>);

impl rustls::client::danger::ServerCertVerifier for Remember {
    fn verify_server_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        *self.0.lock().unwrap() = Some(end_entity.to_vec());
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &rustls_pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &rustls_pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

/// Connect with TLS to `addr` as `sni`: the stream and the certificate the
/// server presented.
pub(crate) async fn tls_connect(
    addr: &str,
    sni: &str,
    client_cert: Option<(Vec<u8>, Vec<u8>)>,
) -> std::io::Result<(tokio_rustls::client::TlsStream<TcpStream>, Vec<u8>)> {
    let verifier = Arc::new(Remember::default());
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone());
    let config = match client_cert {
        Some((cert, key)) => builder
            .with_client_auth_cert(
                vec![rustls_pki_types::CertificateDer::from(cert)],
                rustls_pki_types::PrivateKeyDer::Pkcs8(key.into()),
            )
            .unwrap(),
        None => builder.with_no_client_auth(),
    };
    let tcp = TcpStream::connect(addr).await?;
    let name = rustls_pki_types::ServerName::try_from(sni.to_string()).unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp).await?;
    // Finish the handshake (TLS 1.3 client certificates are checked after it).
    tls.flush().await?;
    let cert = verifier.0.lock().unwrap().clone().unwrap_or_default();
    Ok((tls, cert))
}

/// An HTTPS request with extra headers on a listener address.
pub(crate) async fn https_request(addr: &str, host: &str, path: &str, headers: &[(&str, &str)]) -> Reply {
    let (mut tls, _) = tls_connect(addr, host, None).await.unwrap();
    tls.write_all(request_text(host, path, headers).as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    let _ = tls.read_to_end(&mut raw).await;
    read_reply(&mut raw.as_slice()).await
}

pub(crate) async fn https_get(
    addr: &str,
    host: &str,
    path: &str,
    client_cert: Option<(Vec<u8>, Vec<u8>)>,
) -> std::io::Result<(Reply, Vec<u8>)> {
    let (mut tls, cert) = tls_connect(addr, host, client_cert).await?;
    tls.write_all(request_text(host, path, &[]).as_bytes()).await?;
    let mut raw = Vec::new();
    tls.read_to_end(&mut raw).await?;
    if raw.is_empty() {
        return Err(std::io::Error::other("connection closed"));
    }
    Ok((read_reply(&mut raw.as_slice()).await, cert))
}

#[tokio::test]
async fn https_listener_serves_acm_certificates_by_sni() {
    let mws = Mws::start().await;
    let elb = client(&mws).await;
    let acm = aws_sdk_acm::Client::new(&mws.root_sdk_config().await);
    let (vpc, subnets) = default_network(&mws).await;
    let backend = Backend::start("secure").await;
    let (main_cert, main_der) = imported_certificate(&mws, "app.example.com").await;
    let (extra_cert, extra_der) = imported_certificate(&mws, "api.example.com").await;

    let lb = elb.create_load_balancer().name("secure").set_subnets(Some(subnets)).send().await.unwrap();
    let lb_arn = lb.load_balancers()[0].load_balancer_arn().unwrap().to_string();
    let tg = ip_target_group(&elb, "secure", &vpc, ProtocolEnum::Http).await;
    elb.register_targets()
        .target_group_arn(&tg)
        .targets(TargetDescription::builder().id("127.0.0.1").port(backend.port()).build())
        .send()
        .await
        .unwrap();

    // HTTPS needs a certificate.
    let err = elb
        .create_listener()
        .load_balancer_arn(&lb_arn)
        .protocol(ProtocolEnum::Https)
        .port(443)
        .default_actions(forward(&tg))
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "ValidationError");
    assert!(message(&err).contains("A certificate must be specified for HTTPS listeners"), "{}", message(&err));

    let listener = elb
        .create_listener()
        .load_balancer_arn(&lb_arn)
        .protocol(ProtocolEnum::Https)
        .port(443)
        .certificates(Certificate::builder().certificate_arn(&main_cert).build())
        .default_actions(forward(&tg))
        .send()
        .await
        .unwrap();
    let l = &listener.listeners()[0];
    assert_eq!(l.ssl_policy(), Some("ELBSecurityPolicy-2016-08"));
    let listener_arn = l.listener_arn().unwrap().to_string();
    elb.add_listener_certificates()
        .listener_arn(&listener_arn)
        .certificates(Certificate::builder().certificate_arn(&extra_cert).build())
        .send()
        .await
        .unwrap();
    let certs = elb.describe_listener_certificates().listener_arn(&listener_arn).send().await.unwrap();
    let defaults: Vec<_> =
        certs.certificates().iter().map(|c| (c.certificate_arn().unwrap(), c.is_default())).collect();
    assert!(
        defaults.contains(&(main_cert.as_str(), Some(true))) && defaults.contains(&(extra_cert.as_str(), Some(false))),
        "{defaults:?}"
    );

    // ACM shows the certificate in use, and will not delete it.
    let d = acm.describe_certificate().certificate_arn(&main_cert).send().await.unwrap();
    assert_eq!(d.certificate().unwrap().in_use_by(), std::slice::from_ref(&lb_arn));
    let err = acm.delete_certificate().certificate_arn(&main_cert).send().await.unwrap_err().into_service_error();
    assert_eq!(err.meta().code(), Some("ResourceInUseException"));

    let addr = listener_address(&mws, &listener_arn).await;
    wait_for_health(&elb, &tg, &[(backend.port(), TargetHealthStateEnum::Healthy)]).await;
    let (r, cert) = https_get(&addr, "app.example.com", "/s", None).await.unwrap();
    assert_eq!(cert, main_der);
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["headers"]["x-forwarded-proto"], "https");
    assert_eq!(r.json()["headers"]["x-forwarded-port"], "443");
    let (_, cert) = https_get(&addr, "api.example.com", "/", None).await.unwrap();
    assert_eq!(cert, extra_der, "SNI picks the matching certificate");
    let (_, cert) = https_get(&addr, "other.example.com", "/", None).await.unwrap();
    assert_eq!(cert, main_der, "unknown names get the default certificate");

    // TLS version and cipher headers, when the load balancer adds them.
    elb.modify_load_balancer_attributes()
        .load_balancer_arn(&lb_arn)
        .attributes(
            LoadBalancerAttribute::builder()
                .key("routing.http.x_amzn_tls_version_and_cipher_suite.enabled")
                .value("true")
                .build(),
        )
        .send()
        .await
        .unwrap();
    let (r, _) = https_get(&addr, "app.example.com", "/", None).await.unwrap();
    let tls_version = r.json()["headers"]["x-amzn-tls-version"].as_str().unwrap_or_default().to_string();
    assert!(tls_version.starts_with("TLSv1."), "{}", r.body);
    assert!(r.json()["headers"]["x-amzn-tls-cipher-suite"].as_str().is_some());

    // Removing the listener releases the certificates.
    elb.remove_listener_certificates()
        .listener_arn(&listener_arn)
        .certificates(Certificate::builder().certificate_arn(&extra_cert).build())
        .send()
        .await
        .unwrap();
    elb.delete_listener().listener_arn(&listener_arn).send().await.unwrap();
    let d = acm.describe_certificate().certificate_arn(&main_cert).send().await.unwrap();
    assert!(d.certificate().unwrap().in_use_by().is_empty());
    acm.delete_certificate().certificate_arn(&extra_cert).send().await.unwrap();
    backend.stop();
}

/// A TCP server that answers each connection with what it read first.
async fn echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    let n = match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    let mut out = b"echo:".to_vec();
                    out.extend_from_slice(&buf[..n]);
                    if s.write_all(&out).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr, task)
}

#[tokio::test]
async fn network_load_balancer_relays_tcp_and_proxy_protocol() {
    let mws = Mws::start().await;
    let elb = client(&mws).await;
    let (vpc, subnets) = default_network(&mws).await;
    let (echo, task) = echo_server().await;

    let lb = elb
        .create_load_balancer()
        .name("tcp")
        .r#type(LoadBalancerTypeEnum::Network)
        .set_subnets(Some(subnets[..1].to_vec()))
        .send()
        .await
        .unwrap();
    let lb = &lb.load_balancers()[0];
    let lb_arn = lb.load_balancer_arn().unwrap().to_string();
    assert!(lb_arn.contains(":loadbalancer/net/tcp/"), "{lb_arn}");
    let dns = lb.dns_name().unwrap();
    assert!(dns.starts_with("tcp-") && dns.ends_with(".elb.us-east-1.amazonaws.com"), "{dns}");
    assert_eq!(lb.canonical_hosted_zone_id(), Some("Z26RNL4JYFTOTI"));

    let tg = ip_target_group(&elb, "tcp", &vpc, ProtocolEnum::Tcp).await;
    elb.register_targets()
        .target_group_arn(&tg)
        .targets(TargetDescription::builder().id("127.0.0.1").port(echo.port() as i32).build())
        .send()
        .await
        .unwrap();
    let listener = elb
        .create_listener()
        .load_balancer_arn(&lb_arn)
        .protocol(ProtocolEnum::Tcp)
        .port(9000)
        .default_actions(forward(&tg))
        .send()
        .await
        .unwrap();
    let listener_arn = listener.listeners()[0].listener_arn().unwrap().to_string();
    let addr = listener_address(&mws, &listener_arn).await;
    wait_for_health(&elb, &tg, &[(echo.port() as i32, TargetHealthStateEnum::Healthy)]).await;

    let mut s = TcpStream::connect(&addr).await.unwrap();
    s.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"echo:ping");
    drop(s);

    // Proxy protocol v2: the target sees the header before the payload.
    elb.modify_target_group_attributes()
        .target_group_arn(&tg)
        .attributes(TargetGroupAttribute::builder().key("proxy_protocol_v2.enabled").value("true").build())
        .send()
        .await
        .unwrap();
    let mut s = TcpStream::connect(&addr).await.unwrap();
    let local = s.local_addr().unwrap();
    s.write_all(b"hi").await.unwrap();
    let mut got = Vec::new();
    while got.len() < 5 + 16 + 12 + 2 {
        let n = s.read(&mut buf).await.unwrap();
        assert!(n > 0);
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(&got[..5], b"echo:");
    assert_eq!(&got[5..17], b"\r\n\r\n\0\r\nQUIT\n");
    assert_eq!(got[17], 0x21);
    assert_eq!(got[18], 0x11);
    assert_eq!(&got[21..25], &[127, 0, 0, 1]);
    assert_eq!(u16::from_be_bytes([got[29], got[30]]), local.port());

    let cw = aws_sdk_cloudwatch::Client::new(&mws.root_sdk_config().await);
    // Host counts follow health changes on the next health check tick.
    let mut metrics = cw.list_metrics().namespace("AWS/NetworkELB").send().await.unwrap();
    for _ in 0..40 {
        if metrics.metrics().iter().any(|m| m.metric_name() == Some("HealthyHostCount")) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        metrics = cw.list_metrics().namespace("AWS/NetworkELB").send().await.unwrap();
    }
    let names: Vec<_> = metrics.metrics().iter().filter_map(|m| m.metric_name()).collect();
    for want in ["NewFlowCount", "NewFlowCount_TCP", "ProcessedBytes", "HealthyHostCount", "UnHealthyHostCount"] {
        assert!(names.contains(&want), "{want} in {names:?}");
    }

    // NLB listeners take no HTTP protocols.
    let err = elb
        .create_listener()
        .load_balancer_arn(&lb_arn)
        .protocol(ProtocolEnum::Http)
        .port(80)
        .default_actions(forward(&tg))
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "UnsupportedProtocol");
    task.abort();
}

const LAMBDA_TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

const LAMBDA_APP: &str = r#"
import json

def handler(event, context):
    return {
        "statusCode": 201,
        "statusDescription": "201 Created",
        "isBase64Encoded": False,
        "headers": {"content-type": "application/json", "x-from": "lambda"},
        "body": json.dumps({
            "method": event["httpMethod"],
            "path": event["path"],
            "query": event["queryStringParameters"],
            "tg": event["requestContext"]["elb"]["targetGroupArn"],
            "host": event["headers"]["host"],
        }),
    }
"#;

fn zip(files: &[(&str, &str)]) -> Vec<u8> {
    use std::io::Write;
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        for (name, body) in files {
            z.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
            z.write_all(body.as_bytes()).unwrap();
        }
        z.finish().unwrap();
    }
    buf.into_inner()
}

#[tokio::test]
async fn lambda_targets_receive_alb_events() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let elb = Client::new(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let (_, subnets) = default_network(&mws).await;

    let role = iam.create_role().role_name("alb-fn").assume_role_policy_document(LAMBDA_TRUST).send().await.unwrap();
    let function_arn = lambda
        .create_function()
        .function_name("alb-fn")
        .runtime(aws_sdk_lambda::types::Runtime::Python312)
        .role(role.role().unwrap().arn())
        .handler("app.handler")
        .code(
            aws_sdk_lambda::types::FunctionCode::builder()
                .zip_file(aws_sdk_lambda::primitives::Blob::new(zip(&[("app.py", LAMBDA_APP)])))
                .build(),
        )
        .send()
        .await
        .unwrap()
        .function_arn()
        .unwrap()
        .to_string();
    mws_e2e::function_active(&lambda, "alb-fn").await;

    let tg =
        elb.create_target_group().name("fn").target_type(TargetTypeEnum::Lambda).send().await.unwrap().target_groups()
            [0]
        .clone();
    assert_eq!(tg.protocol(), None);
    assert_eq!(tg.health_check_enabled(), Some(false));
    let tg_arn = tg.target_group_arn().unwrap().to_string();

    // ELB must be allowed to invoke the function first.
    let err = elb
        .register_targets()
        .target_group_arn(&tg_arn)
        .targets(TargetDescription::builder().id(&function_arn).build())
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "AccessDenied");
    assert!(
        message(&err).contains("elasticloadbalancing principal does not have permission to invoke"),
        "{}",
        message(&err)
    );
    lambda
        .add_permission()
        .function_name("alb-fn")
        .statement_id("elb")
        .action("lambda:InvokeFunction")
        .principal("elasticloadbalancing.amazonaws.com")
        .source_arn(&tg_arn)
        .send()
        .await
        .unwrap();
    elb.register_targets()
        .target_group_arn(&tg_arn)
        .targets(TargetDescription::builder().id(&function_arn).build())
        .send()
        .await
        .unwrap();

    let lb = elb.create_load_balancer().name("fn").set_subnets(Some(subnets)).send().await.unwrap();
    let lb_arn = lb.load_balancers()[0].load_balancer_arn().unwrap().to_string();
    let dns = lb.load_balancers()[0].dns_name().unwrap().to_string();
    let listener = elb
        .create_listener()
        .load_balancer_arn(&lb_arn)
        .protocol(ProtocolEnum::Http)
        .port(80)
        .default_actions(forward(&tg_arn))
        .send()
        .await
        .unwrap();
    let addr = listener_address(&mws, listener.listeners()[0].listener_arn().unwrap()).await;

    let r = get(&addr, &dns, "/orders?id=7", &[]).await;
    assert_eq!(r.status, 201, "{}", r.body);
    assert_eq!(r.header("x-from"), Some("lambda"));
    let j = r.json();
    assert_eq!(j["method"], "GET");
    assert_eq!(j["path"], "/orders");
    assert_eq!(j["query"]["id"], "7");
    assert_eq!(j["tg"], tg_arn.as_str());
    assert_eq!(j["host"], dns.as_str());

    let h = elb.describe_target_health().target_group_arn(&tg_arn).send().await.unwrap();
    let th = h.target_health_descriptions()[0].target_health().unwrap();
    assert_eq!(th.state(), Some(&TargetHealthStateEnum::Unavailable));
    assert_eq!(th.reason().map(|r| r.as_str()), Some("Target.HealthCheckDisabled"));
}

/// Whether a plain HTTP request to `addr` gets an answer (the load
/// balancer's security groups drop disallowed connections).
async fn answers(addr: &str) -> bool {
    let Ok(mut s) = TcpStream::connect(addr).await else { return false };
    if s.write_all(request_text("sg.example.com", "/", &[]).as_bytes()).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 16];
    matches!(tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await, Ok(Ok(n)) if n > 0)
}

#[tokio::test]
async fn security_groups_filter_listener_traffic() {
    let mws = Mws::start().await;
    let elb = client(&mws).await;
    let ec2 = aws_sdk_ec2::Client::new(&mws.root_sdk_config().await);
    let (vpc, subnets) = default_network(&mws).await;
    let sg = ec2.create_security_group().group_name("alb-front").description("ALB").vpc_id(&vpc).send().await.unwrap();
    let sg = sg.group_id().unwrap().to_string();

    let lb = elb
        .create_load_balancer()
        .name("guarded")
        .set_subnets(Some(subnets))
        .security_groups(&sg)
        .send()
        .await
        .unwrap();
    let lb_arn = lb.load_balancers()[0].load_balancer_arn().unwrap().to_string();
    let listener = elb
        .create_listener()
        .load_balancer_arn(&lb_arn)
        .protocol(ProtocolEnum::Http)
        .port(80)
        .default_actions(
            Action::builder()
                .r#type(ActionTypeEnum::FixedResponse)
                .fixed_response_config(FixedResponseActionConfig::builder().status_code("204").build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    let addr = listener_address(&mws, listener.listeners()[0].listener_arn().unwrap()).await;

    // A new security group lets nothing in.
    assert!(!answers(&addr).await);
    // A rule for another port doesn't help; one for the listener's does.
    ec2.authorize_security_group_ingress()
        .group_id(&sg)
        .ip_protocol("tcp")
        .from_port(443)
        .to_port(443)
        .cidr_ip("0.0.0.0/0")
        .send()
        .await
        .unwrap();
    assert!(!answers(&addr).await);
    ec2.authorize_security_group_ingress()
        .group_id(&sg)
        .ip_protocol("tcp")
        .from_port(80)
        .to_port(80)
        .cidr_ip("127.0.0.0/8")
        .send()
        .await
        .unwrap();
    assert!(answers(&addr).await);
    let reply = get(&addr, "sg.example.com", "/", &[]).await;
    assert_eq!(reply.status, 204);
}
