//! Fixed facts about ELB: default attributes, health check defaults,
//! security policies and account limits.

use std::collections::BTreeMap;

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

/// A load balancer's attributes before any `ModifyLoadBalancerAttributes`.
pub fn load_balancer_attributes(ty: &str, scheme: &str, ip_address_type: &str) -> BTreeMap<String, String> {
    match ty {
        "network" => {
            let mut m = map(&[
                ("access_logs.s3.enabled", "false"),
                ("access_logs.s3.bucket", ""),
                ("access_logs.s3.prefix", ""),
                ("deletion_protection.enabled", "false"),
                ("load_balancing.cross_zone.enabled", "false"),
                ("dns_record.client_routing_policy", "any_availability_zone"),
                ("zonal_shift.config.enabled", "false"),
                ("secondary_ips.auto_assigned.per_subnet", "0"),
            ]);
            if scheme == "internet-facing" && ip_address_type == "dualstack" {
                m.insert("ipv6.deny_all_igw_traffic".into(), "false".into());
            }
            m
        }
        "gateway" => map(&[("deletion_protection.enabled", "false"), ("load_balancing.cross_zone.enabled", "false")]),
        _ => {
            let mut m = map(&[
                ("access_logs.s3.enabled", "false"),
                ("access_logs.s3.bucket", ""),
                ("access_logs.s3.prefix", ""),
                ("connection_logs.s3.enabled", "false"),
                ("connection_logs.s3.bucket", ""),
                ("connection_logs.s3.prefix", ""),
                ("health_check_logs.s3.enabled", "false"),
                ("health_check_logs.s3.bucket", ""),
                ("health_check_logs.s3.prefix", ""),
                ("deletion_protection.enabled", "false"),
                ("idle_timeout.timeout_seconds", "60"),
                ("client_keep_alive.seconds", "3600"),
                ("routing.http.desync_mitigation_mode", "defensive"),
                ("routing.http.drop_invalid_header_fields.enabled", "false"),
                ("routing.http.preserve_host_header.enabled", "false"),
                ("routing.http.x_amzn_tls_version_and_cipher_suite.enabled", "false"),
                ("routing.http.xff_client_port.enabled", "false"),
                ("routing.http.xff_header_processing.mode", "append"),
                ("routing.http2.enabled", "true"),
                ("waf.fail_open.enabled", "false"),
                ("zonal_shift.config.enabled", "false"),
                ("load_balancing.cross_zone.enabled", "true"),
            ]);
            if scheme == "internet-facing" && ip_address_type.starts_with("dualstack") {
                m.insert("ipv6.deny_all_igw_traffic".into(), "false".into());
            }
            m
        }
    }
}

/// Values an attribute accepts, or `None` for free-form ones.
pub fn check_lb_attribute(key: &str, value: &str) -> Result<(), String> {
    let boolean = |v: &str| matches!(v, "true" | "false");
    let int_range = |v: &str, lo: i64, hi: i64| v.parse::<i64>().is_ok_and(|n| (lo..=hi).contains(&n));
    let ok = match key {
        k if k.ends_with(".enabled") => boolean(value),
        "idle_timeout.timeout_seconds" => int_range(value, 1, 4000),
        "client_keep_alive.seconds" => int_range(value, 60, 604_800),
        "routing.http.desync_mitigation_mode" => matches!(value, "monitor" | "defensive" | "strictest"),
        "routing.http.xff_header_processing.mode" => matches!(value, "append" | "preserve" | "remove"),
        "dns_record.client_routing_policy" => {
            matches!(
                value,
                "availability_zone_affinity" | "partial_availability_zone_affinity" | "any_availability_zone"
            )
        }
        "secondary_ips.auto_assigned.per_subnet" => int_range(value, 0, 7),
        _ => true,
    };
    if ok {
        Ok(())
    } else {
        Err(format!("'{value}' is not a valid value for load balancer attribute '{key}'"))
    }
}

/// A target group's attributes before any `ModifyTargetGroupAttributes`.
pub fn target_group_attributes(protocol: &str, target_type: &str) -> BTreeMap<String, String> {
    if target_type == "lambda" {
        return map(&[("lambda.multi_value_headers.enabled", "false")]);
    }
    let health = [
        ("target_group_health.dns_failover.minimum_healthy_targets.count", "1"),
        ("target_group_health.dns_failover.minimum_healthy_targets.percentage", "off"),
        ("target_group_health.unhealthy_state_routing.minimum_healthy_targets.count", "1"),
        ("target_group_health.unhealthy_state_routing.minimum_healthy_targets.percentage", "off"),
    ];
    match protocol {
        "TCP" | "TLS" | "UDP" | "TCP_UDP" | "QUIC" | "TCP_QUIC" => {
            let preserve = target_type == "instance" || matches!(protocol, "UDP" | "TCP_UDP");
            let mut m = map(&[
                ("deregistration_delay.timeout_seconds", "300"),
                ("deregistration_delay.connection_termination.enabled", "false"),
                ("preserve_client_ip.enabled", if preserve { "true" } else { "false" }),
                ("proxy_protocol_v2.enabled", "false"),
                ("stickiness.enabled", "false"),
                ("stickiness.type", "source_ip"),
                ("load_balancing.cross_zone.enabled", "use_load_balancer_configuration"),
                ("target_health_state.unhealthy.connection_termination.enabled", "true"),
                ("target_health_state.unhealthy.draining_interval_seconds", "0"),
            ]);
            m.extend(map(&health));
            m
        }
        "GENEVE" => map(&[
            ("deregistration_delay.timeout_seconds", "300"),
            ("stickiness.enabled", "false"),
            ("stickiness.type", "source_ip_dest_ip_proto"),
            ("load_balancing.cross_zone.enabled", "use_load_balancer_configuration"),
            ("target_failover.on_deregistration", "no_rebalance"),
            ("target_failover.on_unhealthy", "no_rebalance"),
            ("target_group_health.dns_failover.minimum_healthy_targets.count", "1"),
            ("target_group_health.dns_failover.minimum_healthy_targets.percentage", "off"),
            ("target_group_health.unhealthy_state_routing.minimum_healthy_targets.count", "1"),
            ("target_group_health.unhealthy_state_routing.minimum_healthy_targets.percentage", "off"),
        ]),
        _ => {
            let mut m = map(&[
                ("deregistration_delay.timeout_seconds", "300"),
                ("stickiness.enabled", "false"),
                ("stickiness.type", "lb_cookie"),
                ("stickiness.lb_cookie.duration_seconds", "86400"),
                ("stickiness.app_cookie.cookie_name", ""),
                ("stickiness.app_cookie.duration_seconds", "86400"),
                ("load_balancing.algorithm.type", "round_robin"),
                ("load_balancing.algorithm.anomaly_mitigation", "off"),
                ("slow_start.duration_seconds", "0"),
                ("load_balancing.cross_zone.enabled", "use_load_balancer_configuration"),
            ]);
            m.extend(map(&health));
            m
        }
    }
}

pub fn check_tg_attribute(key: &str, value: &str) -> Result<(), String> {
    let boolean = |v: &str| matches!(v, "true" | "false");
    let int_range = |v: &str, lo: i64, hi: i64| v.parse::<i64>().is_ok_and(|n| (lo..=hi).contains(&n));
    let ok = match key {
        "deregistration_delay.timeout_seconds" => int_range(value, 0, 3600),
        "stickiness.type" => {
            matches!(value, "lb_cookie" | "app_cookie" | "source_ip" | "source_ip_dest_ip" | "source_ip_dest_ip_proto")
        }
        "stickiness.lb_cookie.duration_seconds" | "stickiness.app_cookie.duration_seconds" => {
            int_range(value, 1, 604_800)
        }
        "stickiness.app_cookie.cookie_name" => {
            !value.starts_with("AWSALB") && !value.starts_with("AWSALBAPP") && !value.starts_with("AWSALBTG")
        }
        "load_balancing.algorithm.type" => {
            matches!(value, "round_robin" | "least_outstanding_requests" | "weighted_random")
        }
        "load_balancing.algorithm.anomaly_mitigation" => matches!(value, "on" | "off"),
        "slow_start.duration_seconds" => value == "0" || int_range(value, 30, 900),
        "load_balancing.cross_zone.enabled" => matches!(value, "true" | "false" | "use_load_balancer_configuration"),
        "target_failover.on_deregistration" | "target_failover.on_unhealthy" => {
            matches!(value, "rebalance" | "no_rebalance")
        }
        "target_health_state.unhealthy.draining_interval_seconds" => int_range(value, 0, 360_000),
        k if k.ends_with(".percentage") => value == "off" || int_range(value, 1, 100),
        k if k.ends_with(".count") => int_range(value, 1, 10_000),
        k if k.ends_with(".enabled") => boolean(value),
        _ => true,
    };
    if ok {
        Ok(())
    } else {
        Err(format!("'{value}' is not a valid value for target group attribute '{key}'"))
    }
}

/// A listener's attributes before any `ModifyListenerAttributes`.
pub fn listener_attributes(protocol: &str) -> BTreeMap<String, String> {
    match protocol {
        "HTTP" | "HTTPS" => {
            let mut m = map(&[
                ("routing.http.response.server.enabled", "true"),
                (
                    "routing.http.request.x_amzn_mtls_clientcert_serial_number.header_name",
                    "X-Amzn-Mtls-Clientcert-Serial-Number",
                ),
                ("routing.http.request.x_amzn_mtls_clientcert_issuer.header_name", "X-Amzn-Mtls-Clientcert-Issuer"),
                ("routing.http.request.x_amzn_mtls_clientcert_subject.header_name", "X-Amzn-Mtls-Clientcert-Subject"),
                ("routing.http.request.x_amzn_mtls_clientcert_validity.header_name", "X-Amzn-Mtls-Clientcert-Validity"),
                ("routing.http.request.x_amzn_mtls_clientcert_leaf.header_name", "X-Amzn-Mtls-Clientcert-Leaf"),
                ("routing.http.request.x_amzn_mtls_clientcert.header_name", "X-Amzn-Mtls-Clientcert"),
                ("routing.http.request.x_amzn_tls_version.header_name", "X-Amzn-Tls-Version"),
                ("routing.http.request.x_amzn_tls_cipher_suite.header_name", "X-Amzn-Tls-Cipher-Suite"),
            ]);
            for h in [
                "access_control_allow_origin",
                "access_control_allow_methods",
                "access_control_allow_headers",
                "access_control_allow_credentials",
                "access_control_expose_headers",
                "access_control_max_age",
                "content_security_policy",
                "x_content_type_options",
                "x_frame_options",
                "strict_transport_security",
            ] {
                m.insert(format!("routing.http.response.{h}.header_value"), String::new());
            }
            m
        }
        "TCP" | "TLS" | "TCP_UDP" | "GENEVE" | "" => map(&[("tcp.idle_timeout.seconds", "350")]),
        _ => BTreeMap::new(),
    }
}

/// Health check settings a new target group gets for what the caller left
/// out: (protocol, port, path, interval, timeout, healthy, unhealthy,
/// matcher, enabled).
pub struct HealthDefaults {
    pub protocol: Option<&'static str>,
    pub path: Option<&'static str>,
    pub interval: i32,
    pub timeout: i32,
    pub healthy: i32,
    pub unhealthy: i32,
    pub http_code: Option<&'static str>,
    pub grpc_code: Option<&'static str>,
    pub enabled: bool,
}

pub fn health_defaults(protocol: &str, protocol_version: &str, target_type: &str, hc_protocol: &str) -> HealthDefaults {
    if target_type == "lambda" {
        return HealthDefaults {
            protocol: None,
            path: Some("/"),
            interval: 35,
            timeout: 30,
            healthy: 5,
            unhealthy: 2,
            http_code: Some("200"),
            grpc_code: None,
            enabled: false,
        };
    }
    match protocol {
        "HTTP" | "HTTPS" => {
            let grpc = protocol_version == "GRPC";
            HealthDefaults {
                protocol: Some(if protocol == "HTTPS" { "HTTPS" } else { "HTTP" }),
                path: Some(if grpc { "/AWS.ALB/healthcheck" } else { "/" }),
                interval: 30,
                timeout: 5,
                healthy: 5,
                unhealthy: 2,
                http_code: (!grpc).then_some("200"),
                grpc_code: grpc.then_some("12"),
                enabled: true,
            }
        }
        "GENEVE" => HealthDefaults {
            protocol: Some("TCP"),
            path: None,
            interval: 10,
            timeout: 5,
            healthy: 5,
            unhealthy: 2,
            http_code: None,
            grpc_code: None,
            enabled: true,
        },
        _ => {
            let http = matches!(hc_protocol, "HTTP" | "HTTPS");
            HealthDefaults {
                protocol: Some("TCP"),
                path: http.then_some("/"),
                interval: 30,
                timeout: if http { 6 } else { 10 },
                healthy: 5,
                unhealthy: 2,
                http_code: http.then_some("200-399"),
                grpc_code: None,
                enabled: true,
            }
        }
    }
}

const TLS13: &[&str] = &["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"];
const TLS13_FIPS: &[&str] = &["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"];
const ECDHE_GCM: &[&str] = &[
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
];
const ECDHE_CBC_SHA2: &[&str] =
    &["ECDHE-ECDSA-AES128-SHA256", "ECDHE-RSA-AES128-SHA256", "ECDHE-ECDSA-AES256-SHA384", "ECDHE-RSA-AES256-SHA384"];
const ECDHE_CBC_SHA1: &[&str] =
    &["ECDHE-ECDSA-AES128-SHA", "ECDHE-RSA-AES128-SHA", "ECDHE-RSA-AES256-SHA", "ECDHE-ECDSA-AES256-SHA"];
const RSA_KX: &[&str] =
    &["AES128-GCM-SHA256", "AES128-SHA256", "AES128-SHA", "AES256-GCM-SHA384", "AES256-SHA256", "AES256-SHA"];

const BOTH: &[&str] = &["application", "network"];

/// Every predefined ELBv2 security policy MWS knows, with its protocols.
/// `(name, protocols, cipher groups)`.
pub type SslPolicy = (&'static str, &'static [&'static str], &'static [&'static [&'static str]]);

pub const SSL_POLICIES: &[SslPolicy] = &[
    (
        "ELBSecurityPolicy-2016-08",
        &["TLSv1", "TLSv1.1", "TLSv1.2"],
        &[ECDHE_GCM, ECDHE_CBC_SHA2, ECDHE_CBC_SHA1, RSA_KX],
    ),
    ("ELBSecurityPolicy-TLS13-1-2-2021-06", &["TLSv1.2", "TLSv1.3"], &[TLS13, ECDHE_GCM, ECDHE_CBC_SHA2]),
    ("ELBSecurityPolicy-TLS13-1-2-Res-2021-06", &["TLSv1.2", "TLSv1.3"], &[TLS13, ECDHE_GCM]),
    ("ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06", &["TLSv1.2", "TLSv1.3"], &[TLS13, ECDHE_GCM, ECDHE_CBC_SHA2, RSA_KX]),
    (
        "ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06",
        &["TLSv1.2", "TLSv1.3"],
        &[TLS13, ECDHE_GCM, ECDHE_CBC_SHA2, ECDHE_CBC_SHA1, RSA_KX],
    ),
    (
        "ELBSecurityPolicy-TLS13-1-1-2021-06",
        &["TLSv1.1", "TLSv1.2", "TLSv1.3"],
        &[TLS13, ECDHE_GCM, ECDHE_CBC_SHA2, ECDHE_CBC_SHA1, RSA_KX],
    ),
    (
        "ELBSecurityPolicy-TLS13-1-0-2021-06",
        &["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"],
        &[TLS13, ECDHE_GCM, ECDHE_CBC_SHA2, ECDHE_CBC_SHA1, RSA_KX],
    ),
    ("ELBSecurityPolicy-TLS13-1-3-2021-06", &["TLSv1.3"], &[TLS13]),
    ("ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04", &["TLSv1.2", "TLSv1.3"], &[TLS13_FIPS, ECDHE_GCM, ECDHE_CBC_SHA2]),
    ("ELBSecurityPolicy-TLS13-1-3-FIPS-2023-04", &["TLSv1.3"], &[TLS13_FIPS]),
    ("ELBSecurityPolicy-TLS13-1-2-PQ-2025-09", &["TLSv1.2", "TLSv1.3"], &[TLS13, ECDHE_GCM, ECDHE_CBC_SHA2]),
    ("ELBSecurityPolicy-TLS13-1-3-PQ-2025-09", &["TLSv1.3"], &[TLS13]),
    (
        "ELBSecurityPolicy-TLS-1-0-2015-04",
        &["TLSv1", "TLSv1.1", "TLSv1.2"],
        &[ECDHE_GCM, ECDHE_CBC_SHA2, ECDHE_CBC_SHA1, RSA_KX],
    ),
    (
        "ELBSecurityPolicy-TLS-1-1-2017-01",
        &["TLSv1.1", "TLSv1.2"],
        &[ECDHE_GCM, ECDHE_CBC_SHA2, ECDHE_CBC_SHA1, RSA_KX],
    ),
    ("ELBSecurityPolicy-TLS-1-2-2017-01", &["TLSv1.2"], &[ECDHE_GCM, ECDHE_CBC_SHA2, RSA_KX]),
    ("ELBSecurityPolicy-TLS-1-2-Ext-2018-06", &["TLSv1.2"], &[ECDHE_GCM, ECDHE_CBC_SHA2, ECDHE_CBC_SHA1, RSA_KX]),
    ("ELBSecurityPolicy-FS-2018-06", &["TLSv1", "TLSv1.1", "TLSv1.2"], &[ECDHE_GCM, ECDHE_CBC_SHA2, ECDHE_CBC_SHA1]),
    ("ELBSecurityPolicy-FS-1-1-2019-08", &["TLSv1.1", "TLSv1.2"], &[ECDHE_GCM, ECDHE_CBC_SHA2, ECDHE_CBC_SHA1]),
    ("ELBSecurityPolicy-FS-1-2-2019-08", &["TLSv1.2"], &[ECDHE_GCM, ECDHE_CBC_SHA2, ECDHE_CBC_SHA1]),
    ("ELBSecurityPolicy-FS-1-2-Res-2019-08", &["TLSv1.2"], &[ECDHE_GCM, ECDHE_CBC_SHA2]),
    ("ELBSecurityPolicy-FS-1-2-Res-2020-10", &["TLSv1.2"], &[ECDHE_GCM]),
    (
        "ELBSecurityPolicy-2015-05",
        &["TLSv1", "TLSv1.1", "TLSv1.2"],
        &[ECDHE_GCM, ECDHE_CBC_SHA2, ECDHE_CBC_SHA1, RSA_KX],
    ),
];

pub const DEFAULT_SSL_POLICY: &str = "ELBSecurityPolicy-2016-08";

pub fn ssl_policy(name: &str) -> Option<(&'static str, Vec<&'static str>, Vec<&'static str>)> {
    SSL_POLICIES.iter().find(|p| p.0 == name).map(|(n, protocols, ciphers)| {
        (*n, protocols.to_vec(), ciphers.iter().flat_map(|c| c.iter().copied()).collect())
    })
}

pub fn ssl_policy_load_balancer_types() -> &'static [&'static str] {
    BOTH
}

/// ELBv2 account limits (quotas) at their default values.
pub const V2_LIMITS: &[(&str, &str)] = &[
    ("application-load-balancers", "50"),
    ("condition-values-per-alb-rule", "5"),
    ("condition-wildcards-per-alb-rule", "5"),
    ("gateway-load-balancers", "100"),
    ("gateway-load-balancers-per-vpc", "100"),
    ("geneve-target-groups", "100"),
    ("listeners-per-application-load-balancer", "50"),
    ("listeners-per-network-load-balancer", "50"),
    ("network-load-balancers", "50"),
    ("rules-per-application-load-balancer", "100"),
    ("target-groups", "3000"),
    ("target-groups-per-action-on-application-load-balancer", "5"),
    ("target-groups-per-action-on-network-load-balancer", "1"),
    ("target-groups-per-application-load-balancer", "100"),
    ("targets-per-application-load-balancer", "1000"),
    ("targets-per-availability-zone-per-gateway-load-balancer", "300"),
    ("targets-per-availability-zone-per-network-load-balancer", "500"),
    ("targets-per-network-load-balancer", "3000"),
    ("certificates-per-application-load-balancer", "25"),
    ("certificates-per-network-load-balancer", "25"),
    ("trust-stores-per-account", "20"),
];

pub fn limit(name: &str) -> usize {
    V2_LIMITS.iter().find(|l| l.0 == name).and_then(|l| l.1.parse().ok()).unwrap_or(usize::MAX)
}

/// The Service Quotas code of an account limit, where Service Quotas has it.
pub fn quota_code(name: &str) -> Option<&'static str> {
    Some(match name {
        "application-load-balancers" => "L-53DA6B97",
        "network-load-balancers" => "L-69A177A2",
        "classic-load-balancers" => "L-E9E9831D",
        "target-groups" => "L-B22855CB",
        "rules-per-application-load-balancer" => "L-7EED9B64",
        "listeners-per-application-load-balancer" => "L-B6DF7632",
        "listeners-per-network-load-balancer" => "L-57A373D6",
        _ => return None,
    })
}

/// Classic Load Balancer account limits.
pub const CLASSIC_LIMITS: &[(&str, &str)] =
    &[("classic-load-balancers", "20"), ("classic-listeners", "100"), ("classic-registered-instances", "1000")];
