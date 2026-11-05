//! Health checks. Every registered target of a target group that receives
//! traffic (and every instance of a Classic Load Balancer) is probed for
//! real: an HTTP(S) `GET` of the health check path compared against the
//! matcher, a TCP connect, or an invocation of a Lambda target. A new
//! target becomes healthy after its first passing check; a target turns
//! unhealthy after `UnhealthyThresholdCount` consecutive failures and
//! healthy again after `HealthyThresholdCount` successes, as in ELB.
//! Results drive routing and `DescribeTargetHealth`, and once a minute
//! become `HealthyHostCount`/`UnHealthyHostCount` metrics.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::state::{RegionState, RegisteredTarget, TargetGroupRecord};
use crate::v2::types as t;
use crate::Elb;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct HealthKey {
    /// A target group ARN, or `classic:<account|region>:<name>`.
    pub group: String,
    pub id: String,
    pub port: i32,
}

impl HealthKey {
    pub fn v2(tg: &str, id: &str, port: i32) -> Self {
        Self { group: tg.to_string(), id: id.to_string(), port }
    }
    pub fn classic(region_key: &str, lb: &str, instance: &str) -> Self {
        Self { group: format!("classic:{region_key}:{lb}"), id: instance.to_string(), port: 0 }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Run {
    /// `None` until the target's health is first decided.
    pub healthy: Option<bool>,
    successes: u32,
    failures: u32,
    pub probes: u32,
    pub last_failure: Option<(String, String)>,
    next_due: Instant,
    in_flight: bool,
}

impl Run {
    fn new() -> Self {
        Self {
            healthy: None,
            successes: 0,
            failures: 0,
            probes: 0,
            last_failure: None,
            next_due: Instant::now(),
            in_flight: false,
        }
    }
}

#[derive(Default)]
pub(crate) struct Health {
    runs: Mutex<HashMap<HealthKey, Run>>,
    started: AtomicBool,
    /// A target's health changed since host counts were last published.
    changed: AtomicBool,
}

impl Health {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<HealthKey, Run>> {
        self.runs.lock().expect("ELB health lock poisoned")
    }
    pub fn get(&self, key: &HealthKey) -> Option<Run> {
        self.lock().get(key).cloned()
    }
    pub fn forget(&self, key: &HealthKey) {
        self.lock().remove(key);
    }
    pub fn forget_group(&self, group: &str) {
        self.lock().retain(|k, _| k.group != group);
    }
    /// Probe a group's targets again now (its settings changed).
    pub fn config_changed(&self, group: &str) {
        for (k, r) in self.lock().iter_mut() {
            if k.group == group {
                r.next_due = Instant::now();
            }
        }
    }
    pub fn clear(&self) {
        self.lock().clear();
    }
}

/// A target's health as `DescribeTargetHealth` reports it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Status {
    pub state: &'static str,
    pub reason: Option<&'static str>,
    pub description: Option<String>,
}

impl Status {
    fn new(state: &'static str, reason: &'static str, description: impl Into<String>) -> Self {
        Self { state, reason: Some(reason), description: Some(description.into()) }
    }
    pub fn unused(reason: &'static str, description: &str) -> Self {
        Self::new("unused", reason, description)
    }
    pub fn healthy() -> Self {
        Self { state: "healthy", reason: None, description: None }
    }
    pub fn wire(&self) -> t::TargetHealth {
        t::TargetHealth {
            state: Some(self.state.into()),
            reason: self.reason.map(str::to_string),
            description: self.description.clone(),
        }
    }
}

/// The address an instance target receives traffic on, and its state.
pub(crate) fn instance_state(
    elb: &Elb,
    account: &str,
    region: &str,
    id: &str,
) -> Option<(String, Option<String>, Option<String>)> {
    let info = elb.ec2()?.instance_info(account, region, id)?;
    Some((info.state, info.private_ip, info.availability_zone))
}

fn health_reason(reason: &str) -> &'static str {
    match reason {
        "Target.Timeout" => "Target.Timeout",
        "Target.ResponseCodeMismatch" => "Target.ResponseCodeMismatch",
        "Target.FailedHealthChecks" => "Target.FailedHealthChecks",
        "Elb.InternalError" => "Elb.InternalError",
        _ => "Target.FailedHealthChecks",
    }
}

/// How a registered target stands, from the state and the health checker.
pub(crate) fn classify(
    elb: &Elb,
    r: &RegionState,
    account: &str,
    region: &str,
    tg: &TargetGroupRecord,
    target: &RegisteredTarget,
) -> Status {
    if target.draining_until.is_some() {
        return Status::new("draining", "Target.DeregistrationInProgress", "Target deregistration is in progress");
    }
    let lbs = crate::ops::tg_load_balancers(r, tg.arn());
    if lbs.is_empty() {
        return Status::unused(
            "Target.NotInUse",
            "Target group is not configured to receive traffic from the load balancer",
        );
    }
    if tg.target_type() == "instance" {
        match instance_state(elb, account, region, &target.id) {
            Some((state, _, _)) if state != "running" => {
                return Status::unused("Target.InvalidState", &format!("Target is in the {state} state"));
            }
            None if elb.ec2().is_some() => {
                return Status::unused("Target.InvalidState", "Target is in the terminated state");
            }
            _ => {}
        }
    }
    if let Some(az) = &target.availability_zone {
        if az != "all" {
            let enabled = lbs.iter().filter_map(|l| r.load_balancers.get(l)).any(|l| l.zones().contains(az));
            if !enabled {
                return Status::unused(
                    "Target.NotInUse",
                    "Target is in an Availability Zone that is not enabled for the load balancer",
                );
            }
        }
    }
    if tg.tg.health_check_enabled == Some(false) {
        return Status::new("unavailable", "Target.HealthCheckDisabled", "Health checks are disabled");
    }
    match elb.inner.health.get(&HealthKey::v2(tg.arn(), &target.id, target.port)) {
        None => Status::new("initial", "Elb.RegistrationInProgress", "Target registration is in progress"),
        Some(run) => match run.healthy {
            None if run.probes == 0 => {
                Status::new("initial", "Elb.RegistrationInProgress", "Target registration is in progress")
            }
            None => Status::new("initial", "Elb.InitialHealthChecking", "Initial health checks in progress"),
            Some(true) => Status::healthy(),
            Some(false) => {
                let (reason, desc) = run
                    .last_failure
                    .unwrap_or_else(|| ("Target.FailedHealthChecks".into(), "Health checks failed".into()));
                Status::new("unhealthy", health_reason(&reason), desc)
            }
        },
    }
}

/// Remove targets whose deregistration delay has passed.
pub(crate) fn sweep_draining(elb: &Elb, now: DateTime<Utc>) {
    let mut removed = Vec::new();
    {
        let mut st = elb.lock();
        for r in st.regions.values_mut() {
            for tg in r.target_groups.values_mut() {
                let arn = tg.arn().to_string();
                tg.targets.retain(|x| {
                    let done = x.draining_until.is_some_and(|u| u <= now);
                    if done {
                        removed.push(HealthKey::v2(&arn, &x.id, x.port));
                    }
                    !done
                });
            }
        }
    }
    for k in removed {
        elb.inner.health.forget(&k);
    }
}

/// What to probe.
#[derive(Debug, Clone)]
pub(crate) enum ProbeKind {
    Tcp,
    Http { tls: bool, path: String, codes: String },
    Lambda { function: String, tg_arn: String, path: String, codes: String },
}

#[derive(Debug, Clone)]
pub(crate) struct Probe {
    pub key: HealthKey,
    pub account: String,
    pub region: String,
    pub kind: ProbeKind,
    pub address: Option<SocketAddr>,
    pub timeout: Duration,
    pub interval: Duration,
    pub healthy_threshold: u32,
    pub unhealthy_threshold: u32,
}

/// Whether `code` matches a matcher like `200`, `200,302` or `200-399`.
pub(crate) fn code_matches(codes: &str, code: u16) -> bool {
    codes.split(',').any(|part| match part.trim().split_once('-') {
        Some((a, b)) => a.parse::<u16>().ok().zip(b.parse::<u16>().ok()).is_some_and(|(a, b)| (a..=b).contains(&code)),
        None => part.trim().parse::<u16>().ok() == Some(code),
    })
}

/// The probes due for ELBv2 target groups.
fn v2_probes(elb: &Elb) -> Vec<Probe> {
    let st = elb.lock();
    let mut out = Vec::new();
    for (key, r) in &st.regions {
        let (account, region) = key.split_once('|').unwrap_or_default();
        for tg in r.target_groups.values() {
            if tg.tg.health_check_enabled == Some(false) || crate::ops::tg_load_balancers(r, tg.arn()).is_empty() {
                continue;
            }
            let g = &tg.tg;
            let timeout = Duration::from_secs(g.health_check_timeout_seconds.unwrap_or(5).max(1) as u64);
            let interval = Duration::from_secs(g.health_check_interval_seconds.unwrap_or(30).max(1) as u64);
            let codes = g.matcher.as_ref().and_then(|m| m.http_code.clone()).unwrap_or_else(|| "200".into());
            let path = g.health_check_path.clone().unwrap_or_else(|| "/".into());
            for target in &tg.targets {
                if target.draining_until.is_some() {
                    continue;
                }
                let kind = match (tg.target_type(), g.health_check_protocol.as_deref()) {
                    ("lambda", _) => ProbeKind::Lambda {
                        function: target.id.clone(),
                        tg_arn: tg.arn().into(),
                        path: path.clone(),
                        codes: codes.clone(),
                    },
                    (_, Some("HTTP")) => ProbeKind::Http { tls: false, path: path.clone(), codes: codes.clone() },
                    (_, Some("HTTPS")) => ProbeKind::Http { tls: true, path: path.clone(), codes: codes.clone() },
                    _ => ProbeKind::Tcp,
                };
                let port = match g.health_check_port.as_deref() {
                    Some("traffic-port") | None => target.port,
                    Some(p) => p.parse().unwrap_or(target.port),
                };
                let address = match tg.target_type() {
                    "lambda" => None,
                    "instance" => match instance_state(elb, account, region, &target.id) {
                        Some((s, Some(ip), _)) if s == "running" => {
                            ip.parse().ok().map(|ip| SocketAddr::new(ip, port as u16))
                        }
                        Some(_) => continue,
                        None if elb.ec2().is_some() => continue,
                        None => None,
                    },
                    "alb" => elb.inner.data.address_of_lb_port(&target.id, port),
                    _ => target.id.parse().ok().map(|ip| SocketAddr::new(ip, port as u16)),
                };
                out.push(Probe {
                    key: HealthKey::v2(tg.arn(), &target.id, target.port),
                    account: account.to_string(),
                    region: region.to_string(),
                    kind,
                    address,
                    timeout,
                    interval,
                    healthy_threshold: g.healthy_threshold_count.unwrap_or(5).max(1) as u32,
                    unhealthy_threshold: g.unhealthy_threshold_count.unwrap_or(2).max(1) as u32,
                });
            }
        }
    }
    out.extend(crate::classic::probes(elb, &st));
    out
}

/// Start the checker loop once, on the current Tokio runtime.
pub(crate) fn ensure_running(elb: &Elb) {
    if elb.inner.health.started.load(Ordering::Relaxed) {
        return;
    }
    let Ok(handle) = tokio::runtime::Handle::try_current() else { return };
    if elb.inner.health.started.swap(true, Ordering::SeqCst) {
        return;
    }
    let weak = std::sync::Arc::downgrade(&elb.inner);
    handle.spawn(async move {
        let mut last_metrics = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let Some(inner) = weak.upgrade() else { return };
            let elb = Elb { inner };
            sweep_draining(&elb, elb.now());
            tick(&elb);
            elb.flush_logs();
            // Every minute, as ELB does, and as soon as a target's health
            // changes.
            if last_metrics.elapsed() >= Duration::from_secs(60)
                || elb.inner.health.changed.swap(false, Ordering::SeqCst)
            {
                last_metrics = Instant::now();
                publish_host_counts(&elb);
            }
        }
    });
}

fn tick(elb: &Elb) {
    let probes = v2_probes(elb);
    let now = Instant::now();
    let mut due = Vec::new();
    {
        let mut runs = elb.inner.health.lock();
        for p in probes {
            let run = runs.entry(p.key.clone()).or_insert_with(Run::new);
            if run.in_flight || run.next_due > now {
                continue;
            }
            run.in_flight = true;
            run.next_due = now + p.interval;
            due.push(p);
        }
    }
    for p in due {
        let elb = elb.clone();
        tokio::spawn(async move {
            let outcome = run_probe(&elb, &p).await;
            let mut runs = elb.inner.health.lock();
            let Some(run) = runs.get_mut(&p.key) else { return };
            run.in_flight = false;
            run.probes += 1;
            match outcome {
                Ok(()) => {
                    run.failures = 0;
                    run.successes += 1;
                    match run.healthy {
                        None => run.healthy = Some(true),
                        Some(false) if run.successes >= p.healthy_threshold => run.healthy = Some(true),
                        _ => return,
                    }
                    elb.inner.health.changed.store(true, Ordering::SeqCst);
                }
                Err((reason, desc)) => {
                    run.successes = 0;
                    run.failures += 1;
                    run.last_failure = Some((reason, desc));
                    if run.healthy != Some(false) && run.failures >= p.unhealthy_threshold {
                        run.healthy = Some(false);
                        elb.inner.health.changed.store(true, Ordering::SeqCst);
                    }
                }
            }
        });
    }
}

type ProbeError = (String, String);

fn failed() -> ProbeError {
    ("Target.FailedHealthChecks".into(), "Health checks failed".into())
}

fn timed_out() -> ProbeError {
    ("Target.Timeout".into(), "Request timed out".into())
}

async fn run_probe(elb: &Elb, p: &Probe) -> Result<(), ProbeError> {
    match &p.kind {
        ProbeKind::Lambda { function, tg_arn, path, codes } => {
            let ctx = elb.background_context(&p.account, &p.region).ok_or_else(failed)?;
            let event = serde_json::json!({
                "requestContext": { "elb": { "targetGroupArn": tg_arn } },
                "httpMethod": "GET",
                "path": path,
                "queryStringParameters": {},
                "headers": { "user-agent": "ELB-HealthChecker/2.0" },
                "body": "",
                "isBase64Encoded": false,
            });
            let lambda = elb.lambda().ok_or_else(failed)?;
            let inv = mws_lambda::ServiceInvocation {
                function,
                service_principal: "elasticloadbalancing.amazonaws.com",
                source_account: Some(&p.account),
                source_arn: Some(tg_arn),
                payload: event.to_string().into_bytes(),
            };
            let result =
                tokio::time::timeout(p.timeout, lambda.invoke_as_service(&ctx, inv)).await.map_err(|_| timed_out())?;
            let result = result.map_err(|_| ("Target.FailedHealthChecks".into(), "Lambda invocation failed".into()))?;
            if result.function_error.is_some() {
                return Err(("Target.FailedHealthChecks".into(), "The Lambda function returned an error".into()));
            }
            let v: serde_json::Value = serde_json::from_slice(&result.payload).unwrap_or_default();
            let code = v.get("statusCode").and_then(|c| c.as_u64()).unwrap_or(0) as u16;
            if code_matches(codes, code) {
                Ok(())
            } else {
                Err(("Target.ResponseCodeMismatch".into(), format!("Health checks failed with these codes: [{code}]")))
            }
        }
        ProbeKind::Tcp => {
            let addr = p.address.ok_or_else(failed)?;
            match tokio::time::timeout(p.timeout, TcpStream::connect(addr)).await {
                Err(_) => Err(timed_out()),
                Ok(Err(_)) => Err(failed()),
                Ok(Ok(_)) => Ok(()),
            }
        }
        ProbeKind::Http { tls, path, codes } => {
            let addr = p.address.ok_or_else(failed)?;
            let fut = http_status(addr, *tls, path);
            match tokio::time::timeout(p.timeout, fut).await {
                Err(_) => Err(timed_out()),
                Ok(Err(())) => Err(failed()),
                Ok(Ok(code)) if code_matches(codes, code) => Ok(()),
                Ok(Ok(code)) => Err((
                    "Target.ResponseCodeMismatch".into(),
                    format!("Health checks failed with these codes: [{code}]"),
                )),
            }
        }
    }
}

/// `GET path` and return the status code.
pub(crate) async fn http_status(addr: SocketAddr, tls: bool, path: &str) -> Result<u16, ()> {
    let stream = TcpStream::connect(addr).await.map_err(|_| ())?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: ELB-HealthChecker/2.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        addr
    );
    let mut buf = Vec::new();
    if tls {
        let mut s = crate::data::tls::connect_insecure(stream, addr).await.map_err(|_| ())?;
        s.write_all(request.as_bytes()).await.map_err(|_| ())?;
        read_status(&mut s, &mut buf).await
    } else {
        let mut s = stream;
        s.write_all(request.as_bytes()).await.map_err(|_| ())?;
        read_status(&mut s, &mut buf).await
    }
}

async fn read_status<S: AsyncReadExt + Unpin>(s: &mut S, buf: &mut Vec<u8>) -> Result<u16, ()> {
    let mut chunk = [0u8; 512];
    loop {
        if let Some(end) = buf.iter().position(|b| *b == b'\n') {
            let line = String::from_utf8_lossy(&buf[..end]);
            return line.split_whitespace().nth(1).and_then(|c| c.parse().ok()).ok_or(());
        }
        let n = s.read(&mut chunk).await.map_err(|_| ())?;
        if n == 0 || buf.len() > 8192 {
            return Err(());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// `HealthyHostCount` and `UnHealthyHostCount` per target group and load
/// balancer.
fn publish_host_counts(elb: &Elb) {
    let Some(sink) = elb.metrics() else { return };
    let mut batches = Vec::new();
    {
        let st = elb.lock();
        for (key, r) in &st.regions {
            let (account, region) = key.split_once('|').unwrap_or_default();
            for tg in r.target_groups.values() {
                for lb_arn in crate::ops::tg_load_balancers(r, tg.arn()) {
                    let Some(lb) = r.load_balancers.get(&lb_arn) else { continue };
                    let (mut healthy, mut unhealthy) = (0.0, 0.0);
                    for target in &tg.targets {
                        match classify(elb, r, account, region, tg, target).state {
                            "healthy" | "unavailable" => healthy += 1.0,
                            "unhealthy" => unhealthy += 1.0,
                            _ => {}
                        }
                    }
                    let mut b = crate::metrics::Batch::new(account, region, crate::metrics::namespace(lb.ty()));
                    let d = vec![crate::metrics::dims(&[
                        ("TargetGroup", &crate::names::tg_dimension(tg.arn())),
                        ("LoadBalancer", &crate::names::lb_dimension(&lb_arn)),
                    ])];
                    b.add("HealthyHostCount", "Count", healthy, &d);
                    b.add("UnHealthyHostCount", "Count", unhealthy, &d);
                    batches.push(b);
                }
            }
            batches.extend(crate::classic::host_count_batches(elb, account, region, r));
        }
    }
    for b in batches {
        b.send(Some(sink));
    }
}

impl Elb {
    /// The emulated time now.
    pub(crate) fn now(&self) -> DateTime<Utc> {
        let guard = self.inner.template.lock().expect("ELB template lock poisoned");
        match guard.as_ref() {
            Some((ctx, wall)) => Utc::now() + (ctx.received_at - *wall),
            None => Utc::now(),
        }
    }

    /// Probe now (tests and the control API use this to skip waiting).
    pub fn run_health_checks_now(&self) {
        for r in self.inner.health.lock().values_mut() {
            r.next_due = Instant::now();
        }
    }
}
