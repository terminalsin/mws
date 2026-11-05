//! The task metadata endpoint (version 4) and the task role credentials
//! endpoint, as containers reach them through
//! `ECS_CONTAINER_METADATA_URI_V4` and `AWS_CONTAINER_CREDENTIALS_FULL_URI`.
//!
//! Paths, under [`PREFIX`]:
//!
//! - `{task}/{container}`: the container's metadata
//! - `{task}/{container}/task`: the task's metadata
//! - `{task}/{container}/stats` and `.../task/stats`: Docker-style stats
//! - `{task}/{container}/v3`: the same, for `ECS_CONTAINER_METADATA_URI`
//! - `{task}/credentials`: the task role credentials
//!
//! Like the real endpoint, it is unauthenticated: the task id in the path
//! is what scopes it.

use bytes::Bytes;
use mws_core::{HttpRequest, HttpResponse};
use serde_json::{json, Value};

use crate::state::TaskRecord;
use crate::Ecs;

pub const PREFIX: &str = "/_aws/ecs/metadata/";

fn respond(status: u16, body: Value) -> HttpResponse {
    http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Bytes::from(serde_json::to_vec(&body).unwrap_or_default()))
        .expect("valid response")
}

fn not_found() -> HttpResponse {
    respond(404, json!({ "message": "Not found" }))
}

fn ts(t: Option<chrono::DateTime<chrono::Utc>>) -> Value {
    t.map(|t| Value::String(t.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))).unwrap_or(Value::Null)
}

fn networks(rec: &TaskRecord) -> Value {
    let mode = rec.definition.network_mode.clone().unwrap_or_else(|| "awsvpc".into());
    let details: Vec<(String, String)> = rec
        .task
        .attachments
        .iter()
        .flatten()
        .flat_map(|a| a.details.iter().flatten())
        .filter_map(|d| Some((d.name.clone()?, d.value.clone()?)))
        .collect();
    let get = |k: &str| details.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let ip = get("privateIPv4Address").or_else(|| rec.vpc.as_ref().map(|v| v.2.clone()));
    let mut n = json!({
        "NetworkMode": mode,
        "IPv4Addresses": ip.into_iter().collect::<Vec<_>>(),
    });
    if mode == "awsvpc" {
        n["AttachmentIndex"] = json!(0);
        n["MACAddress"] = json!(get("macAddress"));
        n["PrivateDNSName"] = json!(get("privateDnsName"));
        n["IPv4SubnetCIDRBlock"] = json!(rec.vpc.as_ref().map(|v| v.1.clone()));
    }
    json!([n])
}

fn container_json(rec: &TaskRecord, name: &str) -> Option<Value> {
    let c = rec.task.containers.iter().flatten().find(|c| c.name.as_deref() == Some(name))?;
    let def = rec.definition.container_definitions.iter().flatten().find(|d| d.name.as_deref() == Some(name));
    let family = rec.definition.family.clone().unwrap_or_default();
    let docker_id = rec.runtime_ids.get(name).cloned().unwrap_or_else(|| c.runtime_id.clone().unwrap_or_default());
    let task_id = crate::names::last_segment(rec.task.task_arn.as_deref().unwrap_or_default()).to_string();
    let log = def.and_then(|d| d.log_configuration.clone());
    Some(json!({
        "DockerId": docker_id,
        "Name": name,
        "DockerName": format!("mws-ecs-{task_id}-{name}"),
        "Image": c.image.clone(),
        "ImageID": c.image_digest.clone(),
        "Labels": {
            "com.amazonaws.ecs.cluster": rec.task.cluster_arn.clone(),
            "com.amazonaws.ecs.container-name": name,
            "com.amazonaws.ecs.task-arn": rec.task.task_arn.clone(),
            "com.amazonaws.ecs.task-definition-family": family,
            "com.amazonaws.ecs.task-definition-version": rec.definition.revision.to_string(),
        },
        "DesiredStatus": rec.task.desired_status.clone(),
        "KnownStatus": c.last_status.clone(),
        "ExitCode": c.exit_code,
        "Limits": {
            "CPU": def.map(|d| d.cpu).unwrap_or(0),
            "Memory": def.and_then(|d| d.memory.or(d.memory_reservation)).unwrap_or(0),
        },
        "CreatedAt": ts(rec.task.created_at),
        "StartedAt": ts(rec.task.started_at),
        "Type": "NORMAL",
        "LogDriver": log.as_ref().map(|l| l.log_driver.clone()),
        "LogOptions": log.and_then(|l| l.options),
        "ContainerARN": c.container_arn.clone(),
        "Networks": networks(rec),
        "Health": c.health_status.as_ref().map(|h| json!({ "status": h })),
    }))
}

fn task_json(rec: &TaskRecord) -> Value {
    let containers: Vec<Value> =
        rec.task.containers.iter().flatten().filter_map(|c| container_json(rec, c.name.as_deref()?)).collect();
    let cpu = rec.task.cpu.as_deref().and_then(|c| c.parse::<f64>().ok()).map(|c| c / 1024.0);
    let mem = rec.task.memory.as_deref().and_then(|m| m.parse::<i64>().ok());
    json!({
        "Cluster": rec.task.cluster_arn.clone(),
        "TaskARN": rec.task.task_arn.clone(),
        "Family": rec.definition.family.clone(),
        "Revision": rec.definition.revision.to_string(),
        "DesiredStatus": rec.task.desired_status.clone(),
        "KnownStatus": rec.task.last_status.clone(),
        "Limits": { "CPU": cpu, "Memory": mem },
        "PullStartedAt": ts(rec.task.pull_started_at),
        "PullStoppedAt": ts(rec.task.pull_stopped_at),
        "AvailabilityZone": rec.task.availability_zone.clone(),
        "LaunchType": rec.task.launch_type.clone(),
        "Containers": containers,
        "ClockDrift": { "ClockErrorBound": 0.5, "ReferenceTimestamp": ts(Some(chrono::Utc::now())), "ClockSynchronizationStatus": "SYNCHRONIZED" },
        "TaskTags": {},
    })
}

fn stats(name: &str, id: &str) -> Value {
    json!({
        "read": chrono::Utc::now().to_rfc3339(),
        "name": format!("/{name}"),
        "id": id,
        "cpu_stats": { "cpu_usage": { "total_usage": 0 }, "system_cpu_usage": 0, "online_cpus": 1 },
        "memory_stats": { "usage": 0, "limit": 0 },
        "networks": {},
    })
}

/// Answer a request under [`PREFIX`].
pub fn serve(ecs: &Ecs, request: &HttpRequest) -> HttpResponse {
    if request.method() != http::Method::GET {
        return respond(405, json!({ "message": "Method not allowed" }));
    }
    let rest = request.uri().path()[PREFIX.len()..].trim_end_matches('/');
    let mut parts = rest.split('/');
    let (Some(task_id), Some(container)) = (parts.next(), parts.next()) else {
        return not_found();
    };
    let tail: Vec<&str> = parts.filter(|p| *p != "v3").collect();
    let rec = {
        let st = ecs.lock();
        st.regions
            .values()
            .flat_map(|r| r.tasks.values())
            .find(|t| t.task.task_arn.as_deref().is_some_and(|a| crate::names::last_segment(a) == task_id))
            .cloned()
    };
    let Some(rec) = rec else { return not_found() };
    if container == "credentials" && tail.is_empty() {
        return match &rec.credentials {
            Some(c) => respond(
                200,
                json!({
                    "RoleArn": c.role_arn,
                    "AccessKeyId": c.access_key_id,
                    "SecretAccessKey": c.secret_access_key,
                    "Token": c.session_token,
                    "Expiration": c.expiration.map(|e| e.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
                }),
            ),
            None => not_found(),
        };
    }
    match tail.as_slice() {
        [] => container_json(&rec, container).map(|v| respond(200, v)).unwrap_or_else(not_found),
        ["task"] => respond(200, task_json(&rec)),
        ["stats"] => {
            let id = rec.runtime_ids.get(container).cloned().unwrap_or_default();
            respond(200, stats(container, &id))
        }
        ["task", "stats"] => {
            let all: serde_json::Map<String, Value> =
                rec.runtime_ids.iter().map(|(n, id)| (id.clone(), stats(n, id))).collect();
            respond(200, Value::Object(all))
        }
        _ => not_found(),
    }
}
