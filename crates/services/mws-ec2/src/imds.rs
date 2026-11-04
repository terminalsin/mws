//! The instance metadata service (IMDS), served per instance at
//! `/_aws/ec2/metadata/<instance-id>/latest/...`. Instances launched by a
//! running backend get `AWS_EC2_METADATA_SERVICE_ENDPOINT` pointing here,
//! so SDKs inside them find it (IMDSv2 session tokens, IMDSv1 when the
//! instance allows it) and pick up their instance profile's credentials.

use std::collections::HashMap;
use std::sync::Mutex;

use bytes::Bytes;
use chrono::{DateTime, Duration, Utc};
use http::{Method, StatusCode};
use mws_core::{HttpRequest, HttpResponse, RequestContext};
use rand::RngCore;

use crate::generated::types as t;
use crate::state::{InstanceRecord, RegionState};
use crate::{Ec2, RoleCredentials};

pub const PREFIX: &str = "/_aws/ec2/metadata/";

const TOKEN_HEADER: &str = "x-aws-ec2-metadata-token";
const TTL_HEADER: &str = "x-aws-ec2-metadata-token-ttl-seconds";

/// IMDSv2 session tokens and cached role credentials.
#[derive(Default)]
pub(crate) struct ImdsState {
    /// Token to (instance id, expiry).
    tokens: Mutex<HashMap<String, (String, DateTime<Utc>)>>,
    /// (instance id, role ARN) to credentials, refreshed before they expire.
    credentials: Mutex<HashMap<(String, String), RoleCredentials>>,
}

fn respond(status: StatusCode, content_type: &str, body: impl Into<Bytes>) -> HttpResponse {
    http::Response::builder()
        .status(status)
        .header("content-type", content_type)
        .header("server", "EC2ws")
        .body(body.into())
        .expect("valid response")
}

fn text(body: impl Into<String>) -> HttpResponse {
    respond(StatusCode::OK, "text/plain", body.into())
}

fn status(code: StatusCode) -> HttpResponse {
    let reason = code.canonical_reason().unwrap_or_default();
    let html = format!(
        "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>\n<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\"\n\t\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">\n <head>\n  <title>{} - {reason}</title>\n </head>\n <body>\n  <h1>{} - {reason}</h1>\n </body>\n</html>\n",
        code.as_u16(),
        code.as_u16()
    );
    respond(code, "text/html", html)
}

fn iso(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Everything metadata answers from, copied out of the state lock.
struct View {
    account: String,
    region: String,
    rec: InstanceRecord,
    instance: t::Instance,
    enis: Vec<t::NetworkInterface>,
    subnets: HashMap<String, t::Subnet>,
    vpc_cidrs: HashMap<String, String>,
    key: Option<(String, String)>,
    profile: Option<t::IamInstanceProfile>,
}

fn view(r: &RegionState, account: &str, region: &str, rec: &InstanceRecord) -> View {
    let instance = super::ops::instance::render(r, rec);
    let id = rec.instance.instance_id.clone().unwrap_or_default();
    let mut enis: Vec<t::NetworkInterface> = r
        .network_interfaces
        .values()
        .filter(|n| n.attachment.as_ref().is_some_and(|a| a.instance_id.as_deref() == Some(id.as_str())))
        .cloned()
        .collect();
    enis.sort_by_key(|n| n.attachment.as_ref().and_then(|a| a.device_index));
    View {
        account: account.into(),
        region: region.into(),
        rec: rec.clone(),
        profile: instance.iam_instance_profile.clone(),
        instance,
        subnets: enis
            .iter()
            .filter_map(|n| n.subnet_id.clone())
            .filter_map(|s| r.subnets.get(&s).map(|x| (s, x.clone())))
            .collect(),
        vpc_cidrs: r.vpcs.iter().map(|(id, v)| (id.clone(), v.vpc.cidr_block.clone().unwrap_or_default())).collect(),
        enis,
        key: rec
            .instance
            .key_name
            .as_ref()
            .and_then(|k| r.key_pairs.get(k))
            .map(|k| (k.info.key_name.clone().unwrap_or_default(), k.public_key.clone())),
    }
}

impl Ec2 {
    fn find_instance(&self, id: &str) -> Option<View> {
        let state = self.lock();
        state.regions.iter().find_map(|(key, r)| {
            let rec = r.instances.get(id)?;
            let (account, region) = key.split_once('/')?;
            Some(view(r, account, region, rec))
        })
    }

    fn role_credentials(&self, v: &View, now: DateTime<Utc>) -> Option<RoleCredentials> {
        let role = v.rec.role_arn.clone()?;
        let id = v.instance.instance_id.clone().unwrap_or_default();
        let key = (id.clone(), role.clone());
        if let Some(c) = self.inner.imds.credentials.lock().expect("imds lock").get(&key) {
            if c.expiration - now > Duration::minutes(15) {
                return Some(c.clone());
            }
        }
        let partition = if v.region.starts_with("cn-") {
            "aws-cn"
        } else if v.region.starts_with("us-gov-") {
            "aws-us-gov"
        } else {
            "aws"
        };
        let instance_arn = format!("arn:{partition}:ec2:{}:{}:instance/{id}", v.region, v.account);
        let creds = self.roles()?.credentials(&role, &instance_arn, now)?;
        self.inner.imds.credentials.lock().expect("imds lock").insert(key, creds.clone());
        Some(creds)
    }
}

/// Answer one metadata request.
pub async fn serve(ec2: &Ec2, ctx: &RequestContext, request: &HttpRequest) -> HttpResponse {
    let path = request.uri().path().strip_prefix(PREFIX).unwrap_or_default();
    let (instance_id, rest) = path.split_once('/').unwrap_or((path, ""));
    let Some(v) = ec2.find_instance(instance_id) else {
        return status(StatusCode::NOT_FOUND);
    };
    let now = Utc::now().max(ctx.received_at);
    let options = v.instance.metadata_options.clone().unwrap_or_default();
    if options.http_endpoint.as_deref() == Some("disabled") {
        return status(StatusCode::FORBIDDEN);
    }
    if !matches!(super::ops::instance::state_name(&v.rec).as_str(), "pending" | "running" | "stopping") {
        return status(StatusCode::NOT_FOUND);
    }
    let header = |name: &str| request.headers().get(name).and_then(|h| h.to_str().ok()).map(str::to_string);

    // IMDSv2: PUT /latest/api/token.
    if rest == "latest/api/token" {
        if request.method() != Method::PUT {
            return status(StatusCode::METHOD_NOT_ALLOWED);
        }
        if request.headers().contains_key("x-forwarded-for") {
            return status(StatusCode::FORBIDDEN);
        }
        let ttl = match header(TTL_HEADER).map(|s| s.parse::<i64>()) {
            Some(Ok(ttl)) if (1..=21600).contains(&ttl) => ttl,
            _ => return status(StatusCode::BAD_REQUEST),
        };
        let mut raw = [0u8; 42];
        rand::thread_rng().fill_bytes(&mut raw);
        use base64::Engine;
        let token = base64::engine::general_purpose::STANDARD.encode(raw);
        let mut tokens = ec2.inner.imds.tokens.lock().expect("imds lock");
        tokens.retain(|_, (_, exp)| *exp > now);
        tokens.insert(token.clone(), (instance_id.to_string(), now + Duration::seconds(ttl)));
        return http::Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .header(TTL_HEADER, ttl.to_string())
            .header("server", "EC2ws")
            .body(Bytes::from(token))
            .expect("valid response");
    }
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return status(StatusCode::METHOD_NOT_ALLOWED);
    }
    // A token, when given, must be valid; IMDSv2-only instances need one.
    match header(TOKEN_HEADER) {
        Some(token) => {
            let tokens = ec2.inner.imds.tokens.lock().expect("imds lock");
            match tokens.get(&token) {
                Some((id, exp)) if id == instance_id && *exp > now => {}
                _ => return status(StatusCode::UNAUTHORIZED),
            }
        }
        None if options.http_tokens.as_deref() == Some("required") => return status(StatusCode::UNAUTHORIZED),
        None => {}
    }

    let rest = rest.strip_prefix("latest/").unwrap_or(rest);
    match rest {
        "" => return text("dynamic\nmeta-data\nuser-data"),
        "user-data" | "user-data/" => {
            use base64::Engine;
            return match v
                .rec
                .user_data
                .as_deref()
                .and_then(|u| base64::engine::general_purpose::STANDARD.decode(u.trim()).ok())
            {
                Some(data) => respond(StatusCode::OK, "application/octet-stream", data),
                None => status(StatusCode::NOT_FOUND),
            };
        }
        "dynamic" | "dynamic/" => return text("instance-identity/"),
        "dynamic/instance-identity" | "dynamic/instance-identity/" => {
            return text("document\npkcs7\nsignature\nrsa2048")
        }
        "dynamic/instance-identity/document" => {
            let i = &v.instance;
            let doc = serde_json::json!({
                "accountId": v.account,
                "architecture": i.architecture,
                "availabilityZone": i.placement.as_ref().and_then(|p| p.availability_zone.clone()),
                "billingProducts": null,
                "devpayProductCodes": null,
                "marketplaceProductCodes": null,
                "imageId": i.image_id,
                "instanceId": i.instance_id,
                "instanceType": i.instance_type,
                "kernelId": null,
                "pendingTime": i.launch_time.map(iso),
                "privateIp": i.private_ip_address,
                "ramdiskId": null,
                "region": v.region,
                "version": "2017-09-30",
            });
            return respond(StatusCode::OK, "text/plain", serde_json::to_string_pretty(&doc).unwrap_or_default());
        }
        _ => {}
    }
    let Some(md) = rest.strip_prefix("meta-data").map(|p| p.trim_start_matches('/')) else {
        return status(StatusCode::NOT_FOUND);
    };
    match meta_data(ec2, &v, md, now) {
        Some(body) => text(body),
        None => status(StatusCode::NOT_FOUND),
    }
}

/// The `meta-data/` tree: a listing for directories, the value for leaves.
fn meta_data(ec2: &Ec2, v: &View, path: &str, now: DateTime<Utc>) -> Option<String> {
    let i = &v.instance;
    let path = path.trim_end_matches('/');
    let primary = v.enis.first();
    let public_ip = i.public_ip_address.clone();
    let public_dns = i.public_dns_name.clone().filter(|d| !d.is_empty());
    let placement = i.placement.clone().unwrap_or_default();
    let tags_enabled = i.metadata_options.as_ref().and_then(|m| m.instance_metadata_tags.as_deref()) == Some("enabled");
    let local_hostname = i.private_dns_name.clone().unwrap_or_default();
    let role_name = v.rec.role_arn.as_ref().and_then(|r| r.rsplit('/').next()).map(str::to_string);
    let leaf = |s: Option<String>| s.filter(|s| !s.is_empty());
    match path {
        "" => {
            let mut items =
                vec!["ami-id", "ami-launch-index", "ami-manifest-path", "block-device-mapping/", "events/", "hostname"];
            if v.profile.is_some() {
                items.push("iam/");
            }
            items.extend([
                "instance-action",
                "instance-id",
                "instance-life-cycle",
                "instance-type",
                "local-hostname",
                "local-ipv4",
                "mac",
                "metrics/",
                "network/",
                "placement/",
                "profile",
            ]);
            if public_ip.is_some() {
                items.extend(["public-hostname", "public-ipv4"]);
            }
            if v.key.is_some() {
                items.push("public-keys/");
            }
            items.extend(["reservation-id", "security-groups", "services/", "system"]);
            if tags_enabled {
                items.push("tags/");
            }
            Some(items.join("\n"))
        }
        "ami-id" => i.image_id.clone(),
        "ami-launch-index" => i.ami_launch_index.map(|x| x.to_string()),
        "ami-manifest-path" => Some("(unknown)".into()),
        "block-device-mapping" => {
            let mut items = vec!["ami".to_string()];
            items.extend(
                i.block_device_mappings.iter().flatten().skip(1).enumerate().map(|(n, _)| format!("ebs{}", n + 1)),
            );
            items.push("root".into());
            Some(items.join("\n"))
        }
        "block-device-mapping/ami" | "block-device-mapping/root" => {
            i.root_device_name.clone().map(|d| d.trim_start_matches("/dev/").to_string())
        }
        "events" => Some("maintenance/".into()),
        "events/maintenance" => Some("history\nscheduled".into()),
        "events/maintenance/history" | "events/maintenance/scheduled" => Some("[]".into()),
        "hostname" | "local-hostname" => Some(local_hostname),
        "instance-action" => Some("none".into()),
        "instance-id" => i.instance_id.clone(),
        "instance-life-cycle" => Some("on-demand".into()),
        "instance-type" => i.instance_type.clone(),
        "local-ipv4" => i.private_ip_address.clone(),
        "mac" => primary.and_then(|n| n.mac_address.clone()),
        "metrics" => Some("vhostmd".into()),
        "metrics/vhostmd" => Some("<?xml version=\"1.0\" encoding=\"UTF-8\"?>".into()),
        "placement" => Some("availability-zone\navailability-zone-id\ngroup-name\nregion".into()),
        "placement/availability-zone" => placement.availability_zone.clone(),
        "placement/availability-zone-id" => placement.availability_zone_id.clone(),
        "placement/group-name" => leaf(placement.group_name.clone()),
        "placement/region" => Some(v.region.clone()),
        "profile" => Some("default-hvm".into()),
        "public-hostname" => public_dns,
        "public-ipv4" => public_ip,
        "public-keys" => v.key.as_ref().map(|(name, _)| format!("0={name}")),
        "public-keys/0" => v.key.as_ref().map(|_| "openssh-key".to_string()),
        "public-keys/0/openssh-key" => v.key.as_ref().map(|(name, key)| format!("{key} {name}\n")),
        "reservation-id" => Some(v.rec.reservation_id.clone()),
        "security-groups" => {
            Some(i.security_groups.iter().flatten().filter_map(|g| g.group_name.clone()).collect::<Vec<_>>().join("\n"))
        }
        "services" => Some("domain\npartition".into()),
        "services/domain" => Some("amazonaws.com".into()),
        "services/partition" => Some("aws".into()),
        "system" => Some("xen-on-nitro".into()),
        "tags" if tags_enabled => Some("instance/".into()),
        "tags/instance" if tags_enabled => {
            Some(i.tags.iter().flatten().filter_map(|t| t.key.clone()).collect::<Vec<_>>().join("\n"))
        }
        p if tags_enabled && p.starts_with("tags/instance/") => {
            let key = &p["tags/instance/".len()..];
            i.tags.iter().flatten().find(|t| t.key.as_deref() == Some(key)).map(|t| t.value.clone().unwrap_or_default())
        }
        "iam" => v.profile.as_ref().map(|_| "info\nsecurity-credentials/".to_string()),
        "iam/info" => v.profile.as_ref().map(|p| {
            let doc = serde_json::json!({
                "Code": "Success",
                "LastUpdated": iso(now),
                "InstanceProfileArn": p.arn,
                "InstanceProfileId": p.id,
            });
            serde_json::to_string_pretty(&doc).unwrap_or_default()
        }),
        "iam/security-credentials" => role_name.clone(),
        p if p.starts_with("iam/security-credentials/") => {
            let name = &p["iam/security-credentials/".len()..];
            if role_name.as_deref() != Some(name) {
                return None;
            }
            let c = ec2.role_credentials(v, now)?;
            let doc = serde_json::json!({
                "Code": "Success",
                "LastUpdated": iso(now),
                "Type": "AWS-HMAC",
                "AccessKeyId": c.access_key_id,
                "SecretAccessKey": c.secret_access_key,
                "Token": c.session_token,
                "Expiration": iso(c.expiration),
            });
            Some(serde_json::to_string_pretty(&doc).unwrap_or_default())
        }
        "network" => Some("interfaces/".into()),
        "network/interfaces" => Some("macs/".into()),
        "network/interfaces/macs" => Some(
            v.enis.iter().filter_map(|n| n.mac_address.clone()).map(|m| format!("{m}/")).collect::<Vec<_>>().join("\n"),
        ),
        p if p.starts_with("network/interfaces/macs/") => {
            let rest = &p["network/interfaces/macs/".len()..];
            let (mac, field) = rest.split_once('/').unwrap_or((rest, ""));
            let n = v.enis.iter().find(|n| n.mac_address.as_deref() == Some(mac))?;
            let subnet = n.subnet_id.as_ref().and_then(|s| v.subnets.get(s));
            let vpc_cidr = n.vpc_id.as_ref().and_then(|id| v.vpc_cidrs.get(id)).cloned();
            let public = n.association.as_ref().and_then(|a| a.public_ip.clone());
            match field {
                "" => {
                    let mut items =
                        vec!["device-number", "interface-id", "local-hostname", "local-ipv4s", "mac", "owner-id"];
                    if public.is_some() {
                        items.extend(["public-hostname", "public-ipv4s"]);
                    }
                    items.extend([
                        "security-group-ids",
                        "security-groups",
                        "subnet-id",
                        "subnet-ipv4-cidr-block",
                        "vpc-id",
                        "vpc-ipv4-cidr-block",
                        "vpc-ipv4-cidr-blocks",
                    ]);
                    Some(items.join("\n"))
                }
                "device-number" => n.attachment.as_ref().and_then(|a| a.device_index).map(|d| d.to_string()),
                "interface-id" => n.network_interface_id.clone(),
                "local-hostname" => n.private_dns_name.clone(),
                "local-ipv4s" => Some(
                    n.private_ip_addresses
                        .iter()
                        .flatten()
                        .filter_map(|p| p.private_ip_address.clone())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                "mac" => n.mac_address.clone(),
                "owner-id" => Some(v.account.clone()),
                "public-hostname" => n.association.as_ref().and_then(|a| a.public_dns_name.clone()),
                "public-ipv4s" => public,
                "security-group-ids" => {
                    Some(n.groups.iter().flatten().filter_map(|g| g.group_id.clone()).collect::<Vec<_>>().join("\n"))
                }
                "security-groups" => {
                    Some(n.groups.iter().flatten().filter_map(|g| g.group_name.clone()).collect::<Vec<_>>().join("\n"))
                }
                "subnet-id" => n.subnet_id.clone(),
                "subnet-ipv4-cidr-block" => subnet.and_then(|s| s.cidr_block.clone()),
                "vpc-id" => n.vpc_id.clone(),
                "vpc-ipv4-cidr-block" | "vpc-ipv4-cidr-blocks" => vpc_cidr,
                _ => None,
            }
        }
        _ => None,
    }
}
