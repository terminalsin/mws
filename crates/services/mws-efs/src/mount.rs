//! Mounting file systems from EC2 instances.
//!
//! AWS clients mount EFS over NFSv4.1 (TCP 2049) at a mount target's
//! address, directly (`mount -t nfs4 fs-1234.efs.<region>.amazonaws.com:/
//! /mnt`) or through the EFS mount helper (`mount -t efs -o tls,iam
//! fs-1234:/ /mnt`). MWS has no NFS server; instead it shares the
//! directory tree of every file system into the instances EC2 runs (at
//! [`INSTANCE_ROOT`]) and installs a `mount` helper that asks MWS
//! (`GET /_aws/efs/mount`) whether the mount would succeed on AWS and which
//! directory it reaches, then bind-mounts that directory (or, where the
//! container may not mount, links it).
//!
//! The checks are those AWS's network and EFS make: the instance is
//! running; the file system exists and has an available mount target in
//! the instance's VPC (for the plain DNS name, in the instance's
//! Availability Zone, since the name resolves to that zone's mount
//! target); the mount target's security groups let TCP 2049 in from the
//! instance; the file system policy, if any, allows
//! `elasticfilesystem:ClientMount` for the client (anonymous, or the
//! instance profile role with `-o iam`), and `ClientWrite` or the mount is
//! read-only; access points (`-o accesspoint=fsap-...`, which needs
//! `tls`) belong to the file system and create their root directory with
//! their `CreationInfo`. Replication destinations mount read-only.

use std::collections::BTreeMap;

use bytes::Bytes;
use mws_core::{HttpRequest, HttpResponse, RequestContext};
use mws_ec2::backend::LaunchSpec;
use mws_ec2::{InstanceNetwork, LaunchExtension, LaunchExtras};
use mws_iam_policy::{ConditionContext, Policy, PolicyKind, PrincipalInfo, Request};

use crate::state::{MountTarget, State};
use crate::storage::relative;
use crate::Efs;

/// Where mount requests from instances arrive (unsigned, like IMDS).
pub const PREFIX: &str = "/_aws/efs/";

/// Where every instance sees the file system directories.
pub const INSTANCE_ROOT: &str = "/var/lib/mws-efs";

/// A successful mount, as the helper needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountGrant {
    /// The directory to mount, relative to the data root.
    pub dir: String,
    pub read_only: bool,
    /// `uid:gid` to give a root directory an access point just created.
    pub chown: Option<String>,
    pub mount_target_id: String,
}

/// What the helper sends: the instance, the mount type, the source
/// (`host:/path`) and the options.
#[derive(Debug, Clone, Default)]
pub struct MountRequest {
    pub instance_id: String,
    pub fs_type: String,
    pub source: String,
    pub options: String,
}

fn nfs(msg: impl std::fmt::Display) -> String {
    format!("mount.nfs4: {msg}")
}

impl Efs {
    /// Decide a mount the way AWS would (see the module documentation).
    pub fn authorize_mount(&self, req: &MountRequest) -> Result<MountGrant, String> {
        let options: BTreeMap<String, String> = req
            .options
            .split(',')
            .filter(|o| !o.is_empty())
            .map(|o| match o.split_once('=') {
                Some((k, v)) => (k.trim().to_string(), v.trim().to_string()),
                None => (o.trim().to_string(), String::new()),
            })
            .collect();
        let helper = req.fs_type == "efs";
        let tls = options.contains_key("tls");
        let iam = options.contains_key("iam");
        if helper && (iam || options.contains_key("accesspoint")) && !tls {
            let which = if iam { "iam" } else { "accesspoint" };
            return Err(format!("The '{which}' option requires the 'tls' option."));
        }
        let instance = self.ec2().instance_network(&req.instance_id).ok_or_else(|| nfs("Connection timed out"))?;
        if instance.state != "running" {
            return Err(nfs("Connection timed out"));
        }
        let (host, path) = match req.source.split_once(":") {
            Some((h, p)) => (h.to_string(), if p.is_empty() { "/".to_string() } else { p.to_string() }),
            None if helper => (req.source.clone(), "/".to_string()),
            None => return Err("mount.nfs4: remote share not in 'host:dir' format".to_string()),
        };
        let st = self.lock();
        let region_key = State::key(&instance.account_id, &instance.region);
        let target = self.resolve_target(&st, &instance, &host, &options, helper)?;
        let (fs_key, fs) = st.find_fs(&target.description.file_system_id).ok_or_else(|| nfs("Connection timed out"))?;
        if fs.description.life_cycle_state != "available" {
            return Err(nfs("Connection timed out"));
        }
        let mt_region = fs_key.split_once('/').map(|(_, r)| r).unwrap_or_default();
        if fs_key != region_key && mt_region != instance.region {
            return Err(nfs("Connection timed out"));
        }
        let mt_account = fs_key.split('/').next().unwrap_or_default();
        // The mount target's security groups must let NFS in.
        if !self.ec2().ingress_allows_tcp(
            mt_account,
            mt_region,
            &target.security_groups,
            2049,
            &instance.private_ip,
            &instance.security_groups,
        ) {
            return Err(nfs("Connection timed out"));
        }
        // Access point.
        let ap = match options.get("accesspoint") {
            Some(id) => {
                let ap = st
                    .regions
                    .get(fs_key)
                    .and_then(|r| r.access_points.get(id))
                    .filter(|a| a.file_system_id.as_deref() == Some(fs.id()))
                    .ok_or_else(|| {
                        format!("Access point {id} does not exist or does not belong to file system {}.", fs.id())
                    })?;
                Some(ap.clone())
            }
            None => None,
        };
        // File system policy.
        let mut read_only = options.contains_key("ro");
        let mut context = ConditionContext::new();
        context.insert("elasticfilesystem:AccessedViaMountTarget", vec!["true".into()]);
        context.insert("aws:SecureTransport", vec![tls.to_string()]);
        context.insert("aws:SourceIp", vec![instance.private_ip.clone()]);
        if let Some(ap) = &ap {
            context.insert("elasticfilesystem:AccessPointArn", vec![ap.access_point_arn.clone().unwrap_or_default()]);
        }
        if let Some(doc) = &fs.policy {
            let policy = Policy::parse(doc, PolicyKind::Resource).map_err(|_| nfs("access denied by server"))?;
            let principal = client_principal(&instance, iam);
            let arn = fs.description.file_system_arn.clone().unwrap_or_default();
            let allowed = |action: &str| {
                let e = policy.evaluate(&Request { action, resource: &arn, principal: &principal, context: &context });
                !e.denied() && e.allowed()
            };
            if !allowed("elasticfilesystem:ClientMount") {
                return Err(nfs(format!("access denied by server while mounting {}", req.source)));
            }
            if !allowed("elasticfilesystem:ClientWrite") {
                read_only = true;
            }
        }
        let replicating =
            fs.description.file_system_protection.as_ref().and_then(|p| p.replication_overwrite_protection.as_deref())
                == Some("REPLICATING");
        if replicating {
            read_only = true;
        }
        // The directory: the access point's root, then the path.
        let ap_root = ap
            .as_ref()
            .and_then(|a| a.root_directory.as_ref())
            .and_then(|r| r.path.clone())
            .unwrap_or_else(|| "/".into());
        let ap_rel = relative(&ap_root).ok_or_else(|| nfs("access denied by server"))?;
        let sub = relative(&path).ok_or_else(|| nfs("access denied by server"))?;
        let fs_dir = self.storage().dir(fs.id());
        let ap_dir = fs_dir.join(&ap_rel);
        let mut chown = None;
        if !ap_dir.exists() {
            let info = ap.as_ref().and_then(|a| a.root_directory.as_ref()).and_then(|r| r.creation_info.clone());
            let Some(info) = info else {
                return Err(nfs(format!("access denied by server while mounting {}", req.source)));
            };
            std::fs::create_dir_all(&ap_dir).map_err(|e| nfs(format!("mounting failed: {e}")))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = u32::from_str_radix(&info.permissions, 8).unwrap_or(0o755);
                let _ = std::fs::set_permissions(&ap_dir, std::fs::Permissions::from_mode(mode));
            }
            chown = Some(format!("{}:{}", info.owner_uid, info.owner_gid));
        }
        let dir = ap_dir.join(&sub);
        if !dir.is_dir() {
            return Err(nfs(format!(
                "mounting {} failed, reason given by server: No such file or directory",
                req.source
            )));
        }
        let mut rel = std::path::PathBuf::from(fs.id());
        rel.extend(ap_rel.components().chain(sub.components()));
        Ok(MountGrant {
            dir: rel.to_string_lossy().into_owned(),
            read_only,
            chown,
            mount_target_id: target.description.mount_target_id.clone(),
        })
    }

    /// The mount target a mount source reaches from `instance`.
    fn resolve_target(
        &self,
        st: &State,
        instance: &InstanceNetwork,
        host: &str,
        options: &BTreeMap<String, String>,
        helper: bool,
    ) -> Result<MountTarget, String> {
        let targets = || st.regions.values().flat_map(|r| r.mount_targets.values());
        let in_vpc = |m: &&MountTarget| {
            m.description.vpc_id.as_deref() == Some(instance.vpc_id.as_str())
                && m.description.life_cycle_state == "available"
        };
        let unresolvable = || {
            if helper {
                format!(
                    "Failed to resolve \"{host}\" - check that your file system ID is correct, and ensure that the VPC has an EFS mount target for this file system ID."
                )
            } else {
                format!("mount.nfs4: Failed to resolve server {host}: Name or service not known")
            }
        };
        // An IP address: the mount target that has it.
        let ip = options
            .get("mounttargetip")
            .map(String::as_str)
            .or_else(|| host.parse::<std::net::IpAddr>().ok().map(|_| host));
        if let Some(ip) = ip {
            return targets()
                .find(|m| {
                    m.description.ip_address.as_deref() == Some(ip) || m.description.ipv6_address.as_deref() == Some(ip)
                })
                .filter(|m| in_vpc(m))
                .cloned()
                .ok_or_else(|| nfs("Connection timed out"));
        }
        // `fs-1234`, `fs-1234.efs.<region>.amazonaws.com` or
        // `<az>.fs-1234.efs.<region>.amazonaws.com`.
        let labels: Vec<&str> = host.split('.').collect();
        let (az, fs_id) = match labels.as_slice() {
            [id] => (None, *id),
            [az, id, "efs", ..] if id.starts_with("fs-") => (Some(*az), *id),
            [id, "efs", ..] => (None, *id),
            _ => return Err(unresolvable()),
        };
        if !fs_id.starts_with("fs-") {
            return Err(unresolvable());
        }
        if labels.len() > 1 {
            // The DNS name names a Region; it must be the instance's.
            let region = labels.iter().skip_while(|l| **l != "efs").nth(1).copied().unwrap_or_default();
            if region != instance.region {
                return Err(unresolvable());
            }
        }
        let mine: Vec<&MountTarget> =
            targets().filter(|m| m.description.file_system_id == fs_id).filter(in_vpc).collect();
        let zone = az.unwrap_or(instance.availability_zone.as_str());
        if let Some(m) = mine.iter().find(|m| m.description.availability_zone_name.as_deref() == Some(zone)) {
            return Ok((*m).clone());
        }
        // The mount helper falls back to a mount target in another zone;
        // the bare DNS name only resolves in zones that have one.
        if helper && az.is_none() {
            if let Some(m) = mine.first() {
                return Ok((*m).clone());
            }
        }
        Err(unresolvable())
    }

    /// The launch extension that shares file systems into instances and
    /// installs the mount helper. Register it with
    /// [`mws_ec2::Ec2::add_launch_extension`].
    pub fn instance_support(&self) -> std::sync::Arc<dyn LaunchExtension> {
        std::sync::Arc::new(InstanceSupport { root: self.storage().root().to_path_buf() })
    }
}

/// The principal an NFS client is: anonymous, or with `-o iam` the
/// instance profile role's session (named after the instance).
fn client_principal(instance: &InstanceNetwork, iam: bool) -> PrincipalInfo {
    match (&instance.role_arn, iam) {
        (Some(role), true) => {
            let partition = role.split(':').nth(1).unwrap_or("aws");
            let name = role.rsplit('/').next().unwrap_or_default();
            PrincipalInfo {
                account_id: instance.account_id.clone(),
                arns: vec![format!(
                    "arn:{partition}:sts::{}:assumed-role/{name}/{}",
                    instance.account_id, instance.instance_id
                )],
                role_arn: Some(role.clone()),
                ..Default::default()
            }
        }
        _ => PrincipalInfo { anonymous: true, ..Default::default() },
    }
}

/// Answer the mount helper. Always 200 with `key=value` lines, so the
/// helper reads failures the same way with curl or busybox wget.
pub fn serve(efs: &Efs, _ctx: &RequestContext, request: &HttpRequest) -> HttpResponse {
    let query: BTreeMap<String, String> =
        form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes()).into_owned().collect();
    let body = if request.uri().path() != format!("{PREFIX}mount") {
        "error=unknown EFS endpoint\n".to_string()
    } else {
        let req = MountRequest {
            instance_id: query.get("instance").cloned().unwrap_or_default(),
            fs_type: query.get("type").cloned().unwrap_or_default(),
            source: query.get("source").cloned().unwrap_or_default(),
            options: query.get("options").cloned().unwrap_or_default(),
        };
        match efs.authorize_mount(&req) {
            Ok(g) => {
                let mut s =
                    format!("dir={}\nreadonly={}\nmount_target={}\n", g.dir, g.read_only as u8, g.mount_target_id);
                if let Some(c) = g.chown {
                    s.push_str(&format!("chown={c}\n"));
                }
                s
            }
            Err(e) => format!("error={e}\n"),
        }
    };
    http::Response::builder()
        .status(200)
        .header("content-type", "text/plain")
        .body(Bytes::from(body))
        .expect("static response parts are valid")
}

struct InstanceSupport {
    root: std::path::PathBuf,
}

impl LaunchExtension for InstanceSupport {
    fn extend(&self, spec: &LaunchSpec) -> LaunchExtras {
        let mut extras = LaunchExtras {
            mounts: vec![mws_ec2::HostMount { source: self.root.clone(), target: INSTANCE_ROOT.into() }],
            capabilities: vec!["SYS_ADMIN".into()],
            security_options: vec!["apparmor=unconfined".into()],
            ..Default::default()
        };
        if let Some((_, endpoint)) = spec.env.iter().find(|(k, _)| k == "AWS_ENDPOINT_URL") {
            extras.boot_hooks.push(boot_hook(endpoint, &spec.instance_id));
        }
        extras
    }
}

/// Shell that installs the mount helper as `mount` (ahead of the real one
/// on `PATH`), `mount.efs` and `mount.nfs4`.
pub fn boot_hook(endpoint: &str, instance_id: &str) -> String {
    let script = HELPER
        .replace("@ENDPOINT@", &format!("{}{PREFIX}mount", endpoint.trim_end_matches('/')))
        .replace("@INSTANCE@", instance_id)
        .replace("@ROOT@", INSTANCE_ROOT);
    format!(
        "mkdir -p /usr/local/sbin /sbin 2>/dev/null\ncat > /usr/local/sbin/mount <<'MWS_EFS_EOF'\n{script}MWS_EFS_EOF\nchmod 755 /usr/local/sbin/mount\nfor h in /sbin/mount.efs /sbin/mount.nfs4 /sbin/mount.nfs; do ln -sf /usr/local/sbin/mount \"$h\" 2>/dev/null; done\n"
    )
}

const HELPER: &str = r#"#!/bin/sh
# Installed by MWS: mounts Amazon EFS file systems emulated by MWS
# (types efs, nfs4 and nfs); everything else goes to the real mount.
ENDPOINT='@ENDPOINT@'
INSTANCE='@INSTANCE@'
ROOT='@ROOT@'
real_mount() {
  for m in /usr/bin/mount /bin/mount /usr/sbin/mount.real; do
    if [ -x "$m" ] && [ "$m" != /usr/local/sbin/mount ]; then exec "$m" "$@"; fi
  done
  echo "mount: no mount command found" >&2; exit 1
}
name=${0##*/}
type=""
case "$name" in
  mount.efs) type=efs ;;
  mount.nfs4) type=nfs4 ;;
  mount.nfs) type=nfs ;;
esac
prev=""
for a in "$@"; do
  case "$prev" in -t) type=$a ;; esac
  case "$a" in -t?*) type=${a#-t} ;; --types=*) type=${a#--types=} ;; esac
  prev=$a
done
# `mount -a`: the EFS and NFS entries of /etc/fstab through this helper,
# the rest through the real mount.
all=""
for a in "$@"; do case "$a" in -a|--all) all=1 ;; esac; done
if [ -n "$all" ] && [ -z "$type" ]; then
  status=0
  if [ -f /etc/fstab ]; then
    while read -r fsrc fdst ftype fopts rest; do
      case "$fsrc" in ''|\#*) continue ;; esac
      case "$ftype" in efs|nfs|nfs4) ;; *) continue ;; esac
      if [ -L "$fdst" ] || grep -qs " $fdst " /proc/mounts; then continue; fi
      /usr/local/sbin/mount -t "$ftype" -o "${fopts:-defaults}" "$fsrc" "$fdst" < /dev/null || status=32
    done < /etc/fstab
  fi
  for m in /usr/bin/mount /bin/mount; do
    if [ -x "$m" ]; then "$m" -a -t noefs,nonfs,nonfs4 || status=$?; break; fi
  done
  exit $status
fi
case "$type" in
  efs|nfs|nfs4) ;;
  *) real_mount "$@" ;;
esac
opts=""; src=""; dst=""; prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then opts="${opts:+$opts,}$a"; prev=""; continue; fi
  if [ "$prev" = "-t" ]; then prev=""; continue; fi
  case "$a" in
    -o|-t) prev=$a ;;
    -o?*) opts="${opts:+$opts,}${a#-o}" ;;
    -*) ;;
    *) if [ -z "$src" ]; then src=$a; else dst=$a; fi ;;
  esac
done
if [ -z "$src" ] || [ -z "$dst" ]; then echo "usage: mount -t $type [-o options] source target" >&2; exit 1; fi
enc() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n' | sed 's/../%&/g'; }
url="$ENDPOINT?instance=$INSTANCE&type=$(enc "$type")&source=$(enc "$src")&options=$(enc "$opts")"
if command -v curl >/dev/null 2>&1; then resp=$(curl -fsS "$url")
elif command -v wget >/dev/null 2>&1; then resp=$(wget -qO- "$url")
else echo "mount.nfs4: Connection timed out" >&2; exit 32; fi || { echo "mount.nfs4: Connection timed out" >&2; exit 32; }
val() { printf '%s\n' "$resp" | sed -n "s/^$1=//p" | head -n 1; }
err=$(val error)
if [ -n "$err" ]; then echo "$err" >&2; exit 32; fi
dir="$ROOT/$(val dir)"
owner=$(val chown)
if [ -n "$owner" ]; then chown "$owner" "$dir" 2>/dev/null; fi
if [ ! -d "$dst" ]; then echo "mount: mount point $dst does not exist" >&2; exit 32; fi
for m in /usr/bin/mount /bin/mount; do [ -x "$m" ] && REAL=$m && break; done
if [ -n "$REAL" ] && "$REAL" -o bind "$dir" "$dst" 2>/dev/null; then
  if [ "$(val readonly)" = 1 ]; then "$REAL" -o remount,bind,ro "$dst" 2>/dev/null; fi
  exit 0
fi
# No mount privilege in this container: link the directory instead.
if rmdir "$dst" 2>/dev/null; then ln -s "$dir" "$dst" && exit 0; fi
echo "mount.nfs4: Operation not permitted" >&2
exit 32
"#;
