//! Amazon ECR resource types.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use super::ecs::{camel, coerce, gone_codes, tag_changes};
use super::{changed, document, gone_ok, s, text, Created, Cx, HResult, Props, Provider};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::ECR::Repository", Arc::new(Repository));
    m.insert("AWS::ECR::RegistryPolicy", Arc::new(RegistryPolicy));
    m.insert("AWS::ECR::ReplicationConfiguration", Arc::new(ReplicationConfiguration));
    m.insert("AWS::ECR::PullThroughCacheRule", Arc::new(PullThroughCacheRule));
    m.insert("AWS::ECR::RepositoryCreationTemplate", Arc::new(RepositoryCreationTemplate));
}

/// A property converted to the lowerCamelCase API shape, with booleans
/// given as strings fixed.
fn api(v: &Value) -> Value {
    let mut v = camel(v, &[]);
    coerce(&mut v, &[], &["scanOnPush"], &[]);
    v
}

async fn retag(cx: &Cx<'_>, arn: &str, old: &Props, new: &Props) -> HResult<()> {
    if let Some((set, removed)) = tag_changes(cx, old, new, "Tags") {
        if !removed.is_empty() {
            cx.call("ecr", "UntagResource", json!({"resourceArn": arn, "tagKeys": removed})).await?;
        }
        if !set.is_empty() {
            cx.call("ecr", "TagResource", json!({"resourceArn": arn, "tags": set})).await?;
        }
    }
    Ok(())
}

// ---- Repository --------------------------------------------------------

struct Repository;

async fn put_policy(cx: &Cx<'_>, name: &str, props: &Props, removing: bool) -> HResult<()> {
    match document(props, "RepositoryPolicyText") {
        Some(p) => {
            cx.call("ecr", "SetRepositoryPolicy", json!({"repositoryName": name, "policyText": p})).await?;
        }
        None if removing => {
            gone_ok(cx.call("ecr", "DeleteRepositoryPolicy", json!({"repositoryName": name})).await)?;
        }
        None => {}
    }
    Ok(())
}

async fn put_lifecycle(cx: &Cx<'_>, name: &str, props: &Props, removing: bool) -> HResult<()> {
    let text_of = props.get("LifecyclePolicy").and_then(|l| l.get("LifecyclePolicyText")).map(|v| match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    });
    match text_of {
        Some(t) => {
            let mut input = json!({"repositoryName": name, "lifecyclePolicyText": t});
            if let Some(r) = props.get("LifecyclePolicy").and_then(|l| l.get("RegistryId")) {
                input["registryId"] = r.clone();
            }
            cx.call("ecr", "PutLifecyclePolicy", input).await?;
        }
        None if removing => {
            gone_ok(cx.call("ecr", "DeleteLifecyclePolicy", json!({"repositoryName": name})).await)?;
        }
        None => {}
    }
    Ok(())
}

#[async_trait::async_trait]
impl Provider for Repository {
    fn create_only(&self) -> &'static [&'static str] {
        &["RepositoryName", "EncryptionConfiguration"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn", "RepositoryUri"]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("RepositoryName")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "RepositoryName").unwrap_or_else(|| cx.physical_name_lower(256));
        let mut input = Map::new();
        input.insert("repositoryName".into(), json!(name));
        for (k, member) in [
            ("ImageTagMutability", "imageTagMutability"),
            ("ImageTagMutabilityExclusionFilters", "imageTagMutabilityExclusionFilters"),
            ("ImageScanningConfiguration", "imageScanningConfiguration"),
            ("EncryptionConfiguration", "encryptionConfiguration"),
        ] {
            if let Some(v) = props.get(k).filter(|v| !v.is_null()) {
                input.insert(member.into(), api(v));
            }
        }
        let tags = cx.tags(props);
        if !tags.is_empty() {
            input.insert("tags".into(), Value::Array(tags));
        }
        let out = cx.call("ecr", "CreateRepository", Value::Object(input)).await?;
        let repo = &out["repository"];
        put_policy(cx, &name, props, false).await?;
        put_lifecycle(cx, &name, props, false).await?;
        Ok(Created::new(&name)
            .attr("Arn", text(&repo["repositoryArn"]))
            .attr("RepositoryUri", text(&repo["repositoryUri"])))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "ImageTagMutability") || changed(old, new, "ImageTagMutabilityExclusionFilters") {
            let mut input = json!({
                "repositoryName": name,
                "imageTagMutability": s(new, "ImageTagMutability").unwrap_or_else(|| "MUTABLE".into()),
            });
            if let Some(f) = new.get("ImageTagMutabilityExclusionFilters") {
                input["imageTagMutabilityExclusionFilters"] = api(f);
            }
            cx.call("ecr", "PutImageTagMutability", input).await?;
        }
        if changed(old, new, "ImageScanningConfiguration") {
            let cfg = new.get("ImageScanningConfiguration").map(api).unwrap_or(json!({"scanOnPush": false}));
            cx.call(
                "ecr",
                "PutImageScanningConfiguration",
                json!({"repositoryName": name, "imageScanningConfiguration": cfg}),
            )
            .await?;
        }
        if changed(old, new, "RepositoryPolicyText") {
            put_policy(cx, name, new, true).await?;
        }
        if changed(old, new, "LifecyclePolicy") {
            put_lifecycle(cx, name, new, true).await?;
        }
        retag(cx, &text(&attrs["Arn"]), old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let force = super::boolean(props, "EmptyOnDelete") == Some(true);
        gone_ok(cx.call("ecr", "DeleteRepository", json!({"repositoryName": name, "force": force})).await)
    }

    async fn read(&self, cx: &Cx<'_>, name: &str, props: &Props) -> Option<HResult<Props>> {
        Some(
            async {
                let out = cx.call("ecr", "DescribeRepositories", json!({"repositoryNames": [name]})).await?;
                let r = &out["repositories"][0];
                let mut p = Props::new();
                if props.contains_key("RepositoryName") {
                    p.insert("RepositoryName".into(), r["repositoryName"].clone());
                }
                if props.contains_key("ImageTagMutability") {
                    p.insert("ImageTagMutability".into(), r["imageTagMutability"].clone());
                }
                Ok(p)
            }
            .await,
        )
    }
}

// ---- RegistryPolicy ----------------------------------------------------

struct RegistryPolicy;

#[async_trait::async_trait]
impl Provider for RegistryPolicy {
    fn required(&self) -> &'static [&'static str] {
        &["PolicyText"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["RegistryId"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let policy = document(props, "PolicyText").unwrap_or_default();
        let out = cx.call("ecr", "PutRegistryPolicy", json!({"policyText": policy})).await?;
        let id = text(&out["registryId"]);
        Ok(Created::new(&id).attr("RegistryId", id.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, _id: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let policy = document(new, "PolicyText").unwrap_or_default();
        cx.call("ecr", "PutRegistryPolicy", json!({"policyText": policy})).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, _id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("ecr", "DeleteRegistryPolicy", json!({})).await)
    }
}

// ---- ReplicationConfiguration ------------------------------------------

struct ReplicationConfiguration;

async fn put_replication(cx: &Cx<'_>, cfg: Value) -> HResult<String> {
    cx.call("ecr", "PutReplicationConfiguration", json!({"replicationConfiguration": cfg})).await?;
    let out = cx.call("ecr", "DescribeRegistry", json!({})).await?;
    Ok(text(&out["registryId"]))
}

#[async_trait::async_trait]
impl Provider for ReplicationConfiguration {
    fn required(&self) -> &'static [&'static str] {
        &["ReplicationConfiguration"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["RegistryId"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let cfg = props.get("ReplicationConfiguration").map(api).unwrap_or(json!({"rules": []}));
        let id = put_replication(cx, cfg).await?;
        Ok(Created::new(&id).attr("RegistryId", id.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, _id: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let cfg = new.get("ReplicationConfiguration").map(api).unwrap_or(json!({"rules": []}));
        put_replication(cx, cfg).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, _id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        put_replication(cx, json!({"rules": []})).await.map(|_| ())
    }
}

// ---- PullThroughCacheRule ----------------------------------------------

struct PullThroughCacheRule;

#[async_trait::async_trait]
impl Provider for PullThroughCacheRule {
    fn create_only(&self) -> &'static [&'static str] {
        &["EcrRepositoryPrefix", "UpstreamRegistryUrl", "UpstreamRegistry", "UpstreamRepositoryPrefix"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let input = api(&Value::Object(props.clone()));
        let out = cx.call("ecr", "CreatePullThroughCacheRule", input).await?;
        Ok(Created::new(text(&out["ecrRepositoryPrefix"])))
    }

    async fn update(&self, cx: &Cx<'_>, prefix: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "CredentialArn") || changed(old, new, "CustomRoleArn") {
            let mut input = json!({"ecrRepositoryPrefix": prefix});
            for (k, member) in [("CredentialArn", "credentialArn"), ("CustomRoleArn", "customRoleArn")] {
                if let Some(v) = s(new, k) {
                    input[member] = json!(v);
                }
            }
            cx.call("ecr", "UpdatePullThroughCacheRule", input).await?;
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, prefix: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("ecr", "DeletePullThroughCacheRule", json!({"ecrRepositoryPrefix": prefix})).await)
    }
}

// ---- RepositoryCreationTemplate ----------------------------------------

struct RepositoryCreationTemplate;

fn template_input(props: &Props) -> Map<String, Value> {
    let mut p = props.clone();
    p.remove("ResourceTags");
    let mut input = match api(&Value::Object(p)) {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    // Resource tags are applied to the repositories the template creates,
    // not to the template, so stack tags don't belong in them.
    if let Some(t) = props.get("ResourceTags").filter(|v| !v.is_null()) {
        input.insert("resourceTags".into(), t.clone());
    }
    for k in ["repositoryPolicy", "lifecyclePolicy"] {
        if let Some(v) = input.get(k).filter(|v| !v.is_string()).cloned() {
            input.insert(k.into(), json!(v.to_string()));
        }
    }
    input
}

#[async_trait::async_trait]
impl Provider for RepositoryCreationTemplate {
    fn create_only(&self) -> &'static [&'static str] {
        &["Prefix"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["Prefix", "AppliedFor"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["CreatedAt", "UpdatedAt"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let out = cx.call("ecr", "CreateRepositoryCreationTemplate", Value::Object(template_input(props))).await?;
        let t = &out["repositoryCreationTemplate"];
        Ok(Created::new(text(&t["prefix"]))
            .attr("CreatedAt", text(&t["createdAt"]))
            .attr("UpdatedAt", text(&t["updatedAt"])))
    }

    async fn update(&self, cx: &Cx<'_>, _prefix: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let out = cx.call("ecr", "UpdateRepositoryCreationTemplate", Value::Object(template_input(new))).await?;
        let mut a = attrs.clone();
        a.insert("UpdatedAt".into(), json!(text(&out["repositoryCreationTemplate"]["updatedAt"])));
        Ok(a)
    }

    async fn delete(&self, cx: &Cx<'_>, prefix: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_codes(cx.call("ecr", "DeleteRepositoryCreationTemplate", json!({"prefix": prefix})).await, &[])
    }
}
