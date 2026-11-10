//! KMS resource types.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Value};

use super::{boolean, changed, document, gone_ok, int, req, s, text, Created, Cx, HResult, Props, Provider};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::KMS::Key", Arc::new(Key));
    m.insert("AWS::KMS::Alias", Arc::new(Alias));
}

fn kms_tags(cx: &Cx<'_>, props: &Props) -> Vec<Value> {
    cx.tags(props).iter().map(|t| json!({"TagKey": t["Key"], "TagValue": t["Value"]})).collect()
}

fn policy(cx: &Cx<'_>, props: &Props) -> String {
    document(props, "KeyPolicy").unwrap_or_else(|| {
        json!({
            "Version": "2012-10-17",
            "Id": "key-default-1",
            "Statement": [{
                "Sid": "Enable IAM User Permissions",
                "Effect": "Allow",
                "Principal": {"AWS": format!("arn:{}:iam::{}:root", cx.partition(), cx.account())},
                "Action": "kms:*",
                "Resource": "*"
            }]
        })
        .to_string()
    })
}

struct Key;

#[async_trait::async_trait]
impl Provider for Key {
    fn create_only(&self) -> &'static [&'static str] {
        &["KeySpec", "KeyUsage", "MultiRegion", "Origin"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn", "KeyId"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = json!({"Policy": policy(cx, props)});
        for k in ["Description", "KeyUsage", "KeySpec", "Origin"] {
            if let Some(v) = s(props, k) {
                input[k] = json!(v);
            }
        }
        if let Some(m) = boolean(props, "MultiRegion") {
            input["MultiRegion"] = json!(m);
        }
        if let Some(b) = boolean(props, "BypassPolicyLockoutSafetyCheck") {
            input["BypassPolicyLockoutSafetyCheck"] = json!(b);
        }
        let tags = kms_tags(cx, props);
        if !tags.is_empty() {
            input["Tags"] = json!(tags);
        }
        let out = cx.call("kms", "CreateKey", input).await?;
        let id = text(&out["KeyMetadata"]["KeyId"]);
        if boolean(props, "EnableKeyRotation") == Some(true) {
            let mut r = json!({"KeyId": id});
            if let Some(p) = int(props, "RotationPeriodInDays") {
                r["RotationPeriodInDays"] = json!(p);
            }
            cx.call("kms", "EnableKeyRotation", r).await?;
        }
        if boolean(props, "Enabled") == Some(false) {
            cx.call("kms", "DisableKey", json!({"KeyId": id})).await?;
        }
        Ok(Created::new(&id).attr("KeyId", id.clone()).attr("Arn", out["KeyMetadata"]["Arn"].clone()))
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "Description") {
            cx.call(
                "kms",
                "UpdateKeyDescription",
                json!({"KeyId": id, "Description": s(new, "Description").unwrap_or_default()}),
            )
            .await?;
        }
        if changed(old, new, "KeyPolicy") {
            cx.call("kms", "PutKeyPolicy", json!({"KeyId": id, "PolicyName": "default", "Policy": policy(cx, new)}))
                .await?;
        }
        if changed(old, new, "Enabled") {
            let op = if boolean(new, "Enabled") == Some(false) { "DisableKey" } else { "EnableKey" };
            cx.call("kms", op, json!({"KeyId": id})).await?;
        }
        if changed(old, new, "EnableKeyRotation") || changed(old, new, "RotationPeriodInDays") {
            if boolean(new, "EnableKeyRotation") == Some(true) {
                let mut r = json!({"KeyId": id});
                if let Some(p) = int(new, "RotationPeriodInDays") {
                    r["RotationPeriodInDays"] = json!(p);
                }
                cx.call("kms", "EnableKeyRotation", r).await?;
            } else {
                cx.call("kms", "DisableKeyRotation", json!({"KeyId": id})).await?;
            }
        }
        if changed(old, new, "Tags") {
            let new_tags = kms_tags(cx, new);
            let keys: Vec<Value> = new_tags.iter().map(|t| t["TagKey"].clone()).collect();
            let removed: Vec<Value> =
                kms_tags(cx, old).iter().map(|t| t["TagKey"].clone()).filter(|k| !keys.contains(k)).collect();
            if !removed.is_empty() {
                cx.call("kms", "UntagResource", json!({"KeyId": id, "TagKeys": removed})).await?;
            }
            if !new_tags.is_empty() {
                cx.call("kms", "TagResource", json!({"KeyId": id, "Tags": new_tags})).await?;
            }
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let days = int(props, "PendingWindowInDays").unwrap_or(30);
        match cx.call("kms", "ScheduleKeyDeletion", json!({"KeyId": id, "PendingWindowInDays": days})).await {
            Ok(_) => Ok(()),
            Err(e) if e.not_found || e.message.contains("pending deletion") => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn read(&self, cx: &Cx<'_>, id: &str, props: &Props) -> Option<HResult<Props>> {
        Some(
            async {
                let out = cx.call("kms", "DescribeKey", json!({"KeyId": id})).await?;
                let m = &out["KeyMetadata"];
                if m["KeyState"] == json!("PendingDeletion") {
                    return Err(super::HandlerError::handler("NotFound", format!("Key {id} is pending deletion")));
                }
                let mut p = Props::new();
                if props.contains_key("Description") {
                    p.insert("Description".into(), m["Description"].clone());
                }
                if props.contains_key("Enabled") {
                    p.insert("Enabled".into(), m["Enabled"].clone());
                }
                if props.contains_key("KeyPolicy") {
                    let pol = cx.call("kms", "GetKeyPolicy", json!({"KeyId": id, "PolicyName": "default"})).await?;
                    p.insert(
                        "KeyPolicy".into(),
                        pol["Policy"].as_str().and_then(|s| serde_json::from_str(s).ok()).unwrap_or_default(),
                    );
                }
                Ok(p)
            }
            .await,
        )
    }
}

struct Alias;

#[async_trait::async_trait]
impl Provider for Alias {
    fn name_property(&self) -> Option<&'static str> {
        Some("AliasName")
    }

    fn create_only(&self) -> &'static [&'static str] {
        &["AliasName"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["AliasName", "TargetKeyId"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = req(props, "AliasName")?;
        cx.call("kms", "CreateAlias", json!({"AliasName": name, "TargetKeyId": req(props, "TargetKeyId")?})).await?;
        Ok(Created::new(name))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        cx.call("kms", "UpdateAlias", json!({"AliasName": name, "TargetKeyId": req(new, "TargetKeyId")?})).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("kms", "DeleteAlias", json!({"AliasName": name})).await)
    }
}
