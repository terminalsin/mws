//! Secrets Manager resource types.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use super::{
    boolean, bools, changed, copy, document, gone_ok, numbers, req, s, text, Created, Cx, HResult, Props, Provider,
};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::SecretsManager::Secret", Arc::new(Secret));
    m.insert("AWS::SecretsManager::ResourcePolicy", Arc::new(ResourcePolicy));
}

/// The secret value: `SecretString`, or one `GenerateSecretString` makes.
async fn secret_string(cx: &Cx<'_>, props: &Props) -> HResult<Option<String>> {
    if let Some(v) = s(props, "SecretString") {
        return Ok(Some(v));
    }
    let Some(Value::Object(g)) = props.get("GenerateSecretString") else { return Ok(None) };
    let mut input = Map::new();
    copy(
        g,
        &mut input,
        &[
            "PasswordLength",
            "ExcludeCharacters",
            "ExcludeNumbers",
            "ExcludePunctuation",
            "ExcludeUppercase",
            "ExcludeLowercase",
            "IncludeSpace",
            "RequireEachIncludedType",
        ],
    );
    numbers(&mut input, &["PasswordLength"]);
    bools(
        &mut input,
        &[
            "ExcludeNumbers",
            "ExcludePunctuation",
            "ExcludeUppercase",
            "ExcludeLowercase",
            "IncludeSpace",
            "RequireEachIncludedType",
        ],
    );
    let out = cx.call("secretsmanager", "GetRandomPassword", Value::Object(input)).await?;
    let password = text(&out["RandomPassword"]);
    match (g.get("SecretStringTemplate").map(text), g.get("GenerateStringKey").map(text)) {
        (Some(t), Some(k)) => {
            let mut v: Value = serde_json::from_str(&t)
                .map_err(|_| super::HandlerError::invalid("SecretStringTemplate must be a valid JSON object"))?;
            v[k] = json!(password);
            Ok(Some(v.to_string()))
        }
        _ => Ok(Some(password)),
    }
}

struct Secret;

#[async_trait::async_trait]
impl Provider for Secret {
    fn create_only(&self) -> &'static [&'static str] {
        &["Name"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Id"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "Name").unwrap_or_else(|| {
            let generated = cx.physical_name(512);
            let suffix = generated.rsplit('-').next().unwrap_or_default().to_string();
            format!("{}-{suffix}", cx.logical_id)
        });
        let mut input = json!({"Name": name, "ClientRequestToken": uuid::Uuid::new_v4().to_string()});
        if let Some(v) = secret_string(cx, props).await? {
            input["SecretString"] = json!(v);
        }
        for k in ["Description", "KmsKeyId"] {
            if let Some(v) = s(props, k) {
                input[k] = json!(v);
            }
        }
        let tags = cx.tags(props);
        if !tags.is_empty() {
            input["Tags"] = json!(tags);
        }
        if let Some(Value::Array(r)) = props.get("ReplicaRegions") {
            input["AddReplicaRegions"] = json!(r);
        }
        let out = cx.call("secretsmanager", "CreateSecret", input).await?;
        let arn = text(&out["ARN"]);
        Ok(Created::new(&arn).attr("Id", arn.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, arn: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let mut input = json!({"SecretId": arn});
        let mut any = false;
        for k in ["Description", "KmsKeyId"] {
            if changed(old, new, k) {
                input[k] = json!(s(new, k).unwrap_or_default());
                any = true;
            }
        }
        if changed(old, new, "SecretString") || changed(old, new, "GenerateSecretString") {
            if let Some(v) = secret_string(cx, new).await? {
                input["SecretString"] = json!(v);
                input["ClientRequestToken"] = json!(uuid::Uuid::new_v4().to_string());
                any = true;
            }
        }
        if any {
            cx.call("secretsmanager", "UpdateSecret", input).await?;
        }
        if changed(old, new, "Tags") {
            let new_tags = cx.tags(new);
            let keys: Vec<String> = new_tags.iter().map(|t| text(&t["Key"])).collect();
            let removed: Vec<String> =
                cx.tags(old).iter().map(|t| text(&t["Key"])).filter(|k| !keys.contains(k)).collect();
            if !removed.is_empty() {
                cx.call("secretsmanager", "UntagResource", json!({"SecretId": arn, "TagKeys": removed})).await?;
            }
            if !new_tags.is_empty() {
                cx.call("secretsmanager", "TagResource", json!({"SecretId": arn, "Tags": new_tags})).await?;
            }
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, arn: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(
            cx.call("secretsmanager", "DeleteSecret", json!({"SecretId": arn, "ForceDeleteWithoutRecovery": true}))
                .await,
        )
    }

    async fn read(&self, cx: &Cx<'_>, arn: &str, props: &Props) -> Option<HResult<Props>> {
        Some(
            async {
                let out = cx.call("secretsmanager", "DescribeSecret", json!({"SecretId": arn})).await?;
                if out.get("DeletedDate").is_some_and(|d| !d.is_null()) {
                    return Err(super::HandlerError::handler(
                        "NotFound",
                        format!("Secret {arn} is scheduled for deletion"),
                    ));
                }
                let mut p = Props::new();
                for k in ["Name", "Description", "KmsKeyId"] {
                    if props.contains_key(k) {
                        p.insert(k.into(), out.get(k).cloned().unwrap_or(Value::Null));
                    }
                }
                if props.contains_key("SecretString") {
                    let v = cx.call("secretsmanager", "GetSecretValue", json!({"SecretId": arn})).await?;
                    p.insert("SecretString".into(), v["SecretString"].clone());
                }
                Ok(p)
            }
            .await,
        )
    }
}

struct ResourcePolicy;

#[async_trait::async_trait]
impl Provider for ResourcePolicy {
    fn create_only(&self) -> &'static [&'static str] {
        &["SecretId"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["SecretId", "ResourcePolicy"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Id"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let id = req(props, "SecretId")?;
        let mut input =
            json!({"SecretId": id, "ResourcePolicy": document(props, "ResourcePolicy").unwrap_or_default()});
        if let Some(b) = boolean(props, "BlockPublicPolicy") {
            input["BlockPublicPolicy"] = json!(b);
        }
        let out = cx.call("secretsmanager", "PutResourcePolicy", input).await?;
        let arn = text(&out["ARN"]);
        Ok(Created::new(&arn).attr("Id", arn.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, _arn: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        self.create(cx, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, arn: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("secretsmanager", "DeleteResourcePolicy", json!({"SecretId": arn})).await)
    }
}
