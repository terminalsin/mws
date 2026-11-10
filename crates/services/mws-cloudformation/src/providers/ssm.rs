//! Systems Manager Parameter Store resource types.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Value};

use super::{changed, gone_ok, req, s, text, Created, Cx, HResult, HandlerError, Props, Provider};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::SSM::Parameter", Arc::new(Parameter));
}

struct Parameter;

fn value(props: &Props) -> HResult<String> {
    match props.get("Value") {
        Some(Value::Array(a)) => Ok(a.iter().map(text).collect::<Vec<_>>().join(",")),
        Some(v) => Ok(text(v)),
        None => req(props, "Value"),
    }
}

fn put_input(name: &str, props: &Props, overwrite: bool) -> HResult<Value> {
    let ty = req(props, "Type")?;
    if ty == "SecureString" {
        return Err(HandlerError::invalid(
            "Properties validation failed for resource with message: #/Type: SecureString is not a valid enum value",
        ));
    }
    let mut input = json!({"Name": name, "Type": ty, "Value": value(props)?, "Overwrite": overwrite});
    for k in ["Description", "AllowedPattern", "Tier", "DataType"] {
        if let Some(v) = s(props, k) {
            input[k] = json!(v);
        }
    }
    if let Some(p) = props.get("Policies") {
        input["Policies"] = json!(match p {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        });
    }
    Ok(input)
}

#[async_trait::async_trait]
impl Provider for Parameter {
    fn name_property(&self) -> Option<&'static str> {
        Some("Name")
    }

    fn create_only(&self) -> &'static [&'static str] {
        &["Name"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["Type", "Value"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Type", "Value"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "Name").unwrap_or_else(|| {
            let generated = cx.physical_name(1000);
            let suffix = generated.rsplit('-').next().unwrap_or_default().to_string();
            format!("CFN-{}-{suffix}", cx.logical_id)
        });
        let mut input = put_input(&name, props, false)?;
        let tags: Vec<Value> = cx.tag_map(props).into_iter().map(|(k, v)| json!({"Key": k, "Value": v})).collect();
        if !tags.is_empty() {
            input["Tags"] = json!(tags);
        }
        cx.call("ssm", "PutParameter", input).await?;
        Ok(Created::new(&name).attr("Type", req(props, "Type")?).attr("Value", value(props)?))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, _attrs: &Props) -> HResult<Props> {
        if ["Type", "Value", "Description", "AllowedPattern", "Tier", "DataType", "Policies"]
            .iter()
            .any(|k| changed(old, new, k))
        {
            cx.call("ssm", "PutParameter", put_input(name, new, true)?).await?;
        }
        if changed(old, new, "Tags") {
            let new_tags = cx.tag_map(new);
            let removed: Vec<String> = cx.tag_map(old).keys().filter(|k| !new_tags.contains_key(*k)).cloned().collect();
            if !removed.is_empty() {
                cx.call(
                    "ssm",
                    "RemoveTagsFromResource",
                    json!({"ResourceType": "Parameter", "ResourceId": name, "TagKeys": removed}),
                )
                .await?;
            }
            let tags: Vec<Value> = new_tags.into_iter().map(|(k, v)| json!({"Key": k, "Value": v})).collect();
            if !tags.is_empty() {
                cx.call(
                    "ssm",
                    "AddTagsToResource",
                    json!({"ResourceType": "Parameter", "ResourceId": name, "Tags": tags}),
                )
                .await?;
            }
        }
        Ok(Created::new(name).attr("Type", req(new, "Type")?).attr("Value", value(new)?).attributes)
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("ssm", "DeleteParameter", json!({"Name": name})).await)
    }

    async fn read(&self, cx: &Cx<'_>, name: &str, props: &Props) -> Option<HResult<Props>> {
        Some(
            async {
                let out = cx.call("ssm", "GetParameter", json!({"Name": name})).await?;
                let mut p = Props::new();
                p.insert("Type".into(), out["Parameter"]["Type"].clone());
                p.insert("Value".into(), out["Parameter"]["Value"].clone());
                if props.contains_key("Name") {
                    p.insert("Name".into(), json!(name));
                }
                Ok(p)
            }
            .await,
        )
    }
}
