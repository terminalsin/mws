//! CloudFormation's own resource types: custom resources, wait conditions
//! and nested stacks.

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine;
use serde_json::{json, Map, Value};

use super::{req, text, Created, Cx, HResult, HandlerError, Props, Provider};
use crate::callback;
use crate::engine::STACK_TYPE;
use crate::parameters::Provided;
use crate::state::Stack;

pub const CUSTOM_RESOURCE: &str = "AWS::CloudFormation::CustomResource";

/// The attribute under which an update reports a new physical id.
pub const NEW_PHYSICAL_ID: &str = "\u{1}PhysicalResourceId";

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert(CUSTOM_RESOURCE, custom_resource_provider());
    m.insert("AWS::CloudFormation::WaitConditionHandle", Arc::new(WaitConditionHandle));
    m.insert("AWS::CloudFormation::WaitCondition", Arc::new(WaitCondition));
    m.insert(STACK_TYPE, Arc::new(NestedStack));
}

pub fn custom_resource_provider() -> Arc<dyn Provider> {
    Arc::new(CustomResource)
}

struct CustomResource;

impl CustomResource {
    async fn send(
        &self,
        cx: &Cx<'_>,
        request_type: &str,
        props: &Props,
        physical_id: Option<&str>,
        old: Option<&Props>,
    ) -> HResult<(String, Props)> {
        let token = req(props, "ServiceToken")?;
        let request_id = uuid::Uuid::new_v4().to_string();
        let key = format!("cr-{}", uuid::Uuid::new_v4().simple());
        let resource_type =
            cx.cfn.resource_type_of(cx.stack_id, cx.logical_id).unwrap_or_else(|| super::CUSTOM_RESOURCE.into());
        let mut event = json!({
            "RequestType": request_type,
            "ServiceToken": token,
            "ResponseURL": callback::url(cx.ctx.endpoint.as_deref(), &key),
            "StackId": cx.stack_id,
            "RequestId": request_id,
            "LogicalResourceId": cx.logical_id,
            "ResourceType": resource_type,
            "ResourceProperties": props,
        });
        if let Some(p) = physical_id {
            event["PhysicalResourceId"] = json!(p);
        }
        if let Some(o) = old {
            event["OldResourceProperties"] = json!(o);
        }
        let payload = event.to_string();
        if token.contains(":lambda:") {
            cx.call(
                "lambda",
                "Invoke",
                json!({
                    "FunctionName": token,
                    "InvocationType": "Event",
                    "Payload": base64::engine::general_purpose::STANDARD.encode(&payload),
                }),
            )
            .await?;
        } else if token.contains(":sns:") {
            cx.call("sns", "Publish", json!({"TopicArn": token, "Message": payload})).await?;
        } else {
            return Err(HandlerError::invalid(format!("Invalid service token: {token}")));
        }
        let timeout = super::int(props, "ServiceTimeout").map(|t| t as u64).unwrap_or(3600);
        let got = cx.cfn.wait_for_signals(&key, 1, timeout).await;
        cx.cfn.forget_signals(&key);
        let Ok(got) = got else {
            return Err(HandlerError::invalid(
                "CloudFormation did not receive a response from your Custom Resource. Please check your custom resource function's logs.",
            ));
        };
        let r = &got[0];
        let status = r.get("Status").and_then(Value::as_str).unwrap_or_default();
        if status != "SUCCESS" {
            return Err(HandlerError::invalid(format!(
                "Received response status [{status}] from custom resource. Message returned: {} (RequestId: {request_id})",
                r.get("Reason").map(text).unwrap_or_default()
            )));
        }
        let physical = r
            .get("PhysicalResourceId")
            .map(text)
            .filter(|p| !p.is_empty())
            .or_else(|| physical_id.map(str::to_string))
            .ok_or_else(|| HandlerError::invalid("Invalid PhysicalResourceId"))?;
        let data = r.get("Data").and_then(Value::as_object).cloned().unwrap_or_default();
        Ok((physical, data))
    }
}

#[async_trait::async_trait]
impl Provider for CustomResource {
    fn required(&self) -> &'static [&'static str] {
        &["ServiceToken"]
    }

    fn create_only(&self) -> &'static [&'static str] {
        &["ServiceToken"]
    }

    fn open_attributes(&self) -> bool {
        true
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let (physical, data) = self.send(cx, "Create", props, None, None).await?;
        Ok(Created { physical_id: physical, attributes: data })
    }

    async fn update(&self, cx: &Cx<'_>, physical_id: &str, old: &Props, new: &Props, _attrs: &Props) -> HResult<Props> {
        let (physical, mut data) = self.send(cx, "Update", new, Some(physical_id), Some(old)).await?;
        if physical != physical_id {
            data.insert(NEW_PHYSICAL_ID.into(), json!(physical));
        }
        Ok(data)
    }

    async fn delete(&self, cx: &Cx<'_>, physical_id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        self.send(cx, "Delete", props, Some(physical_id), None).await.map(|_| ())
    }
}

struct WaitConditionHandle;

#[async_trait::async_trait]
impl Provider for WaitConditionHandle {
    async fn create(&self, cx: &Cx<'_>, _props: &Props) -> HResult<Created> {
        let token = format!("wait-{}", uuid::Uuid::new_v4().simple());
        Ok(Created::new(callback::url(cx.ctx.endpoint.as_deref(), &token)))
    }

    async fn delete(&self, cx: &Cx<'_>, physical_id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        if let Some(t) = callback::token_of(physical_id) {
            cx.cfn.forget_signals(&t);
        }
        Ok(())
    }
}

struct WaitCondition;

#[async_trait::async_trait]
impl Provider for WaitCondition {
    fn attributes(&self) -> &'static [&'static str] {
        &["Data"]
    }

    fn updatable(&self) -> bool {
        false
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let handle = req(props, "Handle")?;
        let token =
            callback::token_of(&handle).ok_or_else(|| HandlerError::invalid("Invalid WaitConditionHandle URL"))?;
        let count = super::int(props, "Count").unwrap_or(1).max(1) as usize;
        let timeout = super::int(props, "Timeout").unwrap_or(43_200).max(1) as u64;
        let got = match cx.cfn.wait_for_signals(&token, count, timeout).await {
            Ok(g) => g,
            Err(()) => {
                let n = cx.cfn.signals(&token).len();
                return Err(HandlerError::invalid(format!(
                    "WaitCondition timed out. Received {n} conditions when expecting {count}"
                )));
            }
        };
        let mut data = Map::new();
        for g in &got {
            let id = g.get("UniqueId").map(text).unwrap_or_default();
            if g.get("Status").and_then(Value::as_str) == Some("FAILURE") {
                return Err(HandlerError::invalid(format!(
                    "WaitCondition received failed message: '{}' for uniqueId: {id}",
                    g.get("Reason").map(text).unwrap_or_default()
                )));
            }
            data.insert(id, json!(g.get("Data").map(text).unwrap_or_default()));
        }
        let physical = cx.arn(
            "cloudformation",
            &format!("{}/{}", cx.stack_id.rsplit(':').next().unwrap_or_default(), cx.logical_id),
        );
        Ok(Created::new(physical).attr("Data", Value::Object(data).to_string()))
    }

    async fn delete(&self, _cx: &Cx<'_>, _physical_id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        Ok(())
    }
}

struct NestedStack;

impl NestedStack {
    async fn deploy(&self, cx: &Cx<'_>, existing: Option<&str>, props: &Props) -> HResult<Created> {
        let url = req(props, "TemplateURL")?;
        let body = cx.cfn.fetch_s3(cx.ctx, &url).await.map_err(|e| HandlerError::invalid(e.message))?;
        let provided: Vec<Provided> = props
            .get("Parameters")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .map(|(k, v)| Provided {
                        key: k.clone(),
                        value: Some(match v {
                            Value::Array(a) => a.iter().map(text).collect::<Vec<_>>().join(","),
                            other => text(other),
                        }),
                        use_previous: false,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let caps = vec![
            "CAPABILITY_IAM".to_string(),
            "CAPABILITY_NAMED_IAM".to_string(),
            "CAPABILITY_AUTO_EXPAND".to_string(),
        ];
        let notifications = super::list(props, "NotificationARNs");
        let (parent_root, parent_tags) = {
            let st = cx.cfn.state();
            let p = st.stacks.get(cx.stack_id);
            (
                p.and_then(|p| p.root_id.clone()).unwrap_or_else(|| cx.stack_id.to_string()),
                p.map(|p| p.tags.clone()).unwrap_or_default(),
            )
        };
        let mut tags = parent_tags;
        if let Some(Value::Array(t)) = props.get("Tags") {
            for x in t {
                tags.push(crate::state::Tag {
                    key: x.get("Key").map(text).unwrap_or_default(),
                    value: x.get("Value").map(text).unwrap_or_default(),
                });
            }
        }
        let (id, name, previous) = match existing {
            Some(id) => {
                let st = cx.cfn.state();
                let s = st
                    .stacks
                    .get(id)
                    .ok_or_else(|| HandlerError::handler("NotFound", format!("Stack {id} not found")))?;
                (id.to_string(), s.name.clone(), s.parameters.clone())
            }
            None => {
                let name = cx.physical_name(128);
                let mut c = cx.ctx.clone();
                c.region = cx.region().to_string();
                (crate::ops_new_stack_id(&c, &name), name, Vec::new())
            }
        };
        let (template, params, data) = cx
            .cfn
            .prepare(cx.ctx, cx.ctx, &name, &id, &body, &provided, &previous, &caps, &notifications)
            .await
            .map_err(|e| HandlerError::invalid(e.message))?;
        let d = crate::engine::Deployment {
            cfn: cx.cfn.clone(),
            stack_id: id.clone(),
            ctx: cx.ctx.clone(),
            token: None,
            offset: cx.ctx.received_at - chrono::Utc::now(),
        };
        let imports = crate::ops_imports(&template, &data);
        match existing {
            None => {
                let stack = Stack {
                    id: id.clone(),
                    name: name.clone(),
                    account: cx.account().to_string(),
                    region: cx.region().to_string(),
                    status: "CREATE_IN_PROGRESS".into(),
                    created: d.now(),
                    description: template.description(),
                    template_body: body,
                    parameters: params,
                    tags,
                    capabilities: caps,
                    notification_arns: notifications,
                    timeout_in_minutes: super::int(props, "TimeoutInMinutes").map(|t| t as i32),
                    parent_id: Some(cx.stack_id.to_string()),
                    root_id: Some(parent_root),
                    imports,
                    ..Default::default()
                };
                cx.cfn.state().stacks.insert(id.clone(), stack);
                d.event(&name, STACK_TYPE, Some(&id), "CREATE_IN_PROGRESS", Some("User Initiated"), None).await;
                d.clone().create(template, data).await;
            }
            Some(_) => {
                {
                    let mut st = cx.cfn.state();
                    let s = st.stacks.get_mut(&id).expect("found above");
                    s.previous = Some(Box::new(crate::state::Snapshot {
                        template_body: s.template_body.clone(),
                        parameters: s.parameters.clone(),
                        resources: s.resources.clone(),
                        outputs: s.outputs.clone(),
                        tags: s.tags.clone(),
                    }));
                    s.template_body = body;
                    s.parameters = params;
                    s.tags = tags;
                    s.imports = imports;
                    s.status = "UPDATE_IN_PROGRESS".into();
                    s.updated = Some(d.now());
                }
                d.event(&name, STACK_TYPE, Some(&id), "UPDATE_IN_PROGRESS", Some("User Initiated"), None).await;
                d.clone().update(template, data, None).await;
            }
        }
        let st = cx.cfn.state();
        let s = &st.stacks[&id];
        if s.status != "CREATE_COMPLETE" && s.status != "UPDATE_COMPLETE" {
            return Err(HandlerError::invalid(format!(
                "Embedded stack {id} was not successfully {}: {}",
                if existing.is_some() { "updated" } else { "created" },
                s.status_reason.clone().unwrap_or_default()
            )));
        }
        let mut created = Created::new(id.clone());
        for o in &s.outputs {
            created.attributes.insert(format!("Outputs.{}", o.key), json!(o.value));
        }
        Ok(created)
    }
}

#[async_trait::async_trait]
impl Provider for NestedStack {
    fn required(&self) -> &'static [&'static str] {
        &["TemplateURL"]
    }

    fn open_attributes(&self) -> bool {
        true
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        self.deploy(cx, None, props).await
    }

    async fn update(
        &self,
        cx: &Cx<'_>,
        physical_id: &str,
        _old: &Props,
        new: &Props,
        _attrs: &Props,
    ) -> HResult<Props> {
        self.deploy(cx, Some(physical_id), new).await.map(|c| c.attributes)
    }

    async fn delete(&self, cx: &Cx<'_>, physical_id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        let exists = cx.cfn.state().stacks.get(physical_id).is_some_and(|s| !s.is_deleted());
        if !exists {
            return Ok(());
        }
        let name = {
            let mut st = cx.cfn.state();
            let s = st.stacks.get_mut(physical_id).expect("checked");
            s.status = "DELETE_IN_PROGRESS".into();
            s.name.clone()
        };
        let d = crate::engine::Deployment {
            cfn: cx.cfn.clone(),
            stack_id: physical_id.to_string(),
            ctx: cx.ctx.clone(),
            token: None,
            offset: cx.ctx.received_at - chrono::Utc::now(),
        };
        d.event(&name, STACK_TYPE, Some(physical_id), "DELETE_IN_PROGRESS", Some("User Initiated"), None).await;
        d.clone().delete(Default::default()).await;
        let st = cx.cfn.state();
        match st.stacks.get(physical_id) {
            Some(s) if s.status == "DELETE_COMPLETE" => Ok(()),
            Some(s) => Err(HandlerError::invalid(
                s.status_reason.clone().unwrap_or_else(|| "Embedded stack failed to delete".into()),
            )),
            None => Ok(()),
        }
    }
}
