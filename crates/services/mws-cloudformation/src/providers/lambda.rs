//! Lambda resource types.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::Arc;

use base64::Engine;
use serde_json::{json, Map, Value};

use super::{changed, copy, gone_ok, int, numbers, bools, req, s, text, Created, Cx, HResult, HandlerError, Props, Provider};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::Lambda::Function", Arc::new(Function));
    m.insert("AWS::Lambda::Permission", Arc::new(Permission));
    m.insert("AWS::Lambda::EventSourceMapping", Arc::new(EventSourceMapping));
    m.insert("AWS::Lambda::Version", Arc::new(Version));
    m.insert("AWS::Lambda::Alias", Arc::new(Alias));
    m.insert("AWS::Lambda::Url", Arc::new(Url));
    m.insert("AWS::Lambda::LayerVersion", Arc::new(LayerVersion));
}

/// The `cfnresponse` module CloudFormation adds next to inline Python code.
const CFNRESPONSE_PY: &str = r#"import json
import urllib.request

SUCCESS = "SUCCESS"
FAILED = "FAILED"


def send(event, context, responseStatus, responseData, physicalResourceId=None, noEcho=False, reason=None):
    responseUrl = event['ResponseURL']
    body = {
        'Status': responseStatus,
        'Reason': reason or "See the details in CloudWatch Log Stream: {}".format(context.log_stream_name),
        'PhysicalResourceId': physicalResourceId or context.log_stream_name,
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'NoEcho': noEcho,
        'Data': responseData,
    }
    data = json.dumps(body).encode('utf-8')
    req = urllib.request.Request(responseUrl, data=data, method='PUT',
                                 headers={'content-type': '', 'content-length': str(len(data))})
    try:
        with urllib.request.urlopen(req) as response:
            print("Status code:", response.status)
    except Exception as e:
        print("send(..) failed executing http.request(..):", e)
"#;

/// The `cfn-response` module CloudFormation adds next to inline Node.js
/// code.
const CFN_RESPONSE_JS: &str = r#"exports.SUCCESS = "SUCCESS";
exports.FAILED = "FAILED";

exports.send = function (event, context, responseStatus, responseData, physicalResourceId, noEcho) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      Status: responseStatus,
      Reason: "See the details in CloudWatch Log Stream: " + context.logStreamName,
      PhysicalResourceId: physicalResourceId || context.logStreamName,
      StackId: event.StackId,
      RequestId: event.RequestId,
      LogicalResourceId: event.LogicalResourceId,
      NoEcho: noEcho || false,
      Data: responseData,
    });
    const url = new URL(event.ResponseURL);
    const mod = url.protocol === "https:" ? require("https") : require("http");
    const req = mod.request(
      { hostname: url.hostname, port: url.port, path: url.pathname + url.search, method: "PUT",
        headers: { "content-type": "", "content-length": Buffer.byteLength(body) } },
      (res) => { res.on("data", () => {}); res.on("end", () => { if (context.done) context.done(); resolve(); }); }
    );
    req.on("error", (e) => { console.log("send(..) failed executing https.request(..): " + e); if (context.done) context.done(); reject(e); });
    req.write(body);
    req.end();
  });
};
"#;

/// Package inline code as Lambda does: `index.<ext>` plus the response
/// helper module.
fn inline_zip(runtime: &str, source: &str) -> HResult<String> {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default().unix_permissions(0o644);
        let (file, helper) = if runtime.starts_with("python") {
            ("index.py", Some(("cfnresponse.py", CFNRESPONSE_PY)))
        } else if runtime.starts_with("nodejs") {
            ("index.js", Some(("cfn-response.js", CFN_RESPONSE_JS)))
        } else {
            return Err(HandlerError::invalid(format!("ZipFile can only be used with Node.js and Python runtimes, not {runtime}")));
        };
        let io = |e: std::io::Error| HandlerError::invalid(e.to_string());
        let zerr = |e: zip::result::ZipError| HandlerError::invalid(e.to_string());
        z.start_file(file, opts).map_err(zerr)?;
        z.write_all(source.as_bytes()).map_err(io)?;
        if let Some((name, body)) = helper {
            z.start_file(name, opts).map_err(zerr)?;
            z.write_all(body.as_bytes()).map_err(io)?;
        }
        z.finish().map_err(zerr)?;
    }
    Ok(base64::engine::general_purpose::STANDARD.encode(buf.into_inner()))
}

fn code(props: &Props) -> HResult<Value> {
    let c = props.get("Code").and_then(Value::as_object).cloned().unwrap_or_default();
    if let Some(src) = c.get("ZipFile") {
        let runtime = s(props, "Runtime").unwrap_or_default();
        return Ok(json!({"ZipFile": inline_zip(&runtime, &text(src))?}));
    }
    let mut out = Map::new();
    copy(&c, &mut out, &["S3Bucket", "S3Key", "S3ObjectVersion", "ImageUri"]);
    Ok(Value::Object(out))
}

const CONFIG: &[&str] = &[
    "Role",
    "Handler",
    "Runtime",
    "Description",
    "Timeout",
    "MemorySize",
    "Environment",
    "Layers",
    "DeadLetterConfig",
    "TracingConfig",
    "VpcConfig",
    "EphemeralStorage",
    "LoggingConfig",
    "KmsKeyArn",
    "ImageConfig",
    "FileSystemConfigs",
    "SnapStart",
];

fn config(props: &Props) -> Map<String, Value> {
    let mut out = Map::new();
    for k in CONFIG {
        if let Some(v) = props.get(*k).filter(|v| !v.is_null()) {
            let key = if *k == "KmsKeyArn" { "KMSKeyArn" } else { k };
            out.insert(key.into(), v.clone());
        }
    }
    numbers(&mut out, &["Timeout", "MemorySize"]);
    if let Some(Value::Object(e)) = out.get_mut("EphemeralStorage") {
        numbers(e, &["Size"]);
    }
    out
}

async fn wait_active(cx: &Cx<'_>, name: &str) -> HResult<()> {
    for _ in 0..600 {
        let out = cx.call("lambda", "GetFunctionConfiguration", json!({"FunctionName": name})).await?;
        let state = out["State"].as_str().unwrap_or("Active");
        let update = out["LastUpdateStatus"].as_str().unwrap_or("Successful");
        if state == "Failed" {
            return Err(HandlerError::handler("NotStabilized", format!("Lambda function {name} failed: {}", text(&out["StateReason"]))));
        }
        if state != "Pending" && update != "InProgress" {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Ok(())
}

struct Function;

#[async_trait::async_trait]
impl Provider for Function {
    fn create_only(&self) -> &'static [&'static str] {
        &["FunctionName", "PackageType"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["Code", "Role"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn", "SnapStartResponse", "SnapStartResponse.ApplyOn", "SnapStartResponse.OptimizationStatus"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "FunctionName").unwrap_or_else(|| cx.physical_name(64));
        let mut input = config(props);
        input.insert("FunctionName".into(), json!(name));
        input.insert("Code".into(), code(props)?);
        if let Some(p) = s(props, "PackageType") {
            input.insert("PackageType".into(), json!(p));
        }
        if let Some(a) = props.get("Architectures") {
            input.insert("Architectures".into(), a.clone());
        }
        let tags = cx.tag_map(props);
        if !tags.is_empty() {
            input.insert("Tags".into(), Value::Object(tags));
        }
        let out = cx.call("lambda", "CreateFunction", Value::Object(input)).await?;
        let arn = text(&out["FunctionArn"]);
        if let Some(c) = int(props, "ReservedConcurrentExecutions") {
            cx.call("lambda", "PutFunctionConcurrency", json!({"FunctionName": name, "ReservedConcurrentExecutions": c})).await?;
        }
        wait_active(cx, &name).await?;
        Ok(Created::new(&name).attr("Arn", arn))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "Code") || (changed(old, new, "Runtime") && new.get("Code").and_then(|c| c.get("ZipFile")).is_some()) {
            let mut input = code(new)?.as_object().cloned().unwrap_or_default();
            input.insert("FunctionName".into(), json!(name));
            if let Some(a) = new.get("Architectures") {
                input.insert("Architectures".into(), a.clone());
            }
            cx.call("lambda", "UpdateFunctionCode", Value::Object(input)).await?;
            wait_active(cx, name).await?;
        }
        if CONFIG.iter().any(|k| changed(old, new, k)) {
            let mut input = config(new);
            input.insert("FunctionName".into(), json!(name));
            for k in ["Description", "Environment", "Layers"] {
                if !new.contains_key(k) && old.contains_key(k) {
                    input.insert(
                        k.into(),
                        match k {
                            "Description" => json!(""),
                            "Environment" => json!({"Variables": {}}),
                            _ => json!([]),
                        },
                    );
                }
            }
            cx.call("lambda", "UpdateFunctionConfiguration", Value::Object(input)).await?;
            wait_active(cx, name).await?;
        }
        if changed(old, new, "ReservedConcurrentExecutions") {
            match int(new, "ReservedConcurrentExecutions") {
                Some(c) => cx.call("lambda", "PutFunctionConcurrency", json!({"FunctionName": name, "ReservedConcurrentExecutions": c})).await?,
                None => cx.call("lambda", "DeleteFunctionConcurrency", json!({"FunctionName": name})).await?,
            };
        }
        if changed(old, new, "Tags") {
            let arn = text(&attrs["Arn"]);
            let new_tags = cx.tag_map(new);
            let removed: Vec<String> = cx.tag_map(old).keys().filter(|k| !new_tags.contains_key(*k)).cloned().collect();
            if !removed.is_empty() {
                cx.call("lambda", "UntagResource", json!({"Resource": arn, "TagKeys": removed})).await?;
            }
            if !new_tags.is_empty() {
                cx.call("lambda", "TagResource", json!({"Resource": arn, "Tags": new_tags})).await?;
            }
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("lambda", "DeleteFunction", json!({"FunctionName": name})).await)
    }

    async fn read(&self, cx: &Cx<'_>, name: &str, props: &Props) -> Option<HResult<Props>> {
        Some(
            async {
                let out = cx.call("lambda", "GetFunctionConfiguration", json!({"FunctionName": name})).await?;
                let mut p = Props::new();
                for k in ["Handler", "Runtime", "Role", "Description", "Timeout", "MemorySize"] {
                    if props.contains_key(k) {
                        let v = out.get(k).cloned().unwrap_or(Value::Null);
                        let v = match (&props[k], &v) {
                            (Value::String(_), Value::Number(n)) => json!(n.to_string()),
                            _ => v,
                        };
                        p.insert(k.into(), v);
                    }
                }
                if props.contains_key("Environment") {
                    p.insert("Environment".into(), json!({"Variables": out["Environment"]["Variables"].clone()}));
                }
                Ok(p)
            }
            .await,
        )
    }
}

struct Permission;

#[async_trait::async_trait]
impl Provider for Permission {
    fn required(&self) -> &'static [&'static str] {
        &["Action", "FunctionName", "Principal"]
    }
    fn updatable(&self) -> bool {
        false
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let id = cx.physical_name(100);
        let mut input = Map::new();
        copy(
            props,
            &mut input,
            &["FunctionName", "Action", "Principal", "SourceArn", "SourceAccount", "EventSourceToken", "FunctionUrlAuthType", "PrincipalOrgID", "InvokedViaFunctionUrl"],
        );
        input.insert("StatementId".into(), json!(id));
        cx.call("lambda", "AddPermission", Value::Object(input)).await?;
        Ok(Created::new(id))
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("lambda", "RemovePermission", json!({"FunctionName": req(props, "FunctionName")?, "StatementId": id})).await)
    }
}

const ESM_FIELDS: &[&str] = &[
    "FunctionName",
    "BatchSize",
    "Enabled",
    "MaximumBatchingWindowInSeconds",
    "FilterCriteria",
    "MaximumRetryAttempts",
    "BisectBatchOnFunctionError",
    "DestinationConfig",
    "ParallelizationFactor",
    "FunctionResponseTypes",
    "ScalingConfig",
    "MaximumRecordAgeInSeconds",
    "TumblingWindowInSeconds",
];

fn esm_input(props: &Props) -> Map<String, Value> {
    let mut input = Map::new();
    copy(props, &mut input, ESM_FIELDS);
    numbers(&mut input, &["BatchSize", "MaximumBatchingWindowInSeconds", "MaximumRetryAttempts", "ParallelizationFactor", "MaximumRecordAgeInSeconds", "TumblingWindowInSeconds"]);
    bools(&mut input, &["Enabled", "BisectBatchOnFunctionError"]);
    if let Some(Value::Object(f)) = input.get_mut("FilterCriteria") {
        if let Some(Value::Array(filters)) = f.get_mut("Filters") {
            for x in filters.iter_mut() {
                if let Some(p @ Value::Object(_)) = x.get("Pattern").cloned() {
                    x["Pattern"] = json!(p.to_string());
                }
            }
        }
    }
    input
}

struct EventSourceMapping;

#[async_trait::async_trait]
impl Provider for EventSourceMapping {
    fn create_only(&self) -> &'static [&'static str] {
        &["EventSourceArn", "StartingPosition", "StartingPositionTimestamp", "SelfManagedEventSource"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["FunctionName"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Id", "EventSourceMappingArn"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = esm_input(props);
        copy(props, &mut input, &["EventSourceArn", "StartingPosition", "StartingPositionTimestamp"]);
        let out = cx.call("lambda", "CreateEventSourceMapping", Value::Object(input)).await?;
        let id = text(&out["UUID"]);
        Ok(Created::new(&id).attr("Id", id.clone()).attr("EventSourceMappingArn", out["EventSourceMappingArn"].clone()))
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let mut input = esm_input(new);
        input.insert("UUID".into(), json!(id));
        cx.call("lambda", "UpdateEventSourceMapping", Value::Object(input)).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("lambda", "DeleteEventSourceMapping", json!({"UUID": id})).await)
    }
}

struct Version;

#[async_trait::async_trait]
impl Provider for Version {
    fn required(&self) -> &'static [&'static str] {
        &["FunctionName"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Version", "FunctionArn"]
    }
    fn updatable(&self) -> bool {
        false
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = Map::new();
        copy(props, &mut input, &["FunctionName", "Description", "CodeSha256"]);
        let out = cx.call("lambda", "PublishVersion", Value::Object(input)).await?;
        let arn = text(&out["FunctionArn"]);
        let base = arn.rsplit_once(':').map(|(b, _)| b.to_string()).unwrap_or_default();
        Ok(Created::new(&arn).attr("Version", out["Version"].clone()).attr("FunctionArn", base))
    }

    async fn delete(&self, cx: &Cx<'_>, arn: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        let Some((function, version)) = arn.rsplit_once(':') else { return Ok(()) };
        gone_ok(cx.call("lambda", "DeleteFunction", json!({"FunctionName": function, "Qualifier": version})).await)
    }
}

struct Alias;

#[async_trait::async_trait]
impl Provider for Alias {
    fn create_only(&self) -> &'static [&'static str] {
        &["FunctionName", "Name"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["FunctionName", "FunctionVersion", "Name"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["AliasArn"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = Map::new();
        copy(props, &mut input, &["FunctionName", "Name", "FunctionVersion", "Description", "RoutingConfig"]);
        let out = cx.call("lambda", "CreateAlias", Value::Object(input)).await?;
        let arn = text(&out["AliasArn"]);
        Ok(Created::new(&arn).attr("AliasArn", arn.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, _arn: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let mut input = Map::new();
        copy(new, &mut input, &["FunctionName", "Name", "FunctionVersion", "Description", "RoutingConfig"]);
        cx.call("lambda", "UpdateAlias", Value::Object(input)).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, _arn: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("lambda", "DeleteAlias", json!({"FunctionName": req(props, "FunctionName")?, "Name": req(props, "Name")?})).await)
    }
}

struct Url;

#[async_trait::async_trait]
impl Provider for Url {
    fn create_only(&self) -> &'static [&'static str] {
        &["TargetFunctionArn", "Qualifier"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["AuthType", "TargetFunctionArn"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["FunctionArn", "FunctionUrl"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = Map::new();
        input.insert("FunctionName".into(), json!(req(props, "TargetFunctionArn")?));
        copy(props, &mut input, &["Qualifier", "AuthType", "Cors", "InvokeMode"]);
        let out = cx.call("lambda", "CreateFunctionUrlConfig", Value::Object(input)).await?;
        let arn = text(&out["FunctionArn"]);
        Ok(Created::new(&arn).attr("FunctionArn", arn.clone()).attr("FunctionUrl", out["FunctionUrl"].clone()))
    }

    async fn update(&self, cx: &Cx<'_>, _arn: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let mut input = Map::new();
        input.insert("FunctionName".into(), json!(req(new, "TargetFunctionArn")?));
        copy(new, &mut input, &["Qualifier", "AuthType", "Cors", "InvokeMode"]);
        cx.call("lambda", "UpdateFunctionUrlConfig", Value::Object(input)).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, _arn: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let mut input = Map::new();
        input.insert("FunctionName".into(), json!(req(props, "TargetFunctionArn")?));
        copy(props, &mut input, &["Qualifier"]);
        gone_ok(cx.call("lambda", "DeleteFunctionUrlConfig", Value::Object(input)).await)
    }
}

struct LayerVersion;

#[async_trait::async_trait]
impl Provider for LayerVersion {
    fn required(&self) -> &'static [&'static str] {
        &["Content"]
    }
    fn updatable(&self) -> bool {
        false
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["LayerVersionArn"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "LayerName").unwrap_or_else(|| cx.physical_name(64));
        let mut input = Map::new();
        input.insert("LayerName".into(), json!(name));
        copy(props, &mut input, &["Description", "Content", "CompatibleRuntimes", "LicenseInfo", "CompatibleArchitectures"]);
        let out = cx.call("lambda", "PublishLayerVersion", Value::Object(input)).await?;
        let arn = text(&out["LayerVersionArn"]);
        Ok(Created::new(&arn).attr("LayerVersionArn", arn.clone()))
    }

    async fn delete(&self, cx: &Cx<'_>, arn: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        let parts: Vec<&str> = arn.split(':').collect();
        if parts.len() < 8 {
            return Ok(());
        }
        let version: i64 = parts[7].parse().unwrap_or(0);
        gone_ok(cx.call("lambda", "DeleteLayerVersion", json!({"LayerName": parts[..7].join(":"), "VersionNumber": version})).await)
    }
}
