//! Lambda durable functions, capacity providers and resource policies
//! through the official Rust SDK. The durable function speaks the durable
//! execution protocol the AWS SDKs implement: it replays the operations
//! Lambda hands it and checkpoints new ones (a step, a wait, a callback)
//! with SigV4-signed `CheckpointDurableExecution` calls.

use std::time::Duration;

use aws_sdk_lambda::primitives::Blob;
use aws_sdk_lambda::types::{
    CapacityProviderConfig, CapacityProviderPermissionsConfig, CapacityProviderVpcConfig, DurableConfig, EventType,
    ExecutionStatus, FunctionCode, FunctionScalingConfig, InvocationType, LambdaManagedInstancesCapacityProviderConfig,
    Runtime,
};
use mws_e2e::Mws;

use crate::lambda::zip;

const TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

/// A durable order workflow: charge (a step), wait a second, then wait for
/// an approval callback. `{"quick": true}` finishes at once.
const WORKFLOW: &str = r#"
import datetime, hashlib, hmac, json, os, urllib.parse, urllib.request

def _call(method, path, body):
    endpoint = os.environ["AWS_ENDPOINT_URL"].rstrip("/")
    host = urllib.parse.urlparse(endpoint).netloc
    region = os.environ["AWS_REGION"]
    amz = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    day = amz[:8]
    data = json.dumps(body).encode()
    headers = {"content-type": "application/json", "host": host, "x-amz-date": amz}
    if os.environ.get("AWS_SESSION_TOKEN"):
        headers["x-amz-security-token"] = os.environ["AWS_SESSION_TOKEN"]
    names = sorted(headers)
    canonical_uri = "/".join(urllib.parse.quote(s, safe="-_.~") for s in path.split("/"))
    canonical = "\n".join([method, canonical_uri, "", "".join(f"{k}:{headers[k]}\n" for k in names),
                           ";".join(names), hashlib.sha256(data).hexdigest()])
    scope = f"{day}/{region}/lambda/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = ("AWS4" + os.environ["AWS_SECRET_ACCESS_KEY"]).encode()
    for part in (day, region, "lambda", "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = (f"AWS4-HMAC-SHA256 Credential={os.environ['AWS_ACCESS_KEY_ID']}/{scope}, "
                                f"SignedHeaders={';'.join(names)}, Signature={signature}")
    req = urllib.request.Request(endpoint + path, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read() or b"{}")

class Execution:
    def __init__(self, event):
        self.arn = event["DurableExecutionArn"]
        self.token = event["CheckpointToken"]
        self.ops = {o["Id"]: o for o in event["InitialExecutionState"]["Operations"]}

    def checkpoint(self, update):
        path = "/2025-12-01/durable-executions/" + urllib.parse.quote(self.arn, safe="") + "/checkpoint"
        out = _call("POST", path, {"CheckpointToken": self.token, "Updates": [update]})
        self.token = out.get("CheckpointToken", self.token)
        for o in out["NewExecutionState"]["Operations"]:
            self.ops[o["Id"]] = o

def handler(event, context):
    ex = Execution(event)
    start = next(o for o in ex.ops.values() if o["Type"] == "EXECUTION")
    order = json.loads(start["ExecutionDetails"]["InputPayload"])
    if order.get("quick"):
        return {"Status": "SUCCEEDED", "Result": json.dumps({"quick": order["id"]})}
    if "charge" not in ex.ops:
        ex.checkpoint({"Id": "charge", "Type": "STEP", "Action": "START", "Name": "charge"})
        ex.checkpoint({"Id": "charge", "Type": "STEP", "Action": "SUCCEED",
                       "Payload": json.dumps(order["amount"] * 2)})
    charged = json.loads(ex.ops["charge"]["StepDetails"]["Result"])
    if "cool-off" not in ex.ops:
        ex.checkpoint({"Id": "cool-off", "Type": "WAIT", "Action": "START", "WaitOptions": {"WaitSeconds": 1}})
    if ex.ops["cool-off"]["Status"] != "SUCCEEDED":
        return {"Status": "PENDING"}
    if "approval" not in ex.ops:
        ex.checkpoint({"Id": "approval", "Type": "CALLBACK", "Action": "START", "Name": "approval",
                       "CallbackOptions": {"TimeoutSeconds": 300}})
    approval = ex.ops["approval"]
    if approval["Status"] == "STARTED":
        return {"Status": "PENDING"}
    if approval["Status"] != "SUCCEEDED":
        return {"Status": "FAILED", "Error": {"ErrorType": "Rejected", "ErrorMessage": "not approved"}}
    result = {"charged": charged, "approval": json.loads(approval["CallbackDetails"]["Result"])}
    return {"Status": "SUCCEEDED", "Result": json.dumps(result)}
"#;

async fn durable_function(cfg: &aws_config::SdkConfig, name: &str) -> String {
    let iam = aws_sdk_iam::Client::new(cfg);
    let lambda = aws_sdk_lambda::Client::new(cfg);
    let role = iam.create_role().role_name(name).assume_role_policy_document(TRUST).send().await.unwrap();
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["lambda:CheckpointDurableExecution","lambda:GetDurableExecutionState"],"Resource":"*"}]}"#;
    iam.put_role_policy().role_name(name).policy_name("durable").policy_document(policy).send().await.unwrap();
    let f = lambda
        .create_function()
        .function_name(name)
        .runtime(Runtime::Python312)
        .handler("app.handler")
        .role(role.role().unwrap().arn())
        .durable_config(DurableConfig::builder().execution_timeout(600).retention_period_in_days(7).build())
        .code(FunctionCode::builder().zip_file(Blob::new(zip(&[("app.py", WORKFLOW)]))).build())
        .send()
        .await
        .unwrap();
    mws_e2e::function_active(&lambda, name).await;
    f.function_arn().unwrap().to_string()
}

async fn history_has(lambda: &aws_sdk_lambda::Client, arn: &str, kind: EventType) -> Vec<aws_sdk_lambda::types::Event> {
    for _ in 0..300 {
        let h = lambda.get_durable_execution_history().durable_execution_arn(arn).send().await.unwrap();
        if h.events().iter().any(|e| e.event_type() == Some(&kind)) {
            return h.events().to_vec();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no {kind:?} event in the history of {arn}");
}

async fn wait_status(lambda: &aws_sdk_lambda::Client, arn: &str, want: ExecutionStatus) {
    let mut last = None;
    for _ in 0..300 {
        let e = lambda.get_durable_execution().durable_execution_arn(arn).send().await.unwrap();
        if e.status() == &want {
            return;
        }
        last = Some(e.status().clone());
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{arn} stayed {last:?}");
}

#[tokio::test]
async fn durable_executions_checkpoint_wait_and_resume_on_callbacks() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    durable_function(&cfg, "orders").await;

    let started = lambda
        .invoke()
        .function_name("orders")
        .invocation_type(InvocationType::Event)
        .durable_execution_name("order-1")
        .payload(Blob::new(br#"{"amount":21}"#.to_vec()))
        .send()
        .await
        .unwrap();
    assert_eq!(started.status_code(), 202);
    let arn = started.durable_execution_arn().unwrap().to_string();
    assert!(arn.contains(":function:orders:$LATEST/durable-execution/order-1/"), "{arn}");

    // The same name and input is the same execution; another input is not.
    let again = lambda
        .invoke()
        .function_name("orders")
        .invocation_type(InvocationType::Event)
        .durable_execution_name("order-1")
        .payload(Blob::new(br#"{"amount":21}"#.to_vec()))
        .send()
        .await
        .unwrap();
    assert_eq!(again.durable_execution_arn(), Some(arn.as_str()));
    let clash = lambda
        .invoke()
        .function_name("orders")
        .invocation_type(InvocationType::Event)
        .durable_execution_name("order-1")
        .payload(Blob::new(br#"{"amount":5}"#.to_vec()))
        .send()
        .await
        .unwrap_err();
    assert!(clash.as_service_error().unwrap().is_durable_execution_already_started_exception());

    // The step runs, the wait ends a second later, then the callback waits.
    let events = history_has(&lambda, &arn, EventType::CallbackStarted).await;
    let kinds: Vec<&EventType> = events.iter().filter_map(|e| e.event_type()).collect();
    for k in [EventType::ExecutionStarted, EventType::StepStarted, EventType::StepSucceeded, EventType::WaitStarted] {
        assert!(kinds.contains(&&k), "{k:?} missing from {kinds:?}");
    }
    assert!(kinds.contains(&&EventType::WaitSucceeded));
    let callback = events.iter().find_map(|e| e.callback_started_details()).unwrap().callback_id().to_string();
    let running = lambda.get_durable_execution().durable_execution_arn(&arn).send().await.unwrap();
    assert_eq!(running.status(), &ExecutionStatus::Running);

    lambda
        .send_durable_execution_callback_success()
        .callback_id(&callback)
        .result(Blob::new(br#""approved""#.to_vec()))
        .send()
        .await
        .unwrap();
    wait_status(&lambda, &arn, ExecutionStatus::Succeeded).await;
    let done =
        lambda.get_durable_execution().durable_execution_arn(&arn).include_execution_data(true).send().await.unwrap();
    let result: serde_json::Value = serde_json::from_str(done.result().unwrap()).unwrap();
    assert_eq!(result, serde_json::json!({"charged": 42, "approval": "approved"}));
    assert_eq!(done.input_payload(), Some(r#"{"amount":21}"#));
    assert!(done.end_timestamp().is_some());
    // A completed callback cannot complete again.
    let late = lambda
        .send_durable_execution_callback_success()
        .callback_id(&callback)
        .result(Blob::new(b"1".to_vec()))
        .send()
        .await
        .unwrap_err();
    assert!(late.as_service_error().unwrap().is_callback_timeout_exception());
    history_has(&lambda, &arn, EventType::ExecutionSucceeded).await;

    let listed = lambda.list_durable_executions_by_function().function_name("orders").send().await.unwrap();
    assert_eq!(listed.durable_executions().len(), 1);
    assert_eq!(listed.durable_executions()[0].durable_execution_name(), "order-1");
}

#[tokio::test]
async fn synchronous_durable_invocations_answer_the_result_and_executions_stop() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    durable_function(&cfg, "quick").await;

    let out = lambda
        .invoke()
        .function_name("quick")
        .payload(Blob::new(br#"{"quick":true,"id":"q-1"}"#.to_vec()))
        .send()
        .await
        .unwrap();
    assert_eq!(out.status_code(), 200);
    assert!(out.durable_execution_arn().is_some());
    assert_eq!(out.payload().unwrap().as_ref(), br#"{"quick": "q-1"}"#);

    // An execution waiting for its callback can be stopped.
    let waiting = lambda
        .invoke()
        .function_name("quick")
        .invocation_type(InvocationType::Event)
        .payload(Blob::new(br#"{"amount":1}"#.to_vec()))
        .send()
        .await
        .unwrap();
    let arn = waiting.durable_execution_arn().unwrap().to_string();
    history_has(&lambda, &arn, EventType::CallbackStarted).await;
    lambda.stop_durable_execution().durable_execution_arn(&arn).send().await.unwrap();
    wait_status(&lambda, &arn, ExecutionStatus::Stopped).await;
    history_has(&lambda, &arn, EventType::ExecutionStopped).await;
    let stopped = lambda
        .list_durable_executions_by_function()
        .function_name("quick")
        .statuses(ExecutionStatus::Stopped)
        .send()
        .await
        .unwrap();
    assert_eq!(stopped.durable_executions().len(), 1);
}

#[tokio::test]
async fn capacity_providers_scaling_configs_and_resource_policies() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let subnets = ec2.describe_subnets().send().await.unwrap();
    let subnet = subnets.subnets()[0].subnet_id().unwrap().to_string();
    let groups = ec2.describe_security_groups().send().await.unwrap();
    let group = groups.security_groups()[0].group_id().unwrap().to_string();
    let operator = iam
        .create_role()
        .role_name("operator")
        .assume_role_policy_document(TRUST)
        .send()
        .await
        .unwrap()
        .role()
        .unwrap()
        .arn()
        .to_string();

    let created = lambda
        .create_capacity_provider()
        .capacity_provider_name("fleet")
        .vpc_config(
            CapacityProviderVpcConfig::builder().subnet_ids(&subnet).security_group_ids(&group).build().unwrap(),
        )
        .permissions_config(
            CapacityProviderPermissionsConfig::builder()
                .capacity_provider_operator_role_arn(&operator)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let provider = created.capacity_provider().unwrap();
    let provider_arn = provider.capacity_provider_arn().to_string();
    assert!(provider_arn.ends_with(":capacity-provider:fleet"));
    let got = lambda.get_capacity_provider().capacity_provider_name("fleet").send().await.unwrap();
    assert_eq!(got.capacity_provider().unwrap().state().as_str(), "Active");
    assert_eq!(lambda.list_capacity_providers().send().await.unwrap().capacity_providers().len(), 1);

    let role = iam.create_role().role_name("fn").assume_role_policy_document(TRUST).send().await.unwrap();
    let f = lambda
        .create_function()
        .function_name("managed")
        .runtime(Runtime::Python312)
        .handler("app.handler")
        .role(role.role().unwrap().arn())
        .capacity_provider_config(
            CapacityProviderConfig::builder()
                .lambda_managed_instances_capacity_provider_config(
                    LambdaManagedInstancesCapacityProviderConfig::builder()
                        .capacity_provider_arn(&provider_arn)
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .code(
            FunctionCode::builder()
                .zip_file(Blob::new(zip(&[("app.py", "def handler(e, c):\n    return 'ok'\n")])))
                .build(),
        )
        .send()
        .await
        .unwrap();
    mws_e2e::function_active(&lambda, "managed").await;
    let function_arn = f.function_arn().unwrap().to_string();
    let versions =
        lambda.list_function_versions_by_capacity_provider().capacity_provider_name("fleet").send().await.unwrap();
    assert_eq!(versions.function_versions().len(), 1);
    let busy = lambda.delete_capacity_provider().capacity_provider_name("fleet").send().await.unwrap_err();
    assert!(busy.as_service_error().unwrap().is_resource_conflict_exception());

    lambda.publish_version().function_name("managed").send().await.unwrap();
    lambda
        .put_function_scaling_config()
        .function_name("managed")
        .qualifier("1")
        .function_scaling_config(
            FunctionScalingConfig::builder().min_execution_environments(1).max_execution_environments(4).build(),
        )
        .send()
        .await
        .unwrap();
    let scaling = lambda
        .get_function_scaling_config()
        .function_name("managed")
        .qualifier("$LATEST.PUBLISHED")
        .send()
        .await
        .unwrap();
    assert_eq!(scaling.requested_function_scaling_config().unwrap().max_execution_environments(), Some(4));

    // Resource policies are the function's policy, as GetPolicy sees it.
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Sid":"events","Effect":"Allow","Principal":{{"Service":"events.amazonaws.com"}},"Action":"lambda:InvokeFunction","Resource":"{function_arn}"}}]}}"#
    );
    let put = lambda.put_resource_policy().resource_arn(&function_arn).policy(&policy).send().await.unwrap();
    assert!(put.revision_id().is_some());
    let got = lambda.get_resource_policy().resource_arn(&function_arn).send().await.unwrap();
    assert!(got.policy().unwrap().contains("events.amazonaws.com"));
    let classic = lambda.get_policy().function_name("managed").send().await.unwrap();
    assert!(classic.policy().unwrap().contains(r#""Sid":"events""#));
    lambda.delete_resource_policy().resource_arn(&function_arn).send().await.unwrap();
    assert!(lambda.get_policy().function_name("managed").send().await.is_err());
}
