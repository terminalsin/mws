//! GuardDuty findings in the AWS Security Finding Format, as GuardDuty
//! sends them to Security Hub (product `aws/guardduty`).

use serde_json::{json, Map, Value};

use crate::findings::event_detail;
use crate::generated::types;

/// Security Hub's label for a GuardDuty severity.
fn label(severity: f64) -> &'static str {
    match severity {
        s if s >= 9.0 => "CRITICAL",
        s if s >= 7.0 => "HIGH",
        s if s >= 4.0 => "MEDIUM",
        _ => "LOW",
    }
}

/// The ASFF `Types` entry for a finding type (`ThreatPurpose:Resource/Name`).
fn asff_type(ty: &str) -> String {
    let purpose = ty.split(':').next().unwrap_or_default();
    let namespace = match purpose {
        "Backdoor" | "Trojan" => "TTPs/Command and Control",
        "CryptoCurrency" | "Impact" => "Effects/Resource Consumption",
        "Recon" | "Discovery" => "TTPs/Discovery",
        "UnauthorizedAccess" | "InitialAccess" => "TTPs/Initial Access",
        "CredentialAccess" => "TTPs/Credential Access",
        "Exfiltration" => "Effects/Data Exfiltration",
        "Persistence" => "TTPs/Persistence",
        "PrivilegeEscalation" => "TTPs/Privilege Escalation",
        "DefenseEvasion" | "Stealth" => "TTPs/Defense Evasion",
        "Execution" => "TTPs/Execution",
        "Policy" | "PenTest" => "Software and Configuration Checks/AWS Security Best Practices",
        _ => "Unusual Behaviors",
    };
    format!("{namespace}/{}", ty.replace('/', "-"))
}

/// The ASFF resources of a finding's `resource`.
fn resources(f: &types::Finding, detail: &Value) -> Vec<Value> {
    let partition = f.partition.as_deref().unwrap_or("aws");
    let (region, account) = (&f.region, &f.account_id);
    let res = &detail["resource"];
    let one = |ty: &str, id: String| json!({"Type": ty, "Id": id, "Partition": partition, "Region": region});
    let s = |v: &Value| v.as_str().map(str::to_string);
    let mut out = Vec::new();
    if let Some(id) = s(&res["instanceDetails"]["instanceId"]) {
        out.push(one("AwsEc2Instance", format!("arn:{partition}:ec2:{region}:{account}:instance/{id}")));
    }
    if let Some(id) = s(&res["accessKeyDetails"]["accessKeyId"]) {
        out.push(one("AwsIamAccessKey", id));
    }
    for b in res["s3BucketDetails"].as_array().into_iter().flatten() {
        if let Some(arn) = s(&b["arn"]).or_else(|| s(&b["name"]).map(|n| format!("arn:{partition}:s3:::{n}"))) {
            out.push(one("AwsS3Bucket", arn));
        }
    }
    if let Some(arn) = s(&res["eksClusterDetails"]["arn"]) {
        out.push(one("AwsEksCluster", arn));
    }
    if let Some(arn) = s(&res["lambdaDetails"]["functionArn"]) {
        out.push(one("AwsLambdaFunction", arn));
    }
    if let Some(arn) = s(&res["rdsDbInstanceDetails"]["dbInstanceArn"]) {
        out.push(one("AwsRdsDbInstance", arn));
    }
    if let Some(arn) = s(&res["ecsClusterDetails"]["arn"]) {
        out.push(one("AwsEcsCluster", arn));
    }
    if out.is_empty() {
        out.push(one("Other", f.arn.clone()));
    }
    out
}

/// `f` as an ASFF finding from `aws/guardduty`.
pub fn to_asff(f: &types::Finding) -> Value {
    let detail = event_detail(f);
    let partition = f.partition.as_deref().unwrap_or("aws");
    let detector_id = detail["service"]["detectorId"].as_str().unwrap_or_default().to_string();
    let service = &detail["service"];
    let archived = service["archived"].as_bool().unwrap_or(false);
    let mut fields = Map::new();
    let mut field = |k: &str, v: &Value| {
        let text = match v {
            Value::String(s) => s.clone(),
            Value::Null => return,
            other => other.to_string(),
        };
        fields.insert(format!("aws/guardduty/service/{k}"), Value::String(text));
    };
    for k in ["archived", "count", "detectorId", "resourceRole", "eventFirstSeen", "eventLastSeen", "featureName"] {
        field(k, &service[k]);
    }
    field("action/actionType", &service["action"]["actionType"]);
    if service["additionalInfo"]["sample"] == true {
        fields.insert("aws/guardduty/service/additionalInfo/sample".into(), "true".into());
    }
    fields.insert("aws/guardduty/finding/type".into(), Value::String(f.r#type.clone()));
    let product_arn = format!("arn:{partition}:securityhub:{}::product/aws/guardduty", f.region);
    let first = service["eventFirstSeen"].as_str().unwrap_or(&f.created_at).to_string();
    let last = service["eventLastSeen"].as_str().unwrap_or(&f.updated_at).to_string();
    json!({
        "SchemaVersion": "2018-10-08",
        "Id": f.arn,
        "ProductArn": product_arn,
        "ProductName": "GuardDuty",
        "CompanyName": "Amazon",
        "Region": f.region,
        "GeneratorId": format!("arn:{partition}:guardduty:{}:{}:detector/{detector_id}", f.region, f.account_id),
        "AwsAccountId": f.account_id,
        "Types": [asff_type(&f.r#type)],
        "FirstObservedAt": first,
        "LastObservedAt": last,
        "CreatedAt": f.created_at,
        "UpdatedAt": f.updated_at,
        "Severity": {"Label": label(f.severity), "Original": format!("{}", f.severity), "Product": f.severity},
        "Title": f.title.clone().unwrap_or_default(),
        "Description": f.description.clone().unwrap_or_default(),
        "SourceUrl": format!(
            "https://{}.console.aws.amazon.com/guardduty/home?region={}#/findings?macros=current&fId={}",
            f.region, f.region, f.id
        ),
        "ProductFields": fields,
        "Resources": resources(f, &detail),
        "RecordState": if archived { "ARCHIVED" } else { "ACTIVE" },
        "Workflow": {"Status": "NEW"},
    })
}
