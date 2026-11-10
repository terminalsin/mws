//! S3 resource types.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use super::{boolean, changed, document, gone_ok, req, s, text, Created, Cx, HResult, Props, Provider};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::S3::Bucket", Arc::new(Bucket));
    m.insert("AWS::S3::BucketPolicy", Arc::new(BucketPolicy));
}

fn obj(v: Option<&Value>) -> Map<String, Value> {
    v.and_then(Value::as_object).cloned().unwrap_or_default()
}

fn arr(v: Option<&Value>) -> Vec<Value> {
    v.and_then(Value::as_array).cloned().unwrap_or_default()
}

fn num(v: &Value) -> Value {
    match v {
        Value::String(s) => s.parse::<i64>().map(Value::from).unwrap_or_else(|_| v.clone()),
        other => other.clone(),
    }
}

fn flag(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::Bool(s.eq_ignore_ascii_case("true")),
        other => other.clone(),
    }
}

fn lifecycle_rule(r: &Value) -> Value {
    let r = obj(Some(r));
    let mut out = Map::new();
    if let Some(id) = r.get("Id") {
        out.insert("ID".into(), id.clone());
    }
    out.insert("Status".into(), r.get("Status").cloned().unwrap_or(json!("Enabled")));
    let prefix = r.get("Prefix").map(text).unwrap_or_default();
    let tags = arr(r.get("TagFilters"));
    let gt = r.get("ObjectSizeGreaterThan").map(num);
    let lt = r.get("ObjectSizeLessThan").map(num);
    if tags.is_empty() && gt.is_none() && lt.is_none() {
        out.insert("Filter".into(), json!({"Prefix": prefix}));
    } else {
        let mut and = Map::new();
        if !prefix.is_empty() {
            and.insert("Prefix".into(), json!(prefix));
        }
        if !tags.is_empty() {
            and.insert("Tags".into(), json!(tags));
        }
        if let Some(g) = gt {
            and.insert("ObjectSizeGreaterThan".into(), g);
        }
        if let Some(l) = lt {
            and.insert("ObjectSizeLessThan".into(), l);
        }
        out.insert("Filter".into(), json!({"And": and}));
    }
    let mut exp = Map::new();
    if let Some(d) = r.get("ExpirationInDays") {
        exp.insert("Days".into(), num(d));
    }
    if let Some(d) = r.get("ExpirationDate") {
        exp.insert("Date".into(), d.clone());
    }
    if let Some(d) = r.get("ExpiredObjectDeleteMarker") {
        exp.insert("ExpiredObjectDeleteMarker".into(), flag(d));
    }
    if !exp.is_empty() {
        out.insert("Expiration".into(), Value::Object(exp));
    }
    if let Some(d) = r.get("NoncurrentVersionExpirationInDays") {
        out.insert("NoncurrentVersionExpiration".into(), json!({"NoncurrentDays": num(d)}));
    }
    if let Some(n) = r.get("NoncurrentVersionExpiration") {
        let n = obj(Some(n));
        let mut m = Map::new();
        if let Some(d) = n.get("NoncurrentDays") {
            m.insert("NoncurrentDays".into(), num(d));
        }
        if let Some(d) = n.get("NewerNoncurrentVersions") {
            m.insert("NewerNoncurrentVersions".into(), num(d));
        }
        out.insert("NoncurrentVersionExpiration".into(), Value::Object(m));
    }
    if let Some(a) = r.get("AbortIncompleteMultipartUpload") {
        let d = a.get("DaysAfterInitiation").map(num).unwrap_or(json!(7));
        out.insert("AbortIncompleteMultipartUpload".into(), json!({"DaysAfterInitiation": d}));
    }
    let mut transitions: Vec<Value> = arr(r.get("Transitions"));
    if let Some(t) = r.get("Transition") {
        transitions.push(t.clone());
    }
    if !transitions.is_empty() {
        let t: Vec<Value> = transitions
            .iter()
            .map(|t| {
                let mut m = Map::new();
                m.insert("StorageClass".into(), t.get("StorageClass").cloned().unwrap_or_default());
                if let Some(d) = t.get("TransitionInDays") {
                    m.insert("Days".into(), num(d));
                }
                if let Some(d) = t.get("TransitionDate") {
                    m.insert("Date".into(), d.clone());
                }
                Value::Object(m)
            })
            .collect();
        out.insert("Transitions".into(), json!(t));
    }
    let mut nvt: Vec<Value> = arr(r.get("NoncurrentVersionTransitions"));
    if let Some(t) = r.get("NoncurrentVersionTransition") {
        nvt.push(t.clone());
    }
    if !nvt.is_empty() {
        let t: Vec<Value> = nvt
            .iter()
            .map(|t| {
                let mut m = Map::new();
                m.insert("StorageClass".into(), t.get("StorageClass").cloned().unwrap_or_default());
                if let Some(d) = t.get("TransitionInDays") {
                    m.insert("NoncurrentDays".into(), num(d));
                }
                Value::Object(m)
            })
            .collect();
        out.insert("NoncurrentVersionTransitions".into(), json!(t));
    }
    Value::Object(out)
}

fn notification(n: &Value) -> Value {
    let filter = |c: &Value| -> Option<Value> {
        let rules = c.get("Filter")?.get("S3Key")?.get("Rules")?.clone();
        Some(json!({"Key": {"FilterRules": rules}}))
    };
    let conv = |list: Vec<Value>, target: &str, api: &str| -> Vec<Value> {
        list.iter()
            .map(|c| {
                let mut m = Map::new();
                m.insert(api.into(), c.get(target).cloned().unwrap_or_default());
                m.insert("Events".into(), json!([c.get("Event").cloned().unwrap_or_default()]));
                if let Some(f) = filter(c) {
                    m.insert("Filter".into(), f);
                }
                Value::Object(m)
            })
            .collect()
    };
    let mut out = Map::new();
    let l = conv(arr(n.get("LambdaConfigurations")), "Function", "LambdaFunctionArn");
    if !l.is_empty() {
        out.insert("LambdaFunctionConfigurations".into(), json!(l));
    }
    let q = conv(arr(n.get("QueueConfigurations")), "Queue", "QueueArn");
    if !q.is_empty() {
        out.insert("QueueConfigurations".into(), json!(q));
    }
    let t = conv(arr(n.get("TopicConfigurations")), "Topic", "TopicArn");
    if !t.is_empty() {
        out.insert("TopicConfigurations".into(), json!(t));
    }
    if n.get("EventBridgeConfiguration").and_then(|e| e.get("EventBridgeEnabled")).map(flag) == Some(json!(true)) {
        out.insert("EventBridgeConfiguration".into(), json!({}));
    }
    Value::Object(out)
}

struct Bucket;

impl Bucket {
    /// Apply a sub-configuration, or remove it when the property is gone.
    async fn apply(&self, cx: &Cx<'_>, bucket: &str, props: &Props, old: Option<&Props>) -> HResult<()> {
        let want = |k: &str| {
            old.is_none_or(|o| changed(o, props, k))
                && (props.contains_key(k) || old.is_some_and(|o| o.contains_key(k)))
        };
        if want("VersioningConfiguration") {
            let status = props.get("VersioningConfiguration").and_then(|v| v.get("Status")).map(text);
            let status = status.unwrap_or_else(|| "Suspended".into());
            cx.call(
                "s3",
                "PutBucketVersioning",
                json!({"Bucket": bucket, "VersioningConfiguration": {"Status": status}}),
            )
            .await?;
        }
        if want("BucketEncryption") {
            match props.get("BucketEncryption") {
                Some(e) => {
                    let rules: Vec<Value> = arr(e.get("ServerSideEncryptionConfiguration"))
                        .iter()
                        .map(|r| {
                            let mut m = Map::new();
                            if let Some(d) = r.get("ServerSideEncryptionByDefault") {
                                m.insert("ApplyServerSideEncryptionByDefault".into(), d.clone());
                            }
                            if let Some(b) = r.get("BucketKeyEnabled") {
                                m.insert("BucketKeyEnabled".into(), flag(b));
                            }
                            Value::Object(m)
                        })
                        .collect();
                    cx.call(
                        "s3",
                        "PutBucketEncryption",
                        json!({"Bucket": bucket, "ServerSideEncryptionConfiguration": {"Rules": rules}}),
                    )
                    .await?;
                }
                None => {
                    gone_ok(cx.call("s3", "DeleteBucketEncryption", json!({"Bucket": bucket})).await)?;
                }
            }
        }
        if want("PublicAccessBlockConfiguration") {
            match props.get("PublicAccessBlockConfiguration") {
                Some(p) => {
                    let mut m = Map::new();
                    for k in ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"] {
                        m.insert(k.into(), p.get(k).map(flag).unwrap_or(json!(false)));
                    }
                    cx.call(
                        "s3",
                        "PutPublicAccessBlock",
                        json!({"Bucket": bucket, "PublicAccessBlockConfiguration": m}),
                    )
                    .await?;
                }
                None => gone_ok(cx.call("s3", "DeletePublicAccessBlock", json!({"Bucket": bucket})).await)?,
            }
        }
        if want("CorsConfiguration") {
            match props.get("CorsConfiguration") {
                Some(c) => {
                    let rules: Vec<Value> = arr(c.get("CorsRules"))
                        .iter()
                        .map(|r| {
                            let mut m = Map::new();
                            for (from, to) in [
                                ("AllowedHeaders", "AllowedHeaders"),
                                ("AllowedMethods", "AllowedMethods"),
                                ("AllowedOrigins", "AllowedOrigins"),
                                ("ExposedHeaders", "ExposeHeaders"),
                                ("Id", "ID"),
                            ] {
                                if let Some(v) = r.get(from) {
                                    m.insert(to.into(), v.clone());
                                }
                            }
                            if let Some(v) = r.get("MaxAge") {
                                m.insert("MaxAgeSeconds".into(), num(v));
                            }
                            Value::Object(m)
                        })
                        .collect();
                    cx.call(
                        "s3",
                        "PutBucketCors",
                        json!({"Bucket": bucket, "CORSConfiguration": {"CORSRules": rules}}),
                    )
                    .await?;
                }
                None => gone_ok(cx.call("s3", "DeleteBucketCors", json!({"Bucket": bucket})).await)?,
            }
        }
        if want("LifecycleConfiguration") {
            match props.get("LifecycleConfiguration") {
                Some(l) => {
                    let rules: Vec<Value> = arr(l.get("Rules")).iter().map(lifecycle_rule).collect();
                    cx.call(
                        "s3",
                        "PutBucketLifecycleConfiguration",
                        json!({"Bucket": bucket, "LifecycleConfiguration": {"Rules": rules}}),
                    )
                    .await?;
                }
                None => gone_ok(cx.call("s3", "DeleteBucketLifecycle", json!({"Bucket": bucket})).await)?,
            }
        }
        if want("OwnershipControls") {
            match props.get("OwnershipControls") {
                Some(o) => {
                    cx.call(
                        "s3",
                        "PutBucketOwnershipControls",
                        json!({"Bucket": bucket, "OwnershipControls": {"Rules": arr(o.get("Rules"))}}),
                    )
                    .await?;
                }
                None => gone_ok(cx.call("s3", "DeleteBucketOwnershipControls", json!({"Bucket": bucket})).await)?,
            }
        }
        if want("WebsiteConfiguration") {
            match props.get("WebsiteConfiguration") {
                Some(w) => {
                    let mut m = Map::new();
                    if let Some(i) = w.get("IndexDocument") {
                        m.insert("IndexDocument".into(), json!({"Suffix": text(i)}));
                    }
                    if let Some(e) = w.get("ErrorDocument") {
                        m.insert("ErrorDocument".into(), json!({"Key": text(e)}));
                    }
                    if let Some(r) = w.get("RedirectAllRequestsTo") {
                        m.insert("RedirectAllRequestsTo".into(), r.clone());
                    }
                    let rules: Vec<Value> = arr(w.get("RoutingRules"))
                        .iter()
                        .map(|r| {
                            let mut x = Map::new();
                            if let Some(c) = r.get("RoutingRuleCondition") {
                                x.insert("Condition".into(), c.clone());
                            }
                            if let Some(c) = r.get("RedirectRule") {
                                x.insert("Redirect".into(), c.clone());
                            }
                            Value::Object(x)
                        })
                        .collect();
                    if !rules.is_empty() {
                        m.insert("RoutingRules".into(), json!(rules));
                    }
                    cx.call("s3", "PutBucketWebsite", json!({"Bucket": bucket, "WebsiteConfiguration": m})).await?;
                }
                None => gone_ok(cx.call("s3", "DeleteBucketWebsite", json!({"Bucket": bucket})).await)?,
            }
        }
        if want("NotificationConfiguration") {
            let n = props.get("NotificationConfiguration").map(notification).unwrap_or(json!({}));
            cx.call(
                "s3",
                "PutBucketNotificationConfiguration",
                json!({"Bucket": bucket, "NotificationConfiguration": n}),
            )
            .await?;
        }
        if want("ObjectLockConfiguration") {
            if let Some(o) = props.get("ObjectLockConfiguration") {
                let mut o = o.clone();
                if let Some(d) = o.pointer_mut("/Rule/DefaultRetention") {
                    for k in ["Days", "Years"] {
                        if let Some(v) = d.get(k).cloned() {
                            d[k] = num(&v);
                        }
                    }
                }
                cx.call("s3", "PutObjectLockConfiguration", json!({"Bucket": bucket, "ObjectLockConfiguration": o}))
                    .await?;
            }
        }
        let tags_changed = old.is_none_or(|o| changed(o, props, "Tags"));
        if tags_changed {
            let tags = cx.tags(props);
            if tags.is_empty() {
                if old.is_some() {
                    gone_ok(cx.call("s3", "DeleteBucketTagging", json!({"Bucket": bucket})).await)?;
                }
            } else {
                cx.call("s3", "PutBucketTagging", json!({"Bucket": bucket, "Tagging": {"TagSet": tags}})).await?;
            }
        }
        Ok(())
    }

    fn attributes(&self, cx: &Cx<'_>, bucket: &str) -> Props {
        let region = cx.region();
        let suffix = if cx.partition() == "aws-cn" { "amazonaws.com.cn" } else { "amazonaws.com" };
        Created::new(bucket)
            .attr("Arn", format!("arn:{}:s3:::{bucket}", cx.partition()))
            .attr("DomainName", format!("{bucket}.s3.{suffix}"))
            .attr("RegionalDomainName", format!("{bucket}.s3.{region}.{suffix}"))
            .attr("DualStackDomainName", format!("{bucket}.s3.dualstack.{region}.{suffix}"))
            .attr("WebsiteURL", format!("http://{bucket}.s3-website-{region}.{suffix}"))
            .attributes
    }
}

#[async_trait::async_trait]
impl Provider for Bucket {
    fn name_property(&self) -> Option<&'static str> {
        Some("BucketName")
    }

    fn create_only(&self) -> &'static [&'static str] {
        &["BucketName", "ObjectLockEnabled"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &[
            "Arn",
            "DomainName",
            "DualStackDomainName",
            "RegionalDomainName",
            "WebsiteURL",
            "MetadataTableConfiguration.S3TablesDestination.TableArn",
            "MetadataTableConfiguration.S3TablesDestination.TableNamespace",
        ]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "BucketName").unwrap_or_else(|| cx.physical_name_lower(63));
        let mut input = json!({"Bucket": name});
        if cx.region() != "us-east-1" {
            input["CreateBucketConfiguration"] = json!({"LocationConstraint": cx.region()});
        }
        if boolean(props, "ObjectLockEnabled") == Some(true) {
            input["ObjectLockEnabledForBucket"] = json!(true);
        }
        if let Some(acl) = s(props, "AccessControl") {
            input["ACL"] = json!(match acl.as_str() {
                "Private" => "private",
                "PublicRead" => "public-read",
                "PublicReadWrite" => "public-read-write",
                "AuthenticatedRead" => "authenticated-read",
                "BucketOwnerRead" => "bucket-owner-read",
                "BucketOwnerFullControl" => "bucket-owner-full-control",
                "LogDeliveryWrite" => "log-delivery-write",
                _ => "private",
            });
        }
        cx.call("s3", "CreateBucket", input).await?;
        self.apply(cx, &name, props, None).await?;
        Ok(Created { physical_id: name.clone(), attributes: self.attributes(cx, &name) })
    }

    async fn update(&self, cx: &Cx<'_>, bucket: &str, old: &Props, new: &Props, _attrs: &Props) -> HResult<Props> {
        self.apply(cx, bucket, new, Some(old)).await?;
        Ok(self.attributes(cx, bucket))
    }

    async fn delete(&self, cx: &Cx<'_>, bucket: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("s3", "DeleteBucket", json!({"Bucket": bucket})).await)
    }

    async fn read(&self, cx: &Cx<'_>, bucket: &str, props: &Props) -> Option<HResult<Props>> {
        Some(
            async {
                cx.call("s3", "HeadBucket", json!({"Bucket": bucket})).await?;
                let mut p = Props::new();
                if props.contains_key("BucketName") {
                    p.insert("BucketName".into(), json!(bucket));
                }
                if props.contains_key("VersioningConfiguration") {
                    let v = cx.call("s3", "GetBucketVersioning", json!({"Bucket": bucket})).await?;
                    p.insert(
                        "VersioningConfiguration".into(),
                        json!({"Status": v.get("Status").cloned().unwrap_or(json!("Suspended"))}),
                    );
                }
                if props.contains_key("Tags") {
                    let tags = match cx.call("s3", "GetBucketTagging", json!({"Bucket": bucket})).await {
                        Ok(t) => t["TagSet"].clone(),
                        Err(_) => json!([]),
                    };
                    p.insert("Tags".into(), tags);
                }
                Ok(p)
            }
            .await,
        )
    }
}

struct BucketPolicy;

#[async_trait::async_trait]
impl Provider for BucketPolicy {
    fn create_only(&self) -> &'static [&'static str] {
        &["Bucket"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["Bucket", "PolicyDocument"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let bucket = req(props, "Bucket")?;
        cx.call(
            "s3",
            "PutBucketPolicy",
            json!({"Bucket": bucket, "Policy": document(props, "PolicyDocument").unwrap_or_default()}),
        )
        .await?;
        Ok(Created::new(bucket))
    }

    async fn update(&self, cx: &Cx<'_>, bucket: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        cx.call(
            "s3",
            "PutBucketPolicy",
            json!({"Bucket": bucket, "Policy": document(new, "PolicyDocument").unwrap_or_default()}),
        )
        .await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, bucket: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("s3", "DeleteBucketPolicy", json!({"Bucket": bucket})).await)
    }

    async fn read(&self, cx: &Cx<'_>, bucket: &str, _props: &Props) -> Option<HResult<Props>> {
        Some(
            async {
                let out = cx.call("s3", "GetBucketPolicy", json!({"Bucket": bucket})).await?;
                let doc =
                    out["Policy"].as_str().and_then(|p| serde_json::from_str::<Value>(p).ok()).unwrap_or_default();
                let mut p = Props::new();
                p.insert("Bucket".into(), json!(bucket));
                p.insert("PolicyDocument".into(), doc);
                Ok(p)
            }
            .await,
        )
    }
}
