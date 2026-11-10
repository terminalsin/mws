//! IAM resource types.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use super::{changed, document, gone_ok, int, list, req, s, text, Created, Cx, HResult, Props, Provider};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::IAM::Role", Arc::new(Role));
    m.insert("AWS::IAM::User", Arc::new(User));
    m.insert("AWS::IAM::Group", Arc::new(Group));
    m.insert("AWS::IAM::Policy", Arc::new(InlinePolicy));
    m.insert("AWS::IAM::RolePolicy", Arc::new(EntityPolicy(Entity::Role)));
    m.insert("AWS::IAM::UserPolicy", Arc::new(EntityPolicy(Entity::User)));
    m.insert("AWS::IAM::GroupPolicy", Arc::new(EntityPolicy(Entity::Group)));
    m.insert("AWS::IAM::ManagedPolicy", Arc::new(ManagedPolicy));
    m.insert("AWS::IAM::InstanceProfile", Arc::new(InstanceProfile));
    m.insert("AWS::IAM::AccessKey", Arc::new(AccessKey));
    m.insert("AWS::IAM::UserToGroupAddition", Arc::new(UserToGroupAddition));
    m.insert("AWS::IAM::OIDCProvider", Arc::new(OidcProvider));
}

#[derive(Clone, Copy)]
enum Entity {
    Role,
    User,
    Group,
}

impl Entity {
    fn noun(self) -> &'static str {
        match self {
            Entity::Role => "Role",
            Entity::User => "User",
            Entity::Group => "Group",
        }
    }
    fn name_member(self) -> &'static str {
        match self {
            Entity::Role => "RoleName",
            Entity::User => "UserName",
            Entity::Group => "GroupName",
        }
    }
}

async fn attach(cx: &Cx<'_>, e: Entity, name: &str, arn: &str) -> HResult<()> {
    let mut input = Map::new();
    input.insert(e.name_member().into(), json!(name));
    input.insert("PolicyArn".into(), json!(arn));
    cx.call("iam", &format!("Attach{}Policy", e.noun()), Value::Object(input)).await.map(|_| ())
}

async fn detach(cx: &Cx<'_>, e: Entity, name: &str, arn: &str) -> HResult<()> {
    let mut input = Map::new();
    input.insert(e.name_member().into(), json!(name));
    input.insert("PolicyArn".into(), json!(arn));
    gone_ok(cx.call("iam", &format!("Detach{}Policy", e.noun()), Value::Object(input)).await)
}

async fn put_inline(cx: &Cx<'_>, e: Entity, name: &str, policy: &Value) -> HResult<()> {
    let mut input = Map::new();
    input.insert(e.name_member().into(), json!(name));
    input.insert("PolicyName".into(), json!(policy.get("PolicyName").map(text).unwrap_or_default()));
    let doc = match policy.get("PolicyDocument") {
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
        None => "{}".into(),
    };
    input.insert("PolicyDocument".into(), json!(doc));
    cx.call("iam", &format!("Put{}Policy", e.noun()), Value::Object(input)).await.map(|_| ())
}

async fn delete_inline(cx: &Cx<'_>, e: Entity, name: &str, policy_name: &str) -> HResult<()> {
    let mut input = Map::new();
    input.insert(e.name_member().into(), json!(name));
    input.insert("PolicyName".into(), json!(policy_name));
    gone_ok(cx.call("iam", &format!("Delete{}Policy", e.noun()), Value::Object(input)).await)
}

fn policies(props: &Props) -> Vec<Value> {
    props.get("Policies").and_then(Value::as_array).cloned().unwrap_or_default()
}

/// Bring managed and inline policies from `old` to `new`.
async fn sync_policies(cx: &Cx<'_>, e: Entity, name: &str, old: &Props, new: &Props) -> HResult<()> {
    let old_arns = list(old, "ManagedPolicyArns");
    let new_arns = list(new, "ManagedPolicyArns");
    for a in new_arns.iter().filter(|a| !old_arns.contains(a)) {
        attach(cx, e, name, a).await?;
    }
    for a in old_arns.iter().filter(|a| !new_arns.contains(a)) {
        detach(cx, e, name, a).await?;
    }
    let new_p = policies(new);
    let old_p = policies(old);
    for p in &new_p {
        if !old_p.contains(p) {
            put_inline(cx, e, name, p).await?;
        }
    }
    let new_names: Vec<String> = new_p.iter().map(|p| p.get("PolicyName").map(text).unwrap_or_default()).collect();
    for p in &old_p {
        let n = p.get("PolicyName").map(text).unwrap_or_default();
        if !new_names.contains(&n) {
            delete_inline(cx, e, name, &n).await?;
        }
    }
    Ok(())
}

async fn sync_tags(cx: &Cx<'_>, noun: &str, name_member: &str, name: &str, old: &Props, new: &Props) -> HResult<()> {
    if !changed(old, new, "Tags") {
        return Ok(());
    }
    let new_tags = cx.tags(new);
    let keys: Vec<String> = new_tags.iter().map(|t| text(&t["Key"])).collect();
    let removed: Vec<String> = cx.tags(old).iter().map(|t| text(&t["Key"])).filter(|k| !keys.contains(k)).collect();
    if !removed.is_empty() {
        cx.call("iam", &format!("Untag{noun}"), json!({name_member: name, "TagKeys": removed})).await?;
    }
    if !new_tags.is_empty() {
        cx.call("iam", &format!("Tag{noun}"), json!({name_member: name, "Tags": new_tags})).await?;
    }
    Ok(())
}

/// Detach and delete every policy of an entity before deleting it.
async fn strip(cx: &Cx<'_>, e: Entity, name: &str) -> HResult<()> {
    let mut input = Map::new();
    input.insert(e.name_member().into(), json!(name));
    if let Ok(out) = cx.call("iam", &format!("ListAttached{}Policies", e.noun()), Value::Object(input.clone())).await {
        for p in out["AttachedPolicies"].as_array().cloned().unwrap_or_default() {
            detach(cx, e, name, &text(&p["PolicyArn"])).await?;
        }
    }
    if let Ok(out) = cx.call("iam", &format!("List{}Policies", e.noun()), Value::Object(input)).await {
        for p in out["PolicyNames"].as_array().cloned().unwrap_or_default() {
            delete_inline(cx, e, name, &text(&p)).await?;
        }
    }
    Ok(())
}

struct Role;

#[async_trait::async_trait]
impl Provider for Role {
    fn name_property(&self) -> Option<&'static str> {
        Some("RoleName")
    }

    fn create_only(&self) -> &'static [&'static str] {
        &["RoleName", "Path"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["AssumeRolePolicyDocument"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn", "RoleId"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "RoleName").unwrap_or_else(|| cx.physical_name(64));
        let mut input = json!({
            "RoleName": name,
            "AssumeRolePolicyDocument": document(props, "AssumeRolePolicyDocument").unwrap_or_default(),
        });
        for k in ["Path", "Description", "PermissionsBoundary"] {
            if let Some(v) = s(props, k) {
                input[k] = json!(v);
            }
        }
        if let Some(d) = int(props, "MaxSessionDuration") {
            input["MaxSessionDuration"] = json!(d);
        }
        let tags = cx.tags(props);
        if !tags.is_empty() {
            input["Tags"] = json!(tags);
        }
        let out = cx.call("iam", "CreateRole", input).await?;
        sync_policies(cx, Entity::Role, &name, &Props::new(), props).await?;
        Ok(Created::new(&name).attr("Arn", out["Role"]["Arn"].clone()).attr("RoleId", out["Role"]["RoleId"].clone()))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "AssumeRolePolicyDocument") {
            cx.call(
                "iam",
                "UpdateAssumeRolePolicy",
                json!({"RoleName": name, "PolicyDocument": document(new, "AssumeRolePolicyDocument").unwrap_or_default()}),
            )
            .await?;
        }
        if changed(old, new, "Description") || changed(old, new, "MaxSessionDuration") {
            let mut input = json!({"RoleName": name, "Description": s(new, "Description").unwrap_or_default()});
            if let Some(d) = int(new, "MaxSessionDuration") {
                input["MaxSessionDuration"] = json!(d);
            }
            cx.call("iam", "UpdateRole", input).await?;
        }
        if changed(old, new, "PermissionsBoundary") {
            match s(new, "PermissionsBoundary") {
                Some(b) => {
                    cx.call("iam", "PutRolePermissionsBoundary", json!({"RoleName": name, "PermissionsBoundary": b}))
                        .await?
                }
                None => cx.call("iam", "DeleteRolePermissionsBoundary", json!({"RoleName": name})).await?,
            };
        }
        sync_policies(cx, Entity::Role, name, old, new).await?;
        sync_tags(cx, "Role", "RoleName", name, old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        strip(cx, Entity::Role, name).await?;
        if let Ok(out) = cx.call("iam", "ListInstanceProfilesForRole", json!({"RoleName": name})).await {
            for p in out["InstanceProfiles"].as_array().cloned().unwrap_or_default() {
                let _ = cx
                    .call(
                        "iam",
                        "RemoveRoleFromInstanceProfile",
                        json!({"RoleName": name, "InstanceProfileName": p["InstanceProfileName"]}),
                    )
                    .await;
            }
        }
        let _ = cx.call("iam", "DeleteRolePermissionsBoundary", json!({"RoleName": name})).await;
        gone_ok(cx.call("iam", "DeleteRole", json!({"RoleName": name})).await)
    }

    async fn read(&self, cx: &Cx<'_>, name: &str, props: &Props) -> Option<HResult<Props>> {
        Some(
            async {
                let out = cx.call("iam", "GetRole", json!({"RoleName": name})).await?;
                let r = &out["Role"];
                let mut p = Props::new();
                if let Some(doc) = r["AssumeRolePolicyDocument"].as_str() {
                    let doc = percent_decode(doc);
                    let v = serde_json::from_str::<Value>(&doc).unwrap_or(json!(doc));
                    p.insert(
                        "AssumeRolePolicyDocument".into(),
                        match props.get("AssumeRolePolicyDocument") {
                            Some(Value::String(_)) => json!(v.to_string()),
                            _ => v,
                        },
                    );
                }
                if props.contains_key("Description") {
                    p.insert("Description".into(), r["Description"].clone());
                }
                if props.contains_key("MaxSessionDuration") {
                    p.insert("MaxSessionDuration".into(), r["MaxSessionDuration"].clone());
                }
                if props.contains_key("RoleName") {
                    p.insert("RoleName".into(), json!(name));
                }
                if props.contains_key("Path") {
                    p.insert("Path".into(), r["Path"].clone());
                }
                if props.contains_key("ManagedPolicyArns") {
                    let out = cx.call("iam", "ListAttachedRolePolicies", json!({"RoleName": name})).await?;
                    let arns: Vec<Value> = out["AttachedPolicies"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default()
                        .iter()
                        .map(|a| a["PolicyArn"].clone())
                        .collect();
                    p.insert("ManagedPolicyArns".into(), Value::Array(arns));
                }
                Ok(p)
            }
            .await,
        )
    }
}

/// IAM returns policy documents URL-encoded.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

struct User;

#[async_trait::async_trait]
impl Provider for User {
    fn name_property(&self) -> Option<&'static str> {
        Some("UserName")
    }

    fn create_only(&self) -> &'static [&'static str] {
        &["UserName"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "UserName").unwrap_or_else(|| cx.physical_name(64));
        let mut input = json!({"UserName": name});
        for k in ["Path", "PermissionsBoundary"] {
            if let Some(v) = s(props, k) {
                input[k] = json!(v);
            }
        }
        let tags = cx.tags(props);
        if !tags.is_empty() {
            input["Tags"] = json!(tags);
        }
        let out = cx.call("iam", "CreateUser", input).await?;
        for g in list(props, "Groups") {
            cx.call("iam", "AddUserToGroup", json!({"UserName": name, "GroupName": g})).await?;
        }
        if let Some(lp) = props.get("LoginProfile") {
            let mut input = json!({"UserName": name, "Password": lp.get("Password").map(text).unwrap_or_default()});
            if let Some(r) = lp.get("PasswordResetRequired") {
                input["PasswordResetRequired"] = json!(r.as_bool().unwrap_or(text(r) == "true"));
            }
            cx.call("iam", "CreateLoginProfile", input).await?;
        }
        sync_policies(cx, Entity::User, &name, &Props::new(), props).await?;
        Ok(Created::new(&name).attr("Arn", out["User"]["Arn"].clone()))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let og = list(old, "Groups");
        let ng = list(new, "Groups");
        for g in ng.iter().filter(|g| !og.contains(g)) {
            cx.call("iam", "AddUserToGroup", json!({"UserName": name, "GroupName": g})).await?;
        }
        for g in og.iter().filter(|g| !ng.contains(g)) {
            gone_ok(cx.call("iam", "RemoveUserFromGroup", json!({"UserName": name, "GroupName": g})).await)?;
        }
        if changed(old, new, "Path") {
            cx.call(
                "iam",
                "UpdateUser",
                json!({"UserName": name, "NewPath": s(new, "Path").unwrap_or_else(|| "/".into())}),
            )
            .await?;
        }
        sync_policies(cx, Entity::User, name, old, new).await?;
        sync_tags(cx, "User", "UserName", name, old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        strip(cx, Entity::User, name).await?;
        if let Ok(out) = cx.call("iam", "ListGroupsForUser", json!({"UserName": name})).await {
            for g in out["Groups"].as_array().cloned().unwrap_or_default() {
                let _ =
                    cx.call("iam", "RemoveUserFromGroup", json!({"UserName": name, "GroupName": g["GroupName"]})).await;
            }
        }
        let _ = cx.call("iam", "DeleteLoginProfile", json!({"UserName": name})).await;
        gone_ok(cx.call("iam", "DeleteUser", json!({"UserName": name})).await)
    }
}

struct Group;

#[async_trait::async_trait]
impl Provider for Group {
    fn name_property(&self) -> Option<&'static str> {
        Some("GroupName")
    }

    fn create_only(&self) -> &'static [&'static str] {
        &["GroupName"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "GroupName").unwrap_or_else(|| cx.physical_name(128));
        let mut input = json!({"GroupName": name});
        if let Some(p) = s(props, "Path") {
            input["Path"] = json!(p);
        }
        let out = cx.call("iam", "CreateGroup", input).await?;
        sync_policies(cx, Entity::Group, &name, &Props::new(), props).await?;
        Ok(Created::new(&name).attr("Arn", out["Group"]["Arn"].clone()))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "Path") {
            cx.call(
                "iam",
                "UpdateGroup",
                json!({"GroupName": name, "NewPath": s(new, "Path").unwrap_or_else(|| "/".into())}),
            )
            .await?;
        }
        sync_policies(cx, Entity::Group, name, old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        strip(cx, Entity::Group, name).await?;
        if let Ok(out) = cx.call("iam", "GetGroup", json!({"GroupName": name})).await {
            for u in out["Users"].as_array().cloned().unwrap_or_default() {
                let _ =
                    cx.call("iam", "RemoveUserFromGroup", json!({"UserName": u["UserName"], "GroupName": name})).await;
            }
        }
        gone_ok(cx.call("iam", "DeleteGroup", json!({"GroupName": name})).await)
    }
}

/// `AWS::IAM::Policy`: one inline policy put on several principals.
struct InlinePolicy;

impl InlinePolicy {
    fn targets(props: &Props) -> Vec<(Entity, String)> {
        let mut out = Vec::new();
        for r in list(props, "Roles") {
            out.push((Entity::Role, r));
        }
        for u in list(props, "Users") {
            out.push((Entity::User, u));
        }
        for g in list(props, "Groups") {
            out.push((Entity::Group, g));
        }
        out
    }

    fn policy(props: &Props) -> Value {
        json!({"PolicyName": s(props, "PolicyName").unwrap_or_default(), "PolicyDocument": props.get("PolicyDocument").cloned().unwrap_or(json!({}))})
    }
}

#[async_trait::async_trait]
impl Provider for InlinePolicy {
    fn required(&self) -> &'static [&'static str] {
        &["PolicyName", "PolicyDocument"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Id"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let targets = Self::targets(props);
        if targets.is_empty() {
            return Err(super::HandlerError::invalid("At least one of [Groups,Roles,Users] must be non-empty."));
        }
        let p = Self::policy(props);
        for (e, n) in &targets {
            put_inline(cx, *e, n, &p).await?;
        }
        let id = cx.physical_name(64);
        Ok(Created::new(&id).attr("Id", id.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, _id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let p = Self::policy(new);
        let new_targets = Self::targets(new);
        let old_name = s(old, "PolicyName").unwrap_or_default();
        for (e, n) in Self::targets(old) {
            let kept = new_targets.iter().any(|(e2, n2)| e2.noun() == e.noun() && n2 == &n);
            if !kept || old_name != s(new, "PolicyName").unwrap_or_default() {
                delete_inline(cx, e, &n, &old_name).await?;
            }
        }
        for (e, n) in &new_targets {
            put_inline(cx, *e, n, &p).await?;
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, _id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let name = s(props, "PolicyName").unwrap_or_default();
        for (e, n) in Self::targets(props) {
            delete_inline(cx, e, &n, &name).await?;
        }
        Ok(())
    }
}

/// `AWS::IAM::RolePolicy` and friends.
struct EntityPolicy(Entity);

#[async_trait::async_trait]
impl Provider for EntityPolicy {
    fn create_only(&self) -> &'static [&'static str] {
        &["PolicyName", "RoleName", "UserName", "GroupName"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["PolicyName"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let target = req(props, self.0.name_member())?;
        let p = InlinePolicy::policy(props);
        put_inline(cx, self.0, &target, &p).await?;
        Ok(Created::new(format!("{}|{target}", s(props, "PolicyName").unwrap_or_default())))
    }

    async fn update(&self, cx: &Cx<'_>, _id: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let target = req(new, self.0.name_member())?;
        put_inline(cx, self.0, &target, &InlinePolicy::policy(new)).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, _id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let target = req(props, self.0.name_member())?;
        delete_inline(cx, self.0, &target, &s(props, "PolicyName").unwrap_or_default()).await
    }
}

struct ManagedPolicy;

#[async_trait::async_trait]
impl Provider for ManagedPolicy {
    fn name_property(&self) -> Option<&'static str> {
        Some("ManagedPolicyName")
    }

    fn create_only(&self) -> &'static [&'static str] {
        &["ManagedPolicyName", "Path", "Description"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["PolicyDocument"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["PolicyArn", "PolicyId", "AttachmentCount", "CreateDate", "DefaultVersionId", "IsAttachable", "UpdateDate"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "ManagedPolicyName").unwrap_or_else(|| cx.physical_name(128));
        let mut input =
            json!({"PolicyName": name, "PolicyDocument": document(props, "PolicyDocument").unwrap_or_default()});
        for k in ["Path", "Description"] {
            if let Some(v) = s(props, k) {
                input[k] = json!(v);
            }
        }
        let out = cx.call("iam", "CreatePolicy", input).await?;
        let p = &out["Policy"];
        let arn = text(&p["Arn"]);
        for (e, key) in [(Entity::Role, "Roles"), (Entity::User, "Users"), (Entity::Group, "Groups")] {
            for n in list(props, key) {
                attach(cx, e, &n, &arn).await?;
            }
        }
        Ok(Created::new(&arn)
            .attr("PolicyArn", arn.clone())
            .attr("PolicyId", p["PolicyId"].clone())
            .attr("DefaultVersionId", p["DefaultVersionId"].clone())
            .attr("IsAttachable", true)
            .attr("AttachmentCount", 0)
            .attr("CreateDate", p["CreateDate"].clone())
            .attr("UpdateDate", p["UpdateDate"].clone()))
    }

    async fn update(&self, cx: &Cx<'_>, arn: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let mut attrs = attrs.clone();
        if changed(old, new, "PolicyDocument") {
            let versions = cx.call("iam", "ListPolicyVersions", json!({"PolicyArn": arn})).await?;
            let versions = versions["Versions"].as_array().cloned().unwrap_or_default();
            if versions.len() >= 5 {
                if let Some(oldest) = versions.iter().rfind(|v| v["IsDefaultVersion"] != json!(true)) {
                    cx.call("iam", "DeletePolicyVersion", json!({"PolicyArn": arn, "VersionId": oldest["VersionId"]}))
                        .await?;
                }
            }
            let out = cx
                .call(
                    "iam",
                    "CreatePolicyVersion",
                    json!({"PolicyArn": arn, "PolicyDocument": document(new, "PolicyDocument").unwrap_or_default(), "SetAsDefault": true}),
                )
                .await?;
            attrs.insert("DefaultVersionId".into(), out["PolicyVersion"]["VersionId"].clone());
        }
        for (e, key) in [(Entity::Role, "Roles"), (Entity::User, "Users"), (Entity::Group, "Groups")] {
            let o = list(old, key);
            let n = list(new, key);
            for x in n.iter().filter(|x| !o.contains(x)) {
                attach(cx, e, x, arn).await?;
            }
            for x in o.iter().filter(|x| !n.contains(x)) {
                detach(cx, e, x, arn).await?;
            }
        }
        Ok(attrs)
    }

    async fn delete(&self, cx: &Cx<'_>, arn: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        for (e, key) in [(Entity::Role, "Roles"), (Entity::User, "Users"), (Entity::Group, "Groups")] {
            for n in list(props, key) {
                detach(cx, e, &n, arn).await?;
            }
        }
        if let Ok(out) = cx.call("iam", "ListPolicyVersions", json!({"PolicyArn": arn})).await {
            for v in out["Versions"].as_array().cloned().unwrap_or_default() {
                if v["IsDefaultVersion"] != json!(true) {
                    let _ = cx
                        .call("iam", "DeletePolicyVersion", json!({"PolicyArn": arn, "VersionId": v["VersionId"]}))
                        .await;
                }
            }
        }
        gone_ok(cx.call("iam", "DeletePolicy", json!({"PolicyArn": arn})).await)
    }
}

struct InstanceProfile;

#[async_trait::async_trait]
impl Provider for InstanceProfile {
    fn name_property(&self) -> Option<&'static str> {
        Some("InstanceProfileName")
    }

    fn create_only(&self) -> &'static [&'static str] {
        &["InstanceProfileName", "Path"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["Roles"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "InstanceProfileName").unwrap_or_else(|| cx.physical_name(128));
        let mut input = json!({"InstanceProfileName": name});
        if let Some(p) = s(props, "Path") {
            input["Path"] = json!(p);
        }
        let out = cx.call("iam", "CreateInstanceProfile", input).await?;
        for r in list(props, "Roles") {
            cx.call("iam", "AddRoleToInstanceProfile", json!({"InstanceProfileName": name, "RoleName": r})).await?;
        }
        Ok(Created::new(&name).attr("Arn", out["InstanceProfile"]["Arn"].clone()))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let o = list(old, "Roles");
        let n = list(new, "Roles");
        for r in o.iter().filter(|r| !n.contains(r)) {
            gone_ok(
                cx.call("iam", "RemoveRoleFromInstanceProfile", json!({"InstanceProfileName": name, "RoleName": r}))
                    .await,
            )?;
        }
        for r in n.iter().filter(|r| !o.contains(r)) {
            cx.call("iam", "AddRoleToInstanceProfile", json!({"InstanceProfileName": name, "RoleName": r})).await?;
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        for r in list(props, "Roles") {
            let _ = cx
                .call("iam", "RemoveRoleFromInstanceProfile", json!({"InstanceProfileName": name, "RoleName": r}))
                .await;
        }
        gone_ok(cx.call("iam", "DeleteInstanceProfile", json!({"InstanceProfileName": name})).await)
    }
}

struct AccessKey;

#[async_trait::async_trait]
impl Provider for AccessKey {
    fn create_only(&self) -> &'static [&'static str] {
        &["UserName", "Serial"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["UserName"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["SecretAccessKey"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let user = req(props, "UserName")?;
        let out = cx.call("iam", "CreateAccessKey", json!({"UserName": user})).await?;
        let id = text(&out["AccessKey"]["AccessKeyId"]);
        if s(props, "Status").as_deref() == Some("Inactive") {
            cx.call("iam", "UpdateAccessKey", json!({"UserName": user, "AccessKeyId": id, "Status": "Inactive"}))
                .await?;
        }
        Ok(Created::new(&id).attr("SecretAccessKey", out["AccessKey"]["SecretAccessKey"].clone()))
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let status = s(new, "Status").unwrap_or_else(|| "Active".into());
        cx.call(
            "iam",
            "UpdateAccessKey",
            json!({"UserName": req(new, "UserName")?, "AccessKeyId": id, "Status": status}),
        )
        .await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(
            cx.call("iam", "DeleteAccessKey", json!({"UserName": req(props, "UserName")?, "AccessKeyId": id})).await,
        )
    }
}

struct UserToGroupAddition;

#[async_trait::async_trait]
impl Provider for UserToGroupAddition {
    fn create_only(&self) -> &'static [&'static str] {
        &["GroupName"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["GroupName", "Users"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let group = req(props, "GroupName")?;
        for u in list(props, "Users") {
            cx.call("iam", "AddUserToGroup", json!({"UserName": u, "GroupName": group})).await?;
        }
        Ok(Created::new(cx.physical_name(128)))
    }

    async fn update(&self, cx: &Cx<'_>, _id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let group = req(new, "GroupName")?;
        let o = list(old, "Users");
        let n = list(new, "Users");
        for u in n.iter().filter(|u| !o.contains(u)) {
            cx.call("iam", "AddUserToGroup", json!({"UserName": u, "GroupName": group})).await?;
        }
        for u in o.iter().filter(|u| !n.contains(u)) {
            gone_ok(cx.call("iam", "RemoveUserFromGroup", json!({"UserName": u, "GroupName": group})).await)?;
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, _id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let group = req(props, "GroupName")?;
        for u in list(props, "Users") {
            gone_ok(cx.call("iam", "RemoveUserFromGroup", json!({"UserName": u, "GroupName": group})).await)?;
        }
        Ok(())
    }
}

struct OidcProvider;

#[async_trait::async_trait]
impl Provider for OidcProvider {
    fn create_only(&self) -> &'static [&'static str] {
        &["Url"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = json!({"Url": req(props, "Url")?, "ClientIDList": list(props, "ClientIdList")});
        let thumbs = list(props, "ThumbprintList");
        if !thumbs.is_empty() {
            input["ThumbprintList"] = json!(thumbs);
        }
        let tags = cx.tags(props);
        if !tags.is_empty() {
            input["Tags"] = json!(tags);
        }
        let out = cx.call("iam", "CreateOpenIDConnectProvider", input).await?;
        let arn = text(&out["OpenIDConnectProviderArn"]);
        Ok(Created::new(&arn).attr("Arn", arn.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, arn: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "ThumbprintList") {
            cx.call(
                "iam",
                "UpdateOpenIDConnectProviderThumbprint",
                json!({"OpenIDConnectProviderArn": arn, "ThumbprintList": list(new, "ThumbprintList")}),
            )
            .await?;
        }
        let o = list(old, "ClientIdList");
        let n = list(new, "ClientIdList");
        for c in n.iter().filter(|c| !o.contains(c)) {
            cx.call(
                "iam",
                "AddClientIDToOpenIDConnectProvider",
                json!({"OpenIDConnectProviderArn": arn, "ClientID": c}),
            )
            .await?;
        }
        for c in o.iter().filter(|c| !n.contains(c)) {
            cx.call(
                "iam",
                "RemoveClientIDFromOpenIDConnectProvider",
                json!({"OpenIDConnectProviderArn": arn, "ClientID": c}),
            )
            .await?;
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, arn: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("iam", "DeleteOpenIDConnectProvider", json!({"OpenIDConnectProviderArn": arn})).await)
    }
}
