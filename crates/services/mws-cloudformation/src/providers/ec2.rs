//! EC2 and VPC resource types.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use super::{boolean, changed, gone_ok, int, list, req, s, text, Created, Cx, HResult, HandlerError, Props, Provider};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::EC2::VPC", Arc::new(Vpc));
    m.insert("AWS::EC2::Subnet", Arc::new(Subnet));
    m.insert("AWS::EC2::SecurityGroup", Arc::new(SecurityGroup));
    m.insert("AWS::EC2::SecurityGroupIngress", Arc::new(SecurityGroupRule { egress: false }));
    m.insert("AWS::EC2::SecurityGroupEgress", Arc::new(SecurityGroupRule { egress: true }));
    m.insert("AWS::EC2::InternetGateway", Arc::new(InternetGateway));
    m.insert("AWS::EC2::VPCGatewayAttachment", Arc::new(GatewayAttachment));
    m.insert("AWS::EC2::RouteTable", Arc::new(RouteTable));
    m.insert("AWS::EC2::Route", Arc::new(Route));
    m.insert("AWS::EC2::SubnetRouteTableAssociation", Arc::new(SubnetRouteTableAssociation));
    m.insert("AWS::EC2::EIP", Arc::new(Eip));
    m.insert("AWS::EC2::EIPAssociation", Arc::new(EipAssociation));
    m.insert("AWS::EC2::NatGateway", Arc::new(NatGateway));
    m.insert("AWS::EC2::NetworkInterface", Arc::new(NetworkInterface));
    m.insert("AWS::EC2::NetworkAcl", Arc::new(NetworkAcl));
    m.insert("AWS::EC2::NetworkAclEntry", Arc::new(NetworkAclEntry));
    m.insert("AWS::EC2::SubnetNetworkAclAssociation", Arc::new(SubnetNetworkAclAssociation));
    m.insert("AWS::EC2::KeyPair", Arc::new(KeyPair));
    m.insert("AWS::EC2::Volume", Arc::new(Volume));
    m.insert("AWS::EC2::VolumeAttachment", Arc::new(VolumeAttachment));
    m.insert("AWS::EC2::Instance", Arc::new(Instance));
}

fn tag_spec(cx: &Cx<'_>, props: &Props, resource_type: &str) -> Value {
    let tags = cx.tags(props);
    if tags.is_empty() {
        json!([])
    } else {
        json!([{"ResourceType": resource_type, "Tags": tags}])
    }
}

/// Put `TagSpecifications` on an input when there are tags.
fn with_tags(cx: &Cx<'_>, props: &Props, resource_type: &str, input: &mut Value) {
    let spec = tag_spec(cx, props, resource_type);
    if spec.as_array().is_some_and(|a| !a.is_empty()) {
        input["TagSpecifications"] = spec;
    }
}

async fn retag(cx: &Cx<'_>, id: &str, old: &Props, new: &Props) -> HResult<()> {
    if !changed(old, new, "Tags") {
        return Ok(());
    }
    let new_tags = cx.tags(new);
    let keys: Vec<String> = new_tags.iter().map(|t| text(&t["Key"])).collect();
    let removed: Vec<Value> =
        cx.tags(old).iter().filter(|t| !keys.contains(&text(&t["Key"]))).map(|t| json!({"Key": t["Key"]})).collect();
    if !removed.is_empty() {
        cx.call("ec2", "DeleteTags", json!({"Resources": [id], "Tags": removed})).await?;
    }
    if !new_tags.is_empty() {
        cx.call("ec2", "CreateTags", json!({"Resources": [id], "Tags": new_tags})).await?;
    }
    Ok(())
}

fn filter(name: &str, value: &str) -> Value {
    json!({"Name": name, "Values": [value]})
}

/// Poll `check` until it returns `Some`, the way resource handlers
/// stabilize.
async fn stabilize<F, Fut>(what: &str, mut check: F) -> HResult<Value>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = HResult<Option<Value>>>,
{
    for _ in 0..1200 {
        if let Some(v) = check().await? {
            return Ok(v);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(HandlerError::handler("NotStabilized", format!("{what} did not stabilize")))
}

fn bool_attr(v: bool) -> Value {
    json!({"Value": v})
}

struct Vpc;

#[async_trait::async_trait]
impl Provider for Vpc {
    fn create_only(&self) -> &'static [&'static str] {
        &["CidrBlock", "Ipv4IpamPoolId", "Ipv4NetmaskLength", "InstanceTenancy"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["CidrBlock", "CidrBlockAssociations", "DefaultNetworkAcl", "DefaultSecurityGroup", "Ipv6CidrBlocks", "VpcId"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = json!({});
        for k in ["CidrBlock", "InstanceTenancy", "Ipv4IpamPoolId"] {
            if let Some(v) = s(props, k) {
                input[k] = json!(v);
            }
        }
        if let Some(n) = int(props, "Ipv4NetmaskLength") {
            input["Ipv4NetmaskLength"] = json!(n);
        }
        with_tags(cx, props, "vpc", &mut input);
        let out = cx.call("ec2", "CreateVpc", input).await?;
        let vpc = &out["Vpc"];
        let id = text(&vpc["VpcId"]);
        for (k, default) in [("EnableDnsSupport", true), ("EnableDnsHostnames", false)] {
            if let Some(b) = boolean(props, k).filter(|b| *b != default) {
                cx.call("ec2", "ModifyVpcAttribute", json!({"VpcId": id, k: bool_attr(b)})).await?;
            }
        }
        let sg = cx
            .call(
                "ec2",
                "DescribeSecurityGroups",
                json!({"Filters": [filter("vpc-id", &id), filter("group-name", "default")]}),
            )
            .await?;
        let acl = cx
            .call("ec2", "DescribeNetworkAcls", json!({"Filters": [filter("vpc-id", &id), filter("default", "true")]}))
            .await?;
        let assoc: Vec<Value> = vpc["CidrBlockAssociationSet"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|a| a["AssociationId"].clone())
            .collect();
        Ok(Created::new(&id)
            .attr("VpcId", id.clone())
            .attr("CidrBlock", vpc["CidrBlock"].clone())
            .attr("CidrBlockAssociations", Value::Array(assoc))
            .attr("Ipv6CidrBlocks", json!([]))
            .attr("DefaultSecurityGroup", sg["SecurityGroups"][0]["GroupId"].clone())
            .attr("DefaultNetworkAcl", acl["NetworkAcls"][0]["NetworkAclId"].clone()))
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        for (k, default) in [("EnableDnsSupport", true), ("EnableDnsHostnames", false)] {
            if changed(old, new, k) {
                let b = boolean(new, k).unwrap_or(default);
                cx.call("ec2", "ModifyVpcAttribute", json!({"VpcId": id, k: bool_attr(b)})).await?;
            }
        }
        retag(cx, id, old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("ec2", "DeleteVpc", json!({"VpcId": id})).await)
    }

    async fn read(&self, cx: &Cx<'_>, id: &str, props: &Props) -> Option<HResult<Props>> {
        Some(
            async {
                let out = cx.call("ec2", "DescribeVpcs", json!({"VpcIds": [id]})).await?;
                let v = &out["Vpcs"][0];
                let mut p = Props::new();
                if props.contains_key("CidrBlock") {
                    p.insert("CidrBlock".into(), v["CidrBlock"].clone());
                }
                for k in ["EnableDnsSupport", "EnableDnsHostnames"] {
                    if props.contains_key(k) {
                        let a = cx
                            .call("ec2", "DescribeVpcAttribute", json!({"VpcId": id, "Attribute": lower_first(k)}))
                            .await?;
                        p.insert(k.into(), a[k]["Value"].clone());
                    }
                }
                Ok(p)
            }
            .await,
        )
    }
}

fn lower_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_lowercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

struct Subnet;

#[async_trait::async_trait]
impl Provider for Subnet {
    fn create_only(&self) -> &'static [&'static str] {
        &[
            "VpcId",
            "CidrBlock",
            "AvailabilityZone",
            "AvailabilityZoneId",
            "Ipv4IpamPoolId",
            "Ipv4NetmaskLength",
            "OutpostArn",
        ]
    }
    fn required(&self) -> &'static [&'static str] {
        &["VpcId"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &[
            "AvailabilityZone",
            "AvailabilityZoneId",
            "CidrBlock",
            "Ipv6CidrBlocks",
            "NetworkAclAssociationId",
            "SubnetId",
            "VpcId",
        ]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = json!({"VpcId": req(props, "VpcId")?});
        for k in ["CidrBlock", "AvailabilityZone", "AvailabilityZoneId", "Ipv4IpamPoolId"] {
            if let Some(v) = s(props, k) {
                input[k] = json!(v);
            }
        }
        if let Some(n) = int(props, "Ipv4NetmaskLength") {
            input["Ipv4NetmaskLength"] = json!(n);
        }
        with_tags(cx, props, "subnet", &mut input);
        let out = cx.call("ec2", "CreateSubnet", input).await?;
        let sn = &out["Subnet"];
        let id = text(&sn["SubnetId"]);
        if boolean(props, "MapPublicIpOnLaunch") == Some(true) {
            cx.call("ec2", "ModifySubnetAttribute", json!({"SubnetId": id, "MapPublicIpOnLaunch": bool_attr(true)}))
                .await?;
        }
        let acl =
            cx.call("ec2", "DescribeNetworkAcls", json!({"Filters": [filter("association.subnet-id", &id)]})).await?;
        let acl_assoc = acl["NetworkAcls"][0]["Associations"]
            .as_array()
            .and_then(|a| a.iter().find(|x| x["SubnetId"] == json!(id)))
            .map(|x| x["NetworkAclAssociationId"].clone())
            .unwrap_or_default();
        Ok(Created::new(&id)
            .attr("SubnetId", id.clone())
            .attr("VpcId", sn["VpcId"].clone())
            .attr("CidrBlock", sn["CidrBlock"].clone())
            .attr("AvailabilityZone", sn["AvailabilityZone"].clone())
            .attr("AvailabilityZoneId", sn["AvailabilityZoneId"].clone())
            .attr("Ipv6CidrBlocks", json!([]))
            .attr("NetworkAclAssociationId", acl_assoc))
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "MapPublicIpOnLaunch") {
            let b = boolean(new, "MapPublicIpOnLaunch").unwrap_or(false);
            cx.call("ec2", "ModifySubnetAttribute", json!({"SubnetId": id, "MapPublicIpOnLaunch": bool_attr(b)}))
                .await?;
        }
        retag(cx, id, old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("ec2", "DeleteSubnet", json!({"SubnetId": id})).await)
    }
}

/// A template rule (`SecurityGroupIngress` entry or standalone rule
/// resource) as an `IpPermission`.
fn permission(rule: &Value, egress: bool) -> Value {
    let get = |k: &str| rule.get(k).map(text).filter(|v| !v.is_empty());
    let protocol = get("IpProtocol").unwrap_or_else(|| "-1".into());
    let mut p = json!({"IpProtocol": protocol});
    if protocol != "-1" {
        if let Some(f) = get("FromPort") {
            p["FromPort"] = json!(f.parse::<i64>().unwrap_or(-1));
        }
        if let Some(t) = get("ToPort") {
            p["ToPort"] = json!(t.parse::<i64>().unwrap_or(-1));
        }
    }
    let desc = get("Description");
    let with_desc = |mut v: Value| {
        if let Some(d) = &desc {
            v["Description"] = json!(d);
        }
        v
    };
    if let Some(c) = get("CidrIp") {
        p["IpRanges"] = json!([with_desc(json!({"CidrIp": c}))]);
    }
    if let Some(c) = get("CidrIpv6") {
        p["Ipv6Ranges"] = json!([with_desc(json!({"CidrIpv6": c}))]);
    }
    let (group, prefix) = if egress {
        ("DestinationSecurityGroupId", "DestinationPrefixListId")
    } else {
        ("SourceSecurityGroupId", "SourcePrefixListId")
    };
    if let Some(g) = get(group) {
        let mut pair = json!({"GroupId": g});
        if let Some(o) = get("SourceSecurityGroupOwnerId") {
            pair["UserId"] = json!(o);
        }
        p["UserIdGroupPairs"] = json!([with_desc(pair)]);
    } else if let Some(g) = get("SourceSecurityGroupName") {
        p["UserIdGroupPairs"] = json!([with_desc(json!({"GroupName": g}))]);
    }
    if let Some(pl) = get(prefix) {
        p["PrefixListIds"] = json!([with_desc(json!({"PrefixListId": pl}))]);
    }
    p
}

fn rules(props: &Props, key: &str, egress: bool) -> Vec<Value> {
    props
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|r| permission(r, egress))
        .collect()
}

const ALLOW_ALL_EGRESS: &str = r#"{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}"#;

struct SecurityGroup;

impl SecurityGroup {
    async fn set_rules(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, fresh: bool) -> HResult<()> {
        for (key, egress, add, revoke) in [
            ("SecurityGroupIngress", false, "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress"),
            ("SecurityGroupEgress", true, "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupEgress"),
        ] {
            let default_egress: Vec<Value> = vec![serde_json::from_str(ALLOW_ALL_EGRESS).expect("valid")];
            let before = match (egress, old.contains_key(key) || !fresh) {
                (true, _) if fresh || !old.contains_key(key) => default_egress.clone(),
                _ => rules(old, key, egress),
            };
            let after = if egress && !new.contains_key(key) { default_egress } else { rules(new, key, egress) };
            let removed: Vec<Value> = before.iter().filter(|r| !after.contains(r)).cloned().collect();
            let added: Vec<Value> = after.iter().filter(|r| !before.contains(r)).cloned().collect();
            if !removed.is_empty() {
                gone_ok(cx.call("ec2", revoke, json!({"GroupId": id, "IpPermissions": removed})).await)?;
            }
            if !added.is_empty() {
                cx.call("ec2", add, json!({"GroupId": id, "IpPermissions": added})).await?;
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl Provider for SecurityGroup {
    fn name_property(&self) -> Option<&'static str> {
        Some("GroupName")
    }

    fn create_only(&self) -> &'static [&'static str] {
        &["GroupDescription", "GroupName", "VpcId"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["GroupDescription"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["GroupId", "VpcId"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "GroupName").unwrap_or_else(|| cx.physical_name(255));
        let mut input = json!({"GroupName": name, "Description": req(props, "GroupDescription")?});
        if let Some(v) = s(props, "VpcId") {
            input["VpcId"] = json!(v);
        }
        with_tags(cx, props, "security-group", &mut input);
        let out = cx.call("ec2", "CreateSecurityGroup", input).await?;
        let id = text(&out["GroupId"]);
        self.set_rules(cx, &id, &Props::new(), props, true).await?;
        let d = cx.call("ec2", "DescribeSecurityGroups", json!({"GroupIds": [id]})).await?;
        Ok(Created::new(&id).attr("GroupId", id.clone()).attr("VpcId", d["SecurityGroups"][0]["VpcId"].clone()))
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        self.set_rules(cx, id, old, new, false).await?;
        retag(cx, id, old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("ec2", "DeleteSecurityGroup", json!({"GroupId": id})).await)
    }
}

struct SecurityGroupRule {
    egress: bool,
}

#[async_trait::async_trait]
impl Provider for SecurityGroupRule {
    fn create_only(&self) -> &'static [&'static str] {
        &[
            "GroupId",
            "GroupName",
            "IpProtocol",
            "FromPort",
            "ToPort",
            "CidrIp",
            "CidrIpv6",
            "SourceSecurityGroupId",
            "SourceSecurityGroupName",
            "SourceSecurityGroupOwnerId",
            "SourcePrefixListId",
            "DestinationSecurityGroupId",
            "DestinationPrefixListId",
        ]
    }
    fn required(&self) -> &'static [&'static str] {
        &["IpProtocol"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Id"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let op = if self.egress { "AuthorizeSecurityGroupEgress" } else { "AuthorizeSecurityGroupIngress" };
        let mut input = json!({"IpPermissions": [permission(&Value::Object(props.clone()), self.egress)]});
        match (s(props, "GroupId"), s(props, "GroupName")) {
            (Some(g), _) => input["GroupId"] = json!(g),
            (None, Some(n)) => input["GroupName"] = json!(n),
            (None, None) => return Err(HandlerError::invalid("Either GroupId or GroupName must be specified")),
        }
        let out = cx.call("ec2", op, input).await?;
        let id = text(&out["SecurityGroupRules"][0]["SecurityGroupRuleId"]);
        Ok(Created::new(&id).attr("Id", id.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let Some(group) = s(new, "GroupId") else {
            return Ok(attrs.clone());
        };
        let op = if self.egress {
            "UpdateSecurityGroupRuleDescriptionsEgress"
        } else {
            "UpdateSecurityGroupRuleDescriptionsIngress"
        };
        cx.call(
            "ec2",
            op,
            json!({"GroupId": group, "SecurityGroupRuleDescriptions": [{"SecurityGroupRuleId": id, "Description": s(new, "Description").unwrap_or_default()}]}),
        )
        .await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let op = if self.egress { "RevokeSecurityGroupEgress" } else { "RevokeSecurityGroupIngress" };
        let mut input = json!({"SecurityGroupRuleIds": [id]});
        match (s(props, "GroupId"), s(props, "GroupName")) {
            (Some(g), _) => input["GroupId"] = json!(g),
            (None, Some(n)) => input["GroupName"] = json!(n),
            _ => {}
        }
        gone_ok(cx.call("ec2", op, input).await)
    }
}

struct InternetGateway;

#[async_trait::async_trait]
impl Provider for InternetGateway {
    fn attributes(&self) -> &'static [&'static str] {
        &["InternetGatewayId"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = json!({});
        with_tags(cx, props, "internet-gateway", &mut input);
        let out = cx.call("ec2", "CreateInternetGateway", input).await?;
        let id = text(&out["InternetGateway"]["InternetGatewayId"]);
        Ok(Created::new(&id).attr("InternetGatewayId", id.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        retag(cx, id, old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("ec2", "DeleteInternetGateway", json!({"InternetGatewayId": id})).await)
    }
}

struct GatewayAttachment;

#[async_trait::async_trait]
impl Provider for GatewayAttachment {
    fn create_only(&self) -> &'static [&'static str] {
        &["VpcId"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["VpcId"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let vpc = req(props, "VpcId")?;
        let Some(igw) = s(props, "InternetGatewayId") else {
            return Err(HandlerError::invalid("MWS supports VPCGatewayAttachment with InternetGatewayId only"));
        };
        cx.call("ec2", "AttachInternetGateway", json!({"InternetGatewayId": igw, "VpcId": vpc})).await?;
        Ok(Created::new(format!("IGW|{vpc}")))
    }

    async fn update(&self, cx: &Cx<'_>, _id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "InternetGatewayId") {
            self.delete(cx, "", old, attrs).await?;
            self.create(cx, new).await?;
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, _id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let (Some(igw), Some(vpc)) = (s(props, "InternetGatewayId"), s(props, "VpcId")) else {
            return Ok(());
        };
        match cx.call("ec2", "DetachInternetGateway", json!({"InternetGatewayId": igw, "VpcId": vpc})).await {
            Err(e) if e.code == "Gateway.NotAttached" => Ok(()),
            r => gone_ok(r),
        }
    }
}

struct RouteTable;

#[async_trait::async_trait]
impl Provider for RouteTable {
    fn create_only(&self) -> &'static [&'static str] {
        &["VpcId"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["VpcId"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["RouteTableId"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = json!({"VpcId": req(props, "VpcId")?});
        with_tags(cx, props, "route-table", &mut input);
        let out = cx.call("ec2", "CreateRouteTable", input).await?;
        let id = text(&out["RouteTable"]["RouteTableId"]);
        Ok(Created::new(&id).attr("RouteTableId", id.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        retag(cx, id, old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("ec2", "DeleteRouteTable", json!({"RouteTableId": id})).await)
    }
}

const ROUTE_TARGETS: &[&str] = &[
    "GatewayId",
    "NatGatewayId",
    "InstanceId",
    "NetworkInterfaceId",
    "VpcPeeringConnectionId",
    "TransitGatewayId",
    "EgressOnlyInternetGatewayId",
    "VpcEndpointId",
    "LocalGatewayId",
    "CarrierGatewayId",
    "CoreNetworkArn",
];

fn destination(props: &Props) -> (&'static str, String) {
    for k in ["DestinationCidrBlock", "DestinationIpv6CidrBlock", "DestinationPrefixListId"] {
        if let Some(v) = s(props, k) {
            return (k, v);
        }
    }
    ("DestinationCidrBlock", String::new())
}

struct Route;

impl Route {
    fn input(&self, props: &Props) -> HResult<Value> {
        let (k, dest) = destination(props);
        let mut input = json!({"RouteTableId": req(props, "RouteTableId")?, k: dest});
        for t in ROUTE_TARGETS {
            if let Some(v) = s(props, t) {
                input[*t] = json!(v);
            }
        }
        Ok(input)
    }
}

#[async_trait::async_trait]
impl Provider for Route {
    fn create_only(&self) -> &'static [&'static str] {
        &["RouteTableId", "DestinationCidrBlock", "DestinationIpv6CidrBlock", "DestinationPrefixListId"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["RouteTableId"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        cx.call("ec2", "CreateRoute", self.input(props)?).await?;
        Ok(Created::new(format!("{}|{}", req(props, "RouteTableId")?, destination(props).1)))
    }

    async fn update(&self, cx: &Cx<'_>, _id: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        cx.call("ec2", "ReplaceRoute", self.input(new)?).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, _id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let (k, dest) = destination(props);
        gone_ok(cx.call("ec2", "DeleteRoute", json!({"RouteTableId": req(props, "RouteTableId")?, k: dest})).await)
    }
}

struct SubnetRouteTableAssociation;

#[async_trait::async_trait]
impl Provider for SubnetRouteTableAssociation {
    fn updatable(&self) -> bool {
        false
    }
    fn required(&self) -> &'static [&'static str] {
        &["RouteTableId", "SubnetId"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Id"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let out = cx
            .call(
                "ec2",
                "AssociateRouteTable",
                json!({"RouteTableId": req(props, "RouteTableId")?, "SubnetId": req(props, "SubnetId")?}),
            )
            .await?;
        let id = text(&out["AssociationId"]);
        Ok(Created::new(&id).attr("Id", id.clone()))
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("ec2", "DisassociateRouteTable", json!({"AssociationId": id})).await)
    }
}

struct Eip;

#[async_trait::async_trait]
impl Provider for Eip {
    fn create_only(&self) -> &'static [&'static str] {
        &["Domain", "NetworkBorderGroup", "PublicIpv4Pool", "Address", "IpamPoolId"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["AllocationId", "PublicIp"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = json!({"Domain": s(props, "Domain").unwrap_or_else(|| "vpc".into())});
        for k in ["NetworkBorderGroup", "PublicIpv4Pool", "Address", "IpamPoolId"] {
            if let Some(v) = s(props, k) {
                input[k] = json!(v);
            }
        }
        with_tags(cx, props, "elastic-ip", &mut input);
        let out = cx.call("ec2", "AllocateAddress", input).await?;
        let ip = text(&out["PublicIp"]);
        let alloc = text(&out["AllocationId"]);
        if let Some(i) = s(props, "InstanceId") {
            cx.call("ec2", "AssociateAddress", json!({"AllocationId": alloc, "InstanceId": i})).await?;
        }
        Ok(Created::new(&ip).attr("AllocationId", alloc).attr("PublicIp", ip.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, _ip: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let alloc = attrs.get("AllocationId").map(text).unwrap_or_default();
        if changed(old, new, "InstanceId") {
            let d = cx.call("ec2", "DescribeAddresses", json!({"AllocationIds": [alloc]})).await?;
            if let Some(a) = d["Addresses"][0]["AssociationId"].as_str() {
                cx.call("ec2", "DisassociateAddress", json!({"AssociationId": a})).await?;
            }
            if let Some(i) = s(new, "InstanceId") {
                cx.call("ec2", "AssociateAddress", json!({"AllocationId": alloc, "InstanceId": i})).await?;
            }
        }
        retag(cx, &alloc, old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, _ip: &str, _props: &Props, attrs: &Props) -> HResult<()> {
        let alloc = attrs.get("AllocationId").map(text).unwrap_or_default();
        if let Ok(d) = cx.call("ec2", "DescribeAddresses", json!({"AllocationIds": [alloc]})).await {
            if let Some(a) = d["Addresses"][0]["AssociationId"].as_str() {
                let _ = cx.call("ec2", "DisassociateAddress", json!({"AssociationId": a})).await;
            }
        }
        match cx.call("ec2", "ReleaseAddress", json!({"AllocationId": alloc})).await {
            Err(e) if e.code == "InvalidAllocationID.NotFound" => Ok(()),
            r => gone_ok(r),
        }
    }
}

struct EipAssociation;

#[async_trait::async_trait]
impl Provider for EipAssociation {
    fn updatable(&self) -> bool {
        false
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = json!({});
        for k in ["AllocationId", "InstanceId", "NetworkInterfaceId", "PrivateIpAddress"] {
            if let Some(v) = s(props, k) {
                input[k] = json!(v);
            }
        }
        if let Some(ip) = s(props, "EIP") {
            input["PublicIp"] = json!(ip);
        }
        let out = cx.call("ec2", "AssociateAddress", input).await?;
        Ok(Created::new(text(&out["AssociationId"])))
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        match cx.call("ec2", "DisassociateAddress", json!({"AssociationId": id})).await {
            Err(e) if e.code.starts_with("InvalidAssociationID") => Ok(()),
            r => gone_ok(r),
        }
    }
}

struct NatGateway;

async fn nat_state(cx: &Cx<'_>, id: &str) -> HResult<Value> {
    let d = cx.call("ec2", "DescribeNatGateways", json!({"NatGatewayIds": [id]})).await?;
    Ok(d["NatGateways"][0].clone())
}

#[async_trait::async_trait]
impl Provider for NatGateway {
    fn create_only(&self) -> &'static [&'static str] {
        &["SubnetId", "AllocationId", "ConnectivityType", "PrivateIpAddress"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["NatGatewayId"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = json!({});
        for k in ["SubnetId", "AllocationId", "ConnectivityType", "PrivateIpAddress"] {
            if let Some(v) = s(props, k) {
                input[k] = json!(v);
            }
        }
        with_tags(cx, props, "natgateway", &mut input);
        let out = cx.call("ec2", "CreateNatGateway", input).await?;
        let id = text(&out["NatGateway"]["NatGatewayId"]);
        stabilize("NAT gateway", || async {
            let n = nat_state(cx, &id).await?;
            match n["State"].as_str() {
                Some("available") => Ok(Some(n)),
                Some("failed") => Err(HandlerError::handler(
                    "NotStabilized",
                    format!("NAT gateway {id} failed: {}", text(&n["FailureMessage"])),
                )),
                _ => Ok(None),
            }
        })
        .await?;
        Ok(Created::new(&id).attr("NatGatewayId", id.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        retag(cx, id, old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("ec2", "DeleteNatGateway", json!({"NatGatewayId": id})).await)?;
        stabilize("NAT gateway deletion", || async {
            let n = match nat_state(cx, id).await {
                Ok(n) => n,
                Err(e) if e.not_found => return Ok(Some(Value::Null)),
                Err(e) => return Err(e),
            };
            Ok(matches!(n["State"].as_str(), Some("deleted") | None).then_some(Value::Null))
        })
        .await?;
        Ok(())
    }
}

struct NetworkInterface;

#[async_trait::async_trait]
impl Provider for NetworkInterface {
    fn create_only(&self) -> &'static [&'static str] {
        &["SubnetId", "PrivateIpAddress", "InterfaceType"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["SubnetId"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Id", "PrimaryPrivateIpAddress", "SecondaryPrivateIpAddresses", "VpcId"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = json!({"SubnetId": req(props, "SubnetId")?});
        for k in ["Description", "PrivateIpAddress", "InterfaceType"] {
            if let Some(v) = s(props, k) {
                input[k] = json!(v);
            }
        }
        let groups = list(props, "GroupSet");
        if !groups.is_empty() {
            input["Groups"] = json!(groups);
        }
        if let Some(n) = int(props, "SecondaryPrivateIpAddressCount") {
            input["SecondaryPrivateIpAddressCount"] = json!(n);
        }
        with_tags(cx, props, "network-interface", &mut input);
        let out = cx.call("ec2", "CreateNetworkInterface", input).await?;
        let ni = &out["NetworkInterface"];
        let id = text(&ni["NetworkInterfaceId"]);
        if boolean(props, "SourceDestCheck") == Some(false) {
            cx.call(
                "ec2",
                "ModifyNetworkInterfaceAttribute",
                json!({"NetworkInterfaceId": id, "SourceDestCheck": bool_attr(false)}),
            )
            .await?;
        }
        let secondary: Vec<Value> = ni["PrivateIpAddresses"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter(|a| a["Primary"] != json!(true))
            .map(|a| a["PrivateIpAddress"].clone())
            .collect();
        Ok(Created::new(&id)
            .attr("Id", id.clone())
            .attr("PrimaryPrivateIpAddress", ni["PrivateIpAddress"].clone())
            .attr("SecondaryPrivateIpAddresses", Value::Array(secondary))
            .attr("VpcId", ni["VpcId"].clone()))
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "GroupSet") {
            cx.call(
                "ec2",
                "ModifyNetworkInterfaceAttribute",
                json!({"NetworkInterfaceId": id, "Groups": list(new, "GroupSet")}),
            )
            .await?;
        }
        if changed(old, new, "Description") {
            cx.call(
                "ec2",
                "ModifyNetworkInterfaceAttribute",
                json!({"NetworkInterfaceId": id, "Description": {"Value": s(new, "Description").unwrap_or_default()}}),
            )
            .await?;
        }
        if changed(old, new, "SourceDestCheck") {
            let b = boolean(new, "SourceDestCheck").unwrap_or(true);
            cx.call(
                "ec2",
                "ModifyNetworkInterfaceAttribute",
                json!({"NetworkInterfaceId": id, "SourceDestCheck": bool_attr(b)}),
            )
            .await?;
        }
        retag(cx, id, old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("ec2", "DeleteNetworkInterface", json!({"NetworkInterfaceId": id})).await)
    }
}

struct NetworkAcl;

#[async_trait::async_trait]
impl Provider for NetworkAcl {
    fn create_only(&self) -> &'static [&'static str] {
        &["VpcId"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["VpcId"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Id"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = json!({"VpcId": req(props, "VpcId")?});
        with_tags(cx, props, "network-acl", &mut input);
        let out = cx.call("ec2", "CreateNetworkAcl", input).await?;
        let id = text(&out["NetworkAcl"]["NetworkAclId"]);
        Ok(Created::new(&id).attr("Id", id.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        retag(cx, id, old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("ec2", "DeleteNetworkAcl", json!({"NetworkAclId": id})).await)
    }
}

struct NetworkAclEntry;

impl NetworkAclEntry {
    fn input(&self, props: &Props) -> HResult<Value> {
        let mut input = json!({
            "NetworkAclId": req(props, "NetworkAclId")?,
            "RuleNumber": int(props, "RuleNumber").unwrap_or(0),
            "Protocol": req(props, "Protocol")?,
            "RuleAction": req(props, "RuleAction")?,
            "Egress": boolean(props, "Egress").unwrap_or(false),
        });
        for k in ["CidrBlock", "Ipv6CidrBlock"] {
            if let Some(v) = s(props, k) {
                input[k] = json!(v);
            }
        }
        if let Some(Value::Object(p)) = props.get("PortRange") {
            let mut p = p.clone();
            super::numbers(&mut p, &["From", "To"]);
            input["PortRange"] = Value::Object(p);
        }
        if let Some(Value::Object(i)) = props.get("Icmp") {
            let mut i = i.clone();
            super::numbers(&mut i, &["Code", "Type"]);
            input["IcmpTypeCode"] = Value::Object(i);
        }
        Ok(input)
    }
}

#[async_trait::async_trait]
impl Provider for NetworkAclEntry {
    fn create_only(&self) -> &'static [&'static str] {
        &["NetworkAclId", "RuleNumber", "Egress"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["NetworkAclId", "Protocol", "RuleAction", "RuleNumber"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Id"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        cx.call("ec2", "CreateNetworkAclEntry", self.input(props)?).await?;
        let id = format!(
            "{}|{}|{}",
            req(props, "NetworkAclId")?,
            if boolean(props, "Egress").unwrap_or(false) { "true" } else { "false" },
            int(props, "RuleNumber").unwrap_or(0)
        );
        Ok(Created::new(&id).attr("Id", id.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, _id: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        cx.call("ec2", "ReplaceNetworkAclEntry", self.input(new)?).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, _id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(
            cx.call(
                "ec2",
                "DeleteNetworkAclEntry",
                json!({"NetworkAclId": req(props, "NetworkAclId")?, "RuleNumber": int(props, "RuleNumber").unwrap_or(0), "Egress": boolean(props, "Egress").unwrap_or(false)}),
            )
            .await,
        )
    }
}

struct SubnetNetworkAclAssociation;

/// The subnet's current ACL association and the VPC's default ACL.
async fn acl_association(cx: &Cx<'_>, subnet: &str) -> HResult<(String, String)> {
    let d =
        cx.call("ec2", "DescribeNetworkAcls", json!({"Filters": [filter("association.subnet-id", subnet)]})).await?;
    let acl = &d["NetworkAcls"][0];
    let assoc = acl["Associations"]
        .as_array()
        .and_then(|a| a.iter().find(|x| x["SubnetId"] == json!(subnet)))
        .map(|x| text(&x["NetworkAclAssociationId"]))
        .ok_or_else(|| HandlerError::handler("NotFound", format!("Subnet {subnet} has no network ACL association")))?;
    let vpc = text(&acl["VpcId"]);
    let def = cx
        .call("ec2", "DescribeNetworkAcls", json!({"Filters": [filter("vpc-id", &vpc), filter("default", "true")]}))
        .await?;
    Ok((assoc, text(&def["NetworkAcls"][0]["NetworkAclId"])))
}

#[async_trait::async_trait]
impl Provider for SubnetNetworkAclAssociation {
    fn updatable(&self) -> bool {
        false
    }
    fn required(&self) -> &'static [&'static str] {
        &["NetworkAclId", "SubnetId"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["AssociationId"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let (assoc, _) = acl_association(cx, &req(props, "SubnetId")?).await?;
        let out = cx
            .call(
                "ec2",
                "ReplaceNetworkAclAssociation",
                json!({"AssociationId": assoc, "NetworkAclId": req(props, "NetworkAclId")?}),
            )
            .await?;
        let id = text(&out["NewAssociationId"]);
        Ok(Created::new(&id).attr("AssociationId", id.clone()))
    }

    async fn delete(&self, cx: &Cx<'_>, _id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        // Put the subnet back on its VPC's default ACL.
        let Ok((assoc, default)) = acl_association(cx, &req(props, "SubnetId")?).await else {
            return Ok(());
        };
        gone_ok(
            cx.call("ec2", "ReplaceNetworkAclAssociation", json!({"AssociationId": assoc, "NetworkAclId": default}))
                .await,
        )
    }
}

struct KeyPair;

#[async_trait::async_trait]
impl Provider for KeyPair {
    fn name_property(&self) -> Option<&'static str> {
        Some("KeyName")
    }

    fn updatable(&self) -> bool {
        false
    }
    fn required(&self) -> &'static [&'static str] {
        &["KeyName"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["KeyFingerprint", "KeyPairId"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = req(props, "KeyName")?;
        let mut input = json!({"KeyName": name});
        with_tags(cx, props, "key-pair", &mut input);
        let out = if let Some(public) = s(props, "PublicKeyMaterial") {
            input["PublicKeyMaterial"] =
                json!(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, public.as_bytes()));
            cx.call("ec2", "ImportKeyPair", input).await?
        } else {
            for k in ["KeyType", "KeyFormat"] {
                if let Some(v) = s(props, k) {
                    input[k] = json!(v);
                }
            }
            let out = cx.call("ec2", "CreateKeyPair", input).await?;
            // AWS keeps a new key pair's private key in Parameter Store.
            let id = text(&out["KeyPairId"]);
            cx.call(
                "ssm",
                "PutParameter",
                json!({"Name": format!("/ec2/keypair/{id}"), "Type": "SecureString", "Value": text(&out["KeyMaterial"])}),
            )
            .await?;
            out
        };
        Ok(Created::new(&name)
            .attr("KeyFingerprint", out["KeyFingerprint"].clone())
            .attr("KeyPairId", out["KeyPairId"].clone()))
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, props: &Props, attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("ec2", "DeleteKeyPair", json!({"KeyName": name})).await)?;
        if s(props, "PublicKeyMaterial").is_none() {
            let id = attrs.get("KeyPairId").map(text).unwrap_or_default();
            gone_ok(cx.call("ssm", "DeleteParameter", json!({"Name": format!("/ec2/keypair/{id}")})).await)?;
        }
        Ok(())
    }
}

struct Volume;

#[async_trait::async_trait]
impl Provider for Volume {
    fn create_only(&self) -> &'static [&'static str] {
        &[
            "AvailabilityZone",
            "Encrypted",
            "KmsKeyId",
            "SnapshotId",
            "OutpostArn",
            "Size",
            "VolumeType",
            "Iops",
            "Throughput",
        ]
    }
    fn required(&self) -> &'static [&'static str] {
        &["AvailabilityZone"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["VolumeId"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = json!({"AvailabilityZone": req(props, "AvailabilityZone")?});
        for k in ["KmsKeyId", "SnapshotId", "VolumeType"] {
            if let Some(v) = s(props, k) {
                input[k] = json!(v);
            }
        }
        for k in ["Size", "Iops", "Throughput"] {
            if let Some(v) = int(props, k) {
                input[k] = json!(v);
            }
        }
        for k in ["Encrypted", "MultiAttachEnabled"] {
            if let Some(v) = boolean(props, k) {
                input[k] = json!(v);
            }
        }
        with_tags(cx, props, "volume", &mut input);
        let out = cx.call("ec2", "CreateVolume", input).await?;
        let id = text(&out["VolumeId"]);
        stabilize("Volume", || async {
            let d = cx.call("ec2", "DescribeVolumes", json!({"VolumeIds": [id]})).await?;
            Ok((d["Volumes"][0]["State"] == json!("available")).then_some(Value::Null))
        })
        .await?;
        Ok(Created::new(&id).attr("VolumeId", id.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        retag(cx, id, old, new).await?;
        Ok(attrs.clone())
    }

    /// `DeletionPolicy: Snapshot`: a snapshot of the volume, completed
    /// before the volume goes.
    async fn snapshot(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> Option<HResult<()>> {
        Some(
            async {
                let input = json!({
                    "VolumeId": id,
                    "Description": format!("Created by CloudFormation for stack {} resource {}", cx.stack_name, cx.logical_id),
                });
                let out = cx.call("ec2", "CreateSnapshot", input).await?;
                let snap = text(&out["SnapshotId"]);
                stabilize("Snapshot", || async {
                    let d = cx.call("ec2", "DescribeSnapshots", json!({"SnapshotIds": [snap]})).await?;
                    match d["Snapshots"][0]["State"].as_str() {
                        Some("error") => Err(HandlerError::handler(
                            "NotStabilized",
                            format!("Snapshot {snap} of volume {id} failed"),
                        )),
                        Some("completed") | None => Ok(Some(Value::Null)),
                        _ => Ok(None),
                    }
                })
                .await?;
                Ok(())
            }
            .await,
        )
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("ec2", "DeleteVolume", json!({"VolumeId": id})).await)
    }
}

struct VolumeAttachment;

#[async_trait::async_trait]
impl Provider for VolumeAttachment {
    fn updatable(&self) -> bool {
        false
    }
    fn required(&self) -> &'static [&'static str] {
        &["InstanceId", "VolumeId"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let volume = req(props, "VolumeId")?;
        let mut input = json!({"InstanceId": req(props, "InstanceId")?, "VolumeId": volume});
        if let Some(d) = s(props, "Device") {
            input["Device"] = json!(d);
        }
        cx.call("ec2", "AttachVolume", input).await?;
        Ok(Created::new(cx.physical_name(128)))
    }

    async fn delete(&self, cx: &Cx<'_>, _id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let input = json!({"InstanceId": req(props, "InstanceId")?, "VolumeId": req(props, "VolumeId")?});
        match cx.call("ec2", "DetachVolume", input).await {
            Err(e) if e.code == "IncorrectState" => Ok(()),
            r => gone_ok(r),
        }
    }
}

struct Instance;

async fn describe_instance(cx: &Cx<'_>, id: &str) -> HResult<Value> {
    let d = cx.call("ec2", "DescribeInstances", json!({"InstanceIds": [id]})).await?;
    Ok(d["Reservations"][0]["Instances"][0].clone())
}

async fn wait_instance(cx: &Cx<'_>, id: &str, state: &'static str) -> HResult<Value> {
    stabilize("Instance", || async {
        let i = describe_instance(cx, id).await?;
        let now = text(&i["State"]["Name"]);
        if now == state {
            return Ok(Some(i));
        }
        if now == "terminated" && state != "terminated" {
            return Err(HandlerError::handler(
                "NotStabilized",
                format!("Instance {id} terminated: {}", text(&i["StateReason"]["Message"])),
            ));
        }
        Ok(None)
    })
    .await
}

fn instance_attrs(i: &Value) -> Props {
    let mut a = Props::new();
    a.insert("InstanceId".into(), i["InstanceId"].clone());
    a.insert("AvailabilityZone".into(), i["Placement"]["AvailabilityZone"].clone());
    a.insert("PrivateDnsName".into(), i["PrivateDnsName"].clone());
    a.insert("PrivateIp".into(), i["PrivateIpAddress"].clone());
    a.insert("PublicDnsName".into(), i.get("PublicDnsName").cloned().unwrap_or(json!("")));
    a.insert("PublicIp".into(), i.get("PublicIpAddress").cloned().unwrap_or(json!("")));
    a.insert("VpcId".into(), i.get("VpcId").cloned().unwrap_or(json!("")));
    a
}

#[async_trait::async_trait]
impl Provider for Instance {
    fn create_only(&self) -> &'static [&'static str] {
        &[
            "ImageId",
            "KeyName",
            "SubnetId",
            "AvailabilityZone",
            "PrivateIpAddress",
            "NetworkInterfaces",
            "SecurityGroups",
            "IamInstanceProfile",
            "BlockDeviceMappings",
            "Tenancy",
            "PlacementGroupName",
            "HostId",
            "LaunchTemplate",
            "CpuOptions",
        ]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["AvailabilityZone", "InstanceId", "PrivateDnsName", "PrivateIp", "PublicDnsName", "PublicIp", "VpcId"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = json!({"MinCount": 1, "MaxCount": 1});
        for k in [
            "ImageId",
            "InstanceType",
            "KeyName",
            "SubnetId",
            "UserData",
            "PrivateIpAddress",
            "InstanceInitiatedShutdownBehavior",
        ] {
            if let Some(v) = s(props, k) {
                input[k] = json!(v);
            }
        }
        for (k, out) in [("SecurityGroupIds", "SecurityGroupIds"), ("SecurityGroups", "SecurityGroups")] {
            let l = list(props, k);
            if !l.is_empty() {
                input[out] = json!(l);
            }
        }
        if let Some(p) = s(props, "IamInstanceProfile") {
            input["IamInstanceProfile"] = if p.starts_with("arn:") { json!({"Arn": p}) } else { json!({"Name": p}) };
        }
        if let Some(az) = s(props, "AvailabilityZone") {
            input["Placement"] = json!({"AvailabilityZone": az});
        }
        for k in ["EbsOptimized", "DisableApiTermination"] {
            if let Some(b) = boolean(props, k) {
                input[k] = json!(b);
            }
        }
        if let Some(b) = boolean(props, "Monitoring") {
            input["Monitoring"] = json!({"Enabled": b});
        }
        if let Some(Value::Object(m)) = props.get("MetadataOptions") {
            let mut m = m.clone();
            super::numbers(&mut m, &["HttpPutResponseHopLimit"]);
            input["MetadataOptions"] = Value::Object(m);
        }
        if let Some(Value::Array(b)) = props.get("BlockDeviceMappings") {
            let mapped: Vec<Value> = b
                .iter()
                .map(|d| {
                    let mut d = d.as_object().cloned().unwrap_or_default();
                    if let Some(Value::Object(e)) = d.get_mut("Ebs") {
                        super::numbers(e, &["VolumeSize", "Iops", "Throughput"]);
                        super::bools(e, &["DeleteOnTermination", "Encrypted"]);
                    }
                    if d.get("NoDevice").is_some() {
                        d.insert("NoDevice".into(), json!(""));
                    }
                    Value::Object(d)
                })
                .collect();
            input["BlockDeviceMappings"] = json!(mapped);
        }
        if let Some(Value::Array(n)) = props.get("NetworkInterfaces") {
            let mapped: Vec<Value> = n
                .iter()
                .map(|ni| {
                    let mut o = ni.as_object().cloned().unwrap_or_default();
                    if let Some(g) = o.remove("GroupSet") {
                        o.insert("Groups".into(), g);
                    }
                    super::numbers(&mut o, &["DeviceIndex", "SecondaryPrivateIpAddressCount", "Ipv6AddressCount"]);
                    super::bools(&mut o, &["AssociatePublicIpAddress", "DeleteOnTermination"]);
                    Value::Object(o)
                })
                .collect();
            input["NetworkInterfaces"] = json!(mapped);
        }
        with_tags(cx, props, "instance", &mut input);
        let out = cx.call("ec2", "RunInstances", input).await?;
        let id = text(&out["Instances"][0]["InstanceId"]);
        let i = wait_instance(cx, &id, "running").await?;
        if boolean(props, "SourceDestCheck") == Some(false) {
            cx.call("ec2", "ModifyInstanceAttribute", json!({"InstanceId": id, "SourceDestCheck": bool_attr(false)}))
                .await?;
        }
        let mut c = Created::new(&id);
        c.attributes = instance_attrs(&i);
        Ok(c)
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        // Changes that need the instance stopped (some interruption).
        let interrupt = ["InstanceType", "UserData", "EbsOptimized"].iter().any(|k| changed(old, new, k));
        if interrupt {
            cx.call("ec2", "StopInstances", json!({"InstanceIds": [id]})).await?;
            wait_instance(cx, id, "stopped").await?;
            if changed(old, new, "InstanceType") {
                cx.call(
                    "ec2",
                    "ModifyInstanceAttribute",
                    json!({"InstanceId": id, "InstanceType": {"Value": s(new, "InstanceType").unwrap_or_default()}}),
                )
                .await?;
            }
            if changed(old, new, "UserData") {
                let data = s(new, "UserData").unwrap_or_default();
                cx.call("ec2", "ModifyInstanceAttribute", json!({"InstanceId": id, "UserData": {"Value": data}}))
                    .await?;
            }
            if changed(old, new, "EbsOptimized") {
                let b = boolean(new, "EbsOptimized").unwrap_or(false);
                cx.call("ec2", "ModifyInstanceAttribute", json!({"InstanceId": id, "EbsOptimized": bool_attr(b)}))
                    .await?;
            }
            cx.call("ec2", "StartInstances", json!({"InstanceIds": [id]})).await?;
        }
        if changed(old, new, "SecurityGroupIds") {
            cx.call(
                "ec2",
                "ModifyInstanceAttribute",
                json!({"InstanceId": id, "Groups": list(new, "SecurityGroupIds")}),
            )
            .await?;
        }
        for (k, default) in [("DisableApiTermination", false), ("SourceDestCheck", true)] {
            if changed(old, new, k) {
                let b = boolean(new, k).unwrap_or(default);
                cx.call("ec2", "ModifyInstanceAttribute", json!({"InstanceId": id, k: bool_attr(b)})).await?;
            }
        }
        if changed(old, new, "InstanceInitiatedShutdownBehavior") {
            let v = s(new, "InstanceInitiatedShutdownBehavior").unwrap_or_else(|| "stop".into());
            cx.call(
                "ec2",
                "ModifyInstanceAttribute",
                json!({"InstanceId": id, "InstanceInitiatedShutdownBehavior": {"Value": v}}),
            )
            .await?;
        }
        retag(cx, id, old, new).await?;
        let i = wait_instance(cx, id, "running").await?;
        let mut a = attrs.clone();
        a.extend(instance_attrs(&i));
        Ok(a)
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        match cx.call("ec2", "TerminateInstances", json!({"InstanceIds": [id]})).await {
            Err(e) if e.not_found || e.code == "InvalidInstanceID.NotFound" => return Ok(()),
            Err(e) => return Err(e),
            Ok(_) => {}
        }
        wait_instance(cx, id, "terminated").await?;
        Ok(())
    }

    async fn read(&self, cx: &Cx<'_>, id: &str, props: &Props) -> Option<HResult<Props>> {
        Some(
            async {
                let i = describe_instance(cx, id).await?;
                let mut p = Props::new();
                for (k, src) in [
                    ("InstanceType", "InstanceType"),
                    ("ImageId", "ImageId"),
                    ("SubnetId", "SubnetId"),
                    ("KeyName", "KeyName"),
                ] {
                    if props.contains_key(k) {
                        p.insert(k.into(), i[src].clone());
                    }
                }
                Ok(p)
            }
            .await,
        )
    }
}
