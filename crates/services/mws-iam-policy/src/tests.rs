use super::*;

fn principal(arn: &str) -> PrincipalInfo {
    PrincipalInfo { account_id: "123456789012".into(), arns: vec![arn.into()], ..Default::default() }
}

fn ctx(pairs: &[(&str, &[&str])]) -> ConditionContext {
    pairs.iter().map(|(k, v)| (*k, v.iter().map(|s| s.to_string()).collect())).collect()
}

fn allowed(doc: &str, action: &str, resource: &str, c: &ConditionContext) -> bool {
    let p = Policy::parse(doc, PolicyKind::Identity).unwrap();
    let who = principal("arn:aws:iam::123456789012:user/bob");
    let e = p.evaluate(&Request { action, resource, principal: &who, context: c });
    e.allowed() && !e.denied()
}

#[test]
fn validation_matches_iam_messages() {
    let e = |d: &str, k| Policy::parse(d, k).unwrap_err().0;
    assert_eq!(e("{", PolicyKind::Identity), "Syntax errors in policy.");
    assert_eq!(
        e(
            r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*","Principal":"*"}}"#,
            PolicyKind::Identity
        ),
        "Policy document should not specify a principal."
    );
    assert_eq!(
        e(r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*"}}"#, PolicyKind::Identity),
        "Policy statement must contain resources."
    );
    assert_eq!(
        e(r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sts:AssumeRole"}}"#, PolicyKind::Trust),
        "Missing required field Principal"
    );
    assert_eq!(
        e(
            r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"GetUser","Resource":"*"}}"#,
            PolicyKind::Identity
        ),
        "Actions/Conditions must be prefaced by a vendor, e.g., iam, sdb, ec2, etc."
    );
    assert_eq!(
        e(
            r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"bucket"}}"#,
            PolicyKind::Identity
        ),
        "Resource bucket must be in ARN format or \"*\"."
    );
}

#[test]
fn actions_are_case_insensitive_and_wildcarded() {
    let doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["IAM:get*","route53:List*"],"Resource":"*"}]}"#;
    let c = ConditionContext::new();
    assert!(allowed(doc, "iam:GetUser", "*", &c));
    assert!(allowed(doc, "route53:ListHostedZones", "*", &c));
    assert!(!allowed(doc, "iam:CreateUser", "*", &c));
}

#[test]
fn not_action_and_not_resource() {
    let doc = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","NotAction":"iam:*","NotResource":"arn:aws:s3:::secret/*"}}"#;
    let c = ConditionContext::new();
    assert!(allowed(doc, "s3:GetObject", "arn:aws:s3:::public/x", &c));
    assert!(!allowed(doc, "s3:GetObject", "arn:aws:s3:::secret/x", &c));
    assert!(!allowed(doc, "iam:GetUser", "arn:aws:s3:::public/x", &c));
}

#[test]
fn deny_beats_allow() {
    let doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:Delete*","Resource":"*"}]}"#;
    let c = ConditionContext::new();
    assert!(allowed(doc, "iam:CreateUser", "*", &c));
    assert!(!allowed(doc, "iam:DeleteUser", "*", &c));
}

#[test]
fn policy_variables_in_resources() {
    let doc = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:*AccessKey*","Resource":"arn:aws:iam::*:user/${aws:username}"}}"#;
    let c = ctx(&[("aws:username", &["bob"])]);
    assert!(allowed(doc, "iam:CreateAccessKey", "arn:aws:iam::123456789012:user/bob", &c));
    assert!(!allowed(doc, "iam:CreateAccessKey", "arn:aws:iam::123456789012:user/alice", &c));
    // Variables are literal text in 2008-10-17 policies.
    let old = doc.replace("2012-10-17", "2008-10-17");
    assert!(!allowed(&old, "iam:CreateAccessKey", "arn:aws:iam::123456789012:user/bob", &c));
    // A missing variable makes the resource not match.
    assert!(!allowed(doc, "iam:CreateAccessKey", "arn:aws:iam::123456789012:user/bob", &ConditionContext::new()));
}

#[test]
fn condition_operators() {
    let cond = |op: &str, key: &str, val: &str| {
        format!(
            r#"{{"Version":"2012-10-17","Statement":{{"Effect":"Allow","Action":"*","Resource":"*","Condition":{{"{op}":{{"{key}":{val}}}}}}}}}"#
        )
    };
    let c = ctx(&[
        ("aws:SourceIp", &["10.1.2.3"]),
        ("aws:PrincipalTag/team", &["platform"]),
        ("aws:MultiFactorAuthPresent", &["false"]),
        ("aws:CurrentTime", &["2026-11-03T00:00:00Z"]),
        ("aws:TagKeys", &["env", "team"]),
        ("s3:max-keys", &["10"]),
    ]);
    let ok = |op: &str, key: &str, val: &str| allowed(&cond(op, key, val), "s3:x", "*", &c);
    assert!(ok("IpAddress", "aws:SourceIp", r#""10.0.0.0/8""#));
    assert!(!ok("NotIpAddress", "aws:SourceIp", r#""10.0.0.0/8""#));
    assert!(ok("StringEquals", "aws:principaltag/team", r#""platform""#), "keys are case-insensitive");
    assert!(!ok("StringEquals", "aws:PrincipalTag/team", r#""Platform""#));
    assert!(ok("StringEqualsIgnoreCase", "aws:PrincipalTag/team", r#""Platform""#));
    assert!(ok("StringLike", "aws:PrincipalTag/team", r#"["dev*","plat*"]"#));
    assert!(ok("Bool", "aws:MultiFactorAuthPresent", "false"));
    assert!(ok("DateLessThan", "aws:CurrentTime", r#""2027-01-01T00:00:00Z""#));
    assert!(ok("NumericLessThanEquals", "s3:max-keys", r#""10""#));
    assert!(!ok("NumericLessThan", "s3:max-keys", "10"));
    assert!(ok("ForAllValues:StringEquals", "aws:TagKeys", r#"["env","team","owner"]"#));
    assert!(!ok("ForAllValues:StringEquals", "aws:TagKeys", r#"["env"]"#));
    assert!(ok("ForAnyValue:StringEquals", "aws:TagKeys", r#"["env"]"#));
    assert!(ok("ForAllValues:StringEquals", "aws:Missing", r#"["x"]"#), "ForAllValues is vacuously true");
    assert!(!ok("ForAnyValue:StringEquals", "aws:Missing", r#"["x"]"#));
    assert!(ok("Null", "aws:Missing", "true"));
    assert!(!ok("Null", "aws:SourceIp", "true"));
    assert!(!ok("StringEquals", "aws:Missing", r#""x""#));
    assert!(ok("StringEqualsIfExists", "aws:Missing", r#""x""#));
    assert!(ok("StringNotEquals", "aws:Missing", r#""x""#), "negated operators match an absent key");
    assert!(!ok("ArnLike", "aws:PrincipalArn", r#""*""#), "absent key");
}

#[test]
fn decision_combines_boundary_session_and_resource() {
    let admin = Policy::parse(
        r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}"#,
        PolicyKind::Identity,
    )
    .unwrap();
    let iam_only = Policy::parse(
        r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:*","Resource":"*"}}"#,
        PolicyKind::Identity,
    )
    .unwrap();
    let who = principal("arn:aws:iam::123456789012:user/bob");
    let c = ConditionContext::new();
    let req = |action| Request { action, resource: "*", principal: &who, context: &c };
    let sp = |id: &str, p: &Policy| SourcedPolicy { source_id: id.into(), policy: p.clone() };

    let mut set = PolicySet { identity: vec![sp("admin", &admin)], ..Default::default() };
    assert!(decide(&set, &req("s3:GetObject")).allowed);

    set.boundary = Some(sp("boundary", &iam_only));
    let d = decide(&set, &req("s3:GetObject"));
    assert_eq!(d.deny_reason, Some(DenyReason::NoBoundaryAllow));
    assert!(decide(&set, &req("iam:GetUser")).allowed);

    set.boundary = None;
    set.session = vec![sp("session", &iam_only)];
    assert_eq!(decide(&set, &req("s3:GetObject")).deny_reason, Some(DenyReason::NoSessionAllow));

    let empty = PolicySet::default();
    assert_eq!(decide(&empty, &req("s3:GetObject")).deny_reason, Some(DenyReason::NoIdentityAllow));
    assert!(decide(&PolicySet { is_root: true, ..Default::default() }, &req("s3:GetObject")).allowed);

    // A trust policy naming the user directly needs no identity policy; one
    // naming the account delegates to identity policies.
    let direct = Policy::parse(r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/bob"},"Action":"sts:AssumeRole"}}"#, PolicyKind::Trust).unwrap();
    let account = Policy::parse(r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"123456789012"},"Action":"sts:AssumeRole"}}"#, PolicyKind::Trust).unwrap();
    let trust = |p: &Policy, identity: Vec<SourcedPolicy>| PolicySet {
        identity,
        resource: Some(sp("trust", p)),
        resource_required: true,
        ..Default::default()
    };
    assert!(decide(&trust(&direct, vec![]), &req("sts:AssumeRole")).allowed);
    assert_eq!(decide(&trust(&account, vec![]), &req("sts:AssumeRole")).deny_reason, Some(DenyReason::NoIdentityAllow));
    assert!(decide(&trust(&account, vec![sp("admin", &admin)]), &req("sts:AssumeRole")).allowed);
    let other = principal("arn:aws:iam::123456789012:user/eve");
    let d = decide(
        &trust(&direct, vec![sp("admin", &admin)]),
        &Request { action: "sts:AssumeRole", resource: "*", principal: &other, context: &c },
    );
    assert_eq!(d.deny_reason, Some(DenyReason::NoResourceAllow), "identity alone cannot satisfy a trust policy");
}
