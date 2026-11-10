//! Function, alias and layer identifiers as Lambda accepts them.

use mws_core::{RequestContext, ServiceError};

use crate::generated::errors;

/// A function named by name, ARN or partial ARN, with an optional
/// qualifier (version or alias).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FunctionRef {
    pub partition: String,
    pub account: String,
    pub region: String,
    pub name: String,
    pub qualifier: Option<String>,
}

impl FunctionRef {
    pub fn arn(&self) -> String {
        function_arn(&self.partition, &self.region, &self.account, &self.name)
    }

    /// The ARN with the qualifier, if any.
    pub fn qualified_arn(&self) -> String {
        match &self.qualifier {
            Some(q) => format!("{}:{q}", self.arn()),
            None => self.arn(),
        }
    }

    pub fn not_found(&self) -> ServiceError {
        errors::resource_not_found(format!("Function not found: {}", self.qualified_arn()))
    }
}

pub fn function_arn(partition: &str, region: &str, account: &str, name: &str) -> String {
    format!("arn:{partition}:lambda:{region}:{account}:function:{name}")
}

/// The account a request acts in.
pub fn account_of(ctx: &RequestContext) -> String {
    if ctx.caller.account_id.is_empty() {
        "000000000000".into()
    } else {
        ctx.caller.account_id.clone()
    }
}

/// Parse a `FunctionName` member. `qualifier` is the separate `Qualifier`
/// member, which must agree with one embedded in the name.
pub fn parse_function(ctx: &RequestContext, raw: &str, qualifier: Option<&str>) -> Result<FunctionRef, ServiceError> {
    let invalid = || errors::invalid_parameter_value(format!("Invalid function name: {raw}"));
    let (account, region, rest) = if let Some(arn) = raw.strip_prefix("arn:") {
        // arn:partition:lambda:region:account:function:name[:qualifier]
        let parts: Vec<&str> = arn.splitn(5, ':').collect();
        if parts.len() != 5 || parts[1] != "lambda" {
            return Err(invalid());
        }
        let rest = parts[4].strip_prefix("function:").ok_or_else(invalid)?;
        (parts[3].to_string(), parts[2].to_string(), rest.to_string())
    } else if let Some((account, rest)) = raw.split_once(":function:") {
        if account.len() != 12 || !account.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid());
        }
        (account.to_string(), ctx.region.clone(), rest.to_string())
    } else {
        (account_of(ctx), ctx.region.clone(), raw.to_string())
    };
    let (name, embedded) = match rest.split_once(':') {
        Some((n, q)) => (n.to_string(), Some(q.to_string())),
        None => (rest, None),
    };
    if name.is_empty() || name.len() > 64 {
        return Err(invalid());
    }
    let qualifier = match (embedded, qualifier) {
        (Some(a), Some(b)) if a != b => {
            return Err(errors::invalid_parameter_value(
                "The derived qualifier from the function name does not match the specified qualifier.",
            ));
        }
        (Some(a), _) => Some(a),
        (None, b) => b.map(str::to_string),
    };
    Ok(FunctionRef { partition: ctx.partition.clone(), account, region, name, qualifier })
}

/// Runtimes Lambda no longer lets you create or update functions with.
pub const DEPRECATED_RUNTIMES: &[&str] = &[
    "nodejs",
    "nodejs4.3",
    "nodejs4.3-edge",
    "nodejs6.10",
    "nodejs8.10",
    "nodejs10.x",
    "nodejs12.x",
    "nodejs14.x",
    "nodejs16.x",
    "java8",
    "python2.7",
    "python3.6",
    "python3.7",
    "python3.8",
    "dotnetcore1.0",
    "dotnetcore2.0",
    "dotnetcore2.1",
    "dotnetcore3.1",
    "dotnet6",
    "go1.x",
    "ruby2.5",
    "ruby2.7",
    "provided",
];

/// What to suggest instead of a deprecated runtime.
pub fn runtime_successor(runtime: &str) -> &'static str {
    match runtime {
        r if r.starts_with("nodejs") => "nodejs22.x",
        r if r.starts_with("python") => "python3.13",
        r if r.starts_with("java") => "java21",
        r if r.starts_with("dotnet") => "dotnet8",
        r if r.starts_with("ruby") => "ruby3.3",
        _ => "provided.al2023",
    }
}

/// Environment variable names Lambda sets itself and refuses from users.
pub const RESERVED_ENV: &[&str] = &[
    "_HANDLER",
    "_X_AMZN_TRACE_ID",
    "AWS_DEFAULT_REGION",
    "AWS_REGION",
    "AWS_EXECUTION_ENV",
    "AWS_LAMBDA_FUNCTION_NAME",
    "AWS_LAMBDA_FUNCTION_MEMORY_SIZE",
    "AWS_LAMBDA_FUNCTION_VERSION",
    "AWS_LAMBDA_INITIALIZATION_TYPE",
    "AWS_LAMBDA_LOG_GROUP_NAME",
    "AWS_LAMBDA_LOG_STREAM_NAME",
    "AWS_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_LAMBDA_RUNTIME_API",
    "LAMBDA_TASK_ROOT",
    "LAMBDA_RUNTIME_DIR",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> RequestContext {
        RequestContext {
            request_id: "r".into(),
            region: "us-east-1".into(),
            partition: "aws".into(),
            received_at: chrono::Utc::now(),
            caller: mws_core::Caller { account_id: "111122223333".into(), ..mws_core::Caller::anonymous() },
            source_ip: None,
            secure_transport: false,
            authorizer: std::sync::Arc::new(mws_core::AllowAll),
            endpoint: None,
        }
    }

    #[test]
    fn name_forms() {
        let c = ctx();
        let f = parse_function(&c, "fn", None).unwrap();
        assert_eq!(f.arn(), "arn:aws:lambda:us-east-1:111122223333:function:fn");
        let f = parse_function(&c, "fn:prod", None).unwrap();
        assert_eq!(f.qualifier.as_deref(), Some("prod"));
        let f = parse_function(&c, "arn:aws:lambda:eu-west-1:444455556666:function:x:3", None).unwrap();
        assert_eq!(
            (f.account.as_str(), f.region.as_str(), f.qualifier.as_deref()),
            ("444455556666", "eu-west-1", Some("3"))
        );
        let f = parse_function(&c, "444455556666:function:x", Some("1")).unwrap();
        assert_eq!(f.qualified_arn(), "arn:aws:lambda:us-east-1:444455556666:function:x:1");
        assert!(parse_function(&c, "fn:1", Some("2")).is_err());
    }
}
