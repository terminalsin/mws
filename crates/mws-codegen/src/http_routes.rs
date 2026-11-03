//! Routing for the HTTP-binding protocols (restXml, restJson1): match a
//! request's method, path and query against each operation's `@http` URI,
//! most specific first.

use std::fmt::Write;

use mws_smithy::{Model, Shape};
use serde_json::Value;

use crate::naming::{rust_str, snake_case};

pub struct Route<'s> {
    pub op: &'s Shape,
    pub method: String,
    /// The URI with optional query literals removed.
    pub pattern: String,
    /// Optional query literals: `(key, value)`.
    pub hints: Vec<(String, String)>,
    /// Conditions that hold when every required query/header member is
    /// present.
    pub required: Vec<String>,
    pub code: u16,
    /// Whether `required` must hold for this route to be chosen.
    pub guarded: bool,
}

/// One route per operation, sorted most specific first. `optional` names
/// query literals that only some SDKs send (S3's `x-id`).
pub fn build<'s>(model: &Model, ops: &[&'s Shape], optional: &[&str]) -> Vec<Route<'s>> {
    let mut routes: Vec<Route> = ops
        .iter()
        .map(|op| {
            let http = op.get_trait("http").unwrap_or_else(|| panic!("{} has no @http trait", op.id));
            let method = http["method"].as_str().unwrap().to_string();
            let uri = http["uri"].as_str().unwrap().to_string();
            let code = http.get("code").and_then(Value::as_u64).unwrap_or(200) as u16;
            let (path, query) = uri.split_once('?').unwrap_or((&uri, ""));
            let mut literals = Vec::new();
            let mut hints = Vec::new();
            for part in query.split('&').filter(|p| !p.is_empty()) {
                let (k, v) = part.split_once('=').unwrap_or((part, ""));
                if optional.contains(&k) {
                    hints.push((k.to_string(), v.to_string()));
                } else {
                    literals.push(part.to_string());
                }
            }
            let pattern = if literals.is_empty() { path.to_string() } else { format!("{path}?{}", literals.join("&")) };
            // Required query and header members, which tell apart
            // operations that share a method, path and query literals
            // (S3's PutObject, CopyObject, UploadPart, UploadPartCopy).
            let mut required = Vec::new();
            if let Some(input) = op.input.as_deref().map(|id| model.expect(id)) {
                for m in input.members.iter().filter(|m| m.has_trait("required")) {
                    if let Some(q) = m.get_trait("httpQuery").and_then(Value::as_str) {
                        required.push(format!("query.contains({})", rust_str(q)));
                    } else if let Some(h) = m.get_trait("httpHeader").and_then(Value::as_str) {
                        required.push(format!("req.headers().contains_key({})", rust_str(h)));
                    }
                }
            }
            Route { op, method, pattern, hints, required, code, guarded: false }
        })
        .collect();
    // Most specific routes first: query literals, then more literal
    // segments, then fewer greedy labels, then more required bindings.
    routes.sort_by_key(|r| {
        let (path, query) = r.pattern.split_once('?').unwrap_or((&r.pattern, ""));
        let literals = path.split('/').filter(|s| !s.starts_with('{')).count();
        let greedy = path.contains("+}");
        (query.is_empty(), std::cmp::Reverse(literals), greedy, std::cmp::Reverse(r.required.len()))
    });
    // Only routes that share a method and pattern with a later route need
    // their required bindings checked to be chosen; the last one keeps
    // reporting missing members as validation errors.
    for i in 0..routes.len() {
        routes[i].guarded =
            routes[i + 1..].iter().any(|later| later.method == routes[i].method && later.pattern == routes[i].pattern);
    }
    routes
}

/// `operation_for` and `route`, which calls `op_{name}(handler, ctx, req,
/// &query, &labels)` for the matching operation. `rt` is the protocol
/// runtime crate, which re-exports `Query`, `match_uri`, `hint_matches` and
/// `unknown_operation`.
pub fn emit_routing(routes: &[Route<'_>], rt: &str, w: &mut String) {
    let conditions = |r: &Route| -> String {
        let mut c = format!("method == {}", rust_str(&r.method));
        for (k, v) in &r.hints {
            let _ = write!(c, " && {rt}::hint_matches(&query, {}, {})", rust_str(k), rust_str(v));
        }
        if r.guarded {
            for req in &r.required {
                let _ = write!(c, " && {req}");
            }
        }
        c
    };

    let _ = writeln!(
        w,
        "\n/// Route the request to its operation, run the handler, and encode the result.\npub async fn dispatch<H: Handler + ?Sized>(handler: &H, ctx: &RequestContext, req: &HttpRequest) -> HttpResponse {{"
    );
    let _ = writeln!(w, "    match route(handler, ctx, req).await {{");
    let _ = writeln!(w, "        Ok(resp) => resp,");
    let _ = writeln!(w, "        Err(e) => {rt}::error_response(&SERVICE_INFO, &ctx.request_id, &e),");
    let _ = writeln!(w, "    }}\n}}");
    let _ = writeln!(
        w,
        "\n/// The operation a request addresses, if any.\npub fn operation_for(req: &HttpRequest) -> Option<&'static str> {{"
    );
    let _ = writeln!(
        w,
        "    let query = {rt}::Query::parse(req.uri().query());\n    let path = req.uri().path();\n    let method = req.method().as_str();"
    );
    let _ = writeln!(w, "    let _ = req.headers();");
    for r in routes {
        let _ = writeln!(
            w,
            "    if {} && {rt}::match_uri({}, path, &query).is_some() {{ return Some({}); }}",
            conditions(r),
            rust_str(&r.pattern),
            rust_str(r.op.name())
        );
    }
    let _ = writeln!(w, "    None\n}}");

    let _ = writeln!(
        w,
        "\n/// Route `req` to its operation, returning the error unrendered (see\n/// `dispatch`).\npub async fn route<H: Handler + ?Sized>(handler: &H, ctx: &RequestContext, req: &HttpRequest) -> Result<HttpResponse, ServiceError> {{"
    );
    let _ = writeln!(
        w,
        "    let query = {rt}::Query::parse(req.uri().query());\n    let path = req.uri().path();\n    let method = req.method().as_str();"
    );
    for r in routes {
        let _ = writeln!(
            w,
            "    if {} {{ if let Some(labels) = {rt}::match_uri({}, path, &query) {{ return op_{}(handler, ctx, req, &query, &labels).await; }} }}",
            conditions(r),
            rust_str(&r.pattern),
            snake_case(r.op.name())
        );
    }
    let _ = writeln!(w, "    Err({rt}::unknown_operation(method, path))\n}}");
}
