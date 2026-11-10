//! The X-Ray trace header (`X-Amzn-Trace-Id`) of the request being
//! handled. AWS SDKs running inside AWS compute (Lambda functions) send the
//! header they were given in `_X_AMZN_TRACE_ID`, and AWS services carry it
//! on to the work the request causes (a queue message's `AWSTraceHeader`,
//! a notification's invocation). The server scopes each request's header
//! with [`scope`]; services read it with [`current`].

use std::future::Future;

use crate::HttpRequest;

tokio::task_local! {
    static CURRENT: Option<String>;
}

/// The request's `X-Amzn-Trace-Id` header, if it has a non-empty one.
pub fn of(request: &HttpRequest) -> Option<String> {
    request
        .headers()
        .get("x-amzn-trace-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// Run `f` with `header` as the current trace header.
pub async fn scope<F: Future>(header: Option<String>, f: F) -> F::Output {
    CURRENT.scope(header, f).await
}

/// Call `f` with `header` as the current trace header.
pub fn scope_sync<R>(header: Option<String>, f: impl FnOnce() -> R) -> R {
    CURRENT.sync_scope(header, f)
}

/// The trace header of the request being handled, if any.
pub fn current() -> Option<String> {
    CURRENT.try_with(Clone::clone).ok().flatten()
}

/// `f` with the current trace header kept: for work spawned onto another
/// task that should still carry the request's header.
pub fn propagate<F: Future>(f: F) -> impl Future<Output = F::Output> {
    scope(current(), f)
}

/// The field `key` (`Root`, `Parent`, `Sampled`, `Lineage`, ...) of a trace
/// header.
pub fn field<'a>(header: &'a str, key: &str) -> Option<&'a str> {
    header.split(';').find_map(|part| {
        let (k, v) = part.split_once('=')?;
        (k.trim() == key).then(|| v.trim())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scoped_and_fields() {
        assert_eq!(current(), None);
        let h = "Root=1-5759e988-bd862e3fe1be46a994272793;Parent=53995c3f42cd8ad8;Sampled=1";
        let got = scope(Some(h.to_string()), async { propagate(async { current() }).await }).await;
        assert_eq!(got.as_deref(), Some(h));
        assert_eq!(field(h, "Sampled"), Some("1"));
        assert_eq!(field(h, "Lineage"), None);
    }
}
