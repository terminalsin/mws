//! Recursive loop detection. As in AWS, Lambda follows an event through
//! the X-Ray trace header (`X-Amzn-Trace-Id`): the SDK in a function sends
//! the header the function got in `_X_AMZN_TRACE_ID`, SQS keeps it as the
//! message's `AWSTraceHeader`, SNS and S3 carry it to the invocations they
//! cause. Lambda adds a `Lineage` entry to the header, a hash of the
//! function and how many times this chain of requests has invoked it
//! (`Lineage=a87bd80c:3|68fd508a:1`). An invocation from an SQS event
//! source mapping, an SNS subscription or an S3 notification that would be
//! the function's 17th in the chain is dropped, unless the function's
//! `RecursiveLoop` is `Allow`, and Lambda publishes the
//! `RecursiveInvocationsDropped` metric.

use mws_core::RequestContext;
use sha2::Digest;

use crate::names::FunctionRef;
use crate::Lambda;

/// The invocations of one function a chain of requests may make.
pub(crate) const MAX_RECURSION: u32 = 16;

/// The function's `Lineage` hash: eight hex digits.
pub(crate) fn function_hash(function_arn: &str) -> String {
    hex::encode(&sha2::Sha256::digest(function_arn.as_bytes())[..4])
}

/// The `Lineage` entries of a header, as `(hash, count)`. Entries in other
/// formats are kept as they are.
fn lineage(header: Option<&str>) -> Vec<(String, Option<u32>)> {
    let Some(l) = header.and_then(|h| mws_core::trace_header::field(h, "Lineage")) else { return Vec::new() };
    l.split('|')
        .filter(|e| !e.is_empty())
        .map(|e| match e.split(':').collect::<Vec<_>>().as_slice() {
            [hash, count] if hash.len() == 8 && hash.bytes().all(|b| b.is_ascii_hexdigit()) => match count.parse() {
                Ok(n) => (hash.to_ascii_lowercase(), Some(n)),
                Err(_) => (e.to_string(), None),
            },
            _ => (e.to_string(), None),
        })
        .collect()
}

/// How many times the chain of requests `header` belongs to has invoked
/// the function with `hash`.
pub(crate) fn count(header: Option<&str>, hash: &str) -> u32 {
    lineage(header).into_iter().find(|(h, n)| h == hash && n.is_some()).and_then(|(_, n)| n).unwrap_or(0)
}

/// The header an invocation of the function with `hash` runs with: the
/// chain's root and sampling decision, a new parent, and the function's
/// lineage count set to `n`.
pub(crate) fn header_for(header: Option<&str>, hash: &str, n: u32) -> String {
    let field = |k| header.and_then(|h| mws_core::trace_header::field(h, k));
    let root = field("Root").map(str::to_string).unwrap_or_else(new_root);
    let sampled = field("Sampled").unwrap_or("0");
    let parent = hex::encode(rand::random::<[u8; 8]>());
    let mut entries = lineage(header);
    match entries.iter_mut().find(|(h, n)| h == hash && n.is_some()) {
        Some(e) => e.1 = Some(n),
        None => entries.push((hash.to_string(), Some(n))),
    }
    let lineage: Vec<String> = entries
        .into_iter()
        .map(|(h, n)| match n {
            Some(n) => format!("{h}:{n}"),
            None => h,
        })
        .collect();
    format!("Root={root};Parent={parent};Sampled={sampled};Lineage={}", lineage.join("|"))
}

fn new_root() -> String {
    format!("1-{:08x}-{}", chrono::Utc::now().timestamp(), hex::encode(rand::random::<[u8; 12]>()))
}

impl Lambda {
    /// The trace header for an invocation an event caused (an SQS message,
    /// an SNS notification, an S3 event) that arrived with `incoming`, or
    /// `None` when the invocation would continue a recursive loop and is
    /// dropped.
    pub(crate) fn recursion_check(
        &self,
        ctx: &RequestContext,
        f: &FunctionRef,
        incoming: Option<&str>,
    ) -> Option<String> {
        let hash = function_hash(&f.arn());
        let n = count(incoming, &hash) + 1;
        if n > MAX_RECURSION {
            let allow = {
                let st = self.read();
                st.functions.get(&f.arn()).and_then(|func| func.recursive_loop.clone())
            };
            if allow.as_deref() != Some("Allow") {
                tracing::warn!(
                    function = %f.arn(),
                    "Lambda detected a recursive loop and stopped the function's invocation"
                );
                self.publish_function_metric(ctx, f, "RecursiveInvocationsDropped", "Count", 1.0);
                return None;
            }
        }
        Some(header_for(incoming, &hash, n))
    }

    /// Send an asynchronous event Lambda dropped as recursive to the
    /// function's on-failure destination and dead-letter queue, as a failed
    /// event would go.
    pub(crate) async fn drop_recursive_event(&self, ctx: &RequestContext, f: &FunctionRef, payload: &[u8]) {
        let (config, dead_letter) = {
            let st = self.read();
            let func = st.functions.get(&f.arn());
            let q = f.qualifier.clone().unwrap_or_else(|| "$LATEST".into());
            (
                func.and_then(|func| func.event_invoke_configs.get(&q).cloned()),
                func.and_then(|func| func.version_for(f.qualifier.as_deref()))
                    .and_then(|v| v.config.dead_letter_config.as_ref())
                    .and_then(|d| d.target_arn.clone())
                    .filter(|a| !a.is_empty()),
            )
        };
        let error = serde_json::json!({
            "errorType": "RecursiveInvocationException",
            "errorMessage": RECURSION_MESSAGE,
        });
        let ran = crate::invoke::Ran {
            outcome: crate::runtime::Outcome {
                payload: error.to_string().into_bytes(),
                function_error: Some("Unhandled".into()),
                logs: String::new(),
            },
            executed_version: f.qualifier.clone().unwrap_or_else(|| "$LATEST".into()),
        };
        self.deliver(ctx, f, config.as_ref(), payload, &ran, 0, "RetriesExhausted").await;
        if let Some(target) = dead_letter {
            self.send_dead_letter(ctx, f, &target, payload, &ran).await;
        }
    }
}

/// The message of `RecursiveInvocationException`.
pub(crate) const RECURSION_MESSAGE: &str = "Lambda has detected your function being invoked in a recursive loop with other AWS resources and stopped your function's invocation.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lineage_counts() {
        let h = function_hash("arn:aws:lambda:us-east-1:123456789012:function:f");
        assert_eq!(h.len(), 8);
        assert_eq!(count(None, &h), 0);
        let first = header_for(None, &h, 1);
        assert!(first.starts_with("Root=1-"));
        assert_eq!(count(Some(&first), &h), 1);
        let second = header_for(Some(&first), &h, 2);
        assert_eq!(mws_core::trace_header::field(&first, "Root"), mws_core::trace_header::field(&second, "Root"));
        assert!(second.ends_with(&format!("Lineage={h}:2")));
        let other = header_for(Some(&second), "0123abcd", 1);
        assert!(other.ends_with(&format!("Lineage={h}:2|0123abcd:1")));
        assert_eq!(count(Some(&other), "0123abcd"), 1);
        // Other formats are carried, not counted.
        let odd = "Root=1-5759e988-bd862e3fe1be46a994272793;Lineage=1:0:0";
        assert_eq!(count(Some(odd), &h), 0);
        assert!(header_for(Some(odd), &h, 1).ends_with(&format!("Lineage=1:0:0|{h}:1")));
    }
}
