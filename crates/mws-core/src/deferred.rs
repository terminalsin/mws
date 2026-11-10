//! Work a handler hands off to run once it has finished: deliveries to
//! other services (an S3 event notification, an SNS message to a queue).
//!
//! AWS makes those deliveries as API calls after the triggering request
//! succeeded. Handlers here usually decide on them while holding their own
//! state lock, where calling another service (and the IAM authorizer) must
//! not happen, and often in synchronous code. [`defer`] queues the work;
//! [`run`], which the front door wraps around every request (and
//! [`crate::ServiceClient`] around every call it makes), runs it once the
//! handler has returned, before the response goes out. So a message is in
//! its queue by the time the SDK sees the triggering call succeed, as tests
//! expect, and no lock is held while it is delivered.
//!
//! Outside [`run`] (background tasks such as lifecycle rules or schedules)
//! deferred work is spawned instead.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

type Job = Pin<Box<dyn Future<Output = ()> + Send>>;
type Queue = Arc<Mutex<Vec<Job>>>;

tokio::task_local! {
    static PENDING: Queue;
}

/// Run `job` after the current request's handler returns, or now on a
/// task of its own when no request is being handled.
pub fn defer<F>(job: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    // The job carries the request's trace header (X-Ray, Lambda's
    // recursion `Lineage`) to the call it makes.
    let mut job: Option<Job> = Some(Box::pin(crate::trace_header::propagate(job)));
    let _ = PENDING.try_with(|q| {
        if let Ok(mut q) = q.lock() {
            q.extend(job.take());
        }
    });
    if let Some(job) = job {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => drop(handle.spawn(job)),
            Err(_) => eprintln!("mws: deferred work dropped: no async runtime is running"),
        }
    }
}

/// Run `fut`, then every job it (or those jobs) deferred, in order.
pub async fn run<F: Future>(fut: F) -> F::Output {
    let queue: Queue = Arc::default();
    let out = PENDING.scope(queue.clone(), fut).await;
    loop {
        let jobs: Vec<Job> = match queue.lock() {
            Ok(mut q) => std::mem::take(&mut *q),
            Err(_) => break,
        };
        if jobs.is_empty() {
            break;
        }
        for job in jobs {
            PENDING.scope(queue.clone(), job).await;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn deferred_jobs_run_after_the_handler_in_order() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let l = log.clone();
        let out = run(async move {
            let l2 = l.clone();
            defer(async move {
                l2.lock().unwrap().push("first");
                let l3 = l2.clone();
                // Work deferred by deferred work runs too.
                defer(async move { l3.lock().unwrap().push("third") });
            });
            let l4 = l.clone();
            defer(async move { l4.lock().unwrap().push("second") });
            l.lock().unwrap().push("handler");
            7
        })
        .await;
        assert_eq!(out, 7);
        assert_eq!(*log.lock().unwrap(), vec!["handler", "first", "second", "third"]);
    }

    #[tokio::test]
    async fn outside_a_request_work_is_spawned() {
        let n = Arc::new(AtomicUsize::new(0));
        let m = n.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        defer(async move {
            m.fetch_add(1, Ordering::SeqCst);
            let _ = tx.send(());
        });
        rx.await.unwrap();
        assert_eq!(n.load(Ordering::SeqCst), 1);
    }
}
