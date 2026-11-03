//! The MWS control API under `/_mws/`. It is not an AWS API: requests are
//! unsigned and bodies are plain JSON.
//!
//! | Method & path                          | Effect                                         |
//! |----------------------------------------|------------------------------------------------|
//! | `GET /_mws/health`                     | liveness and the emulated services             |
//! | `GET /_mws/state`                      | export every service's state                   |
//! | `PUT /_mws/state`                      | replace every service's state                  |
//! | `POST /_mws/reset`                     | back to the baseline (startup scenario)        |
//! | `POST /_mws/reset?to=empty`            | back to a fresh emulator, ignoring the baseline|
//! | `POST /_mws/scenario[?baseline=true]`  | run a scenario; optionally make it the baseline|
//! | `GET /_mws/snapshots`                  | list named snapshots                           |
//! | `PUT /_mws/snapshots/{name}`           | save the current state under `name`            |
//! | `GET /_mws/snapshots/{name}`           | a snapshot's state document                    |
//! | `POST /_mws/snapshots/{name}/restore`  | replace the current state with a snapshot      |
//! | `DELETE /_mws/snapshots/{name}`        | delete a snapshot                              |
//! | `GET /_mws/clock`                      | the emulated time and its offset               |
//! | `POST /_mws/clock`                     | `{"advanceSeconds": n}` or `{"offsetSeconds": n}` moves the emulated clock forward |

use bytes::Bytes;
use http::Method;
use mws_core::{HttpRequest, HttpResponse};
use serde_json::{json, Value};

use crate::scenario::Scenario;
use crate::Gateway;

pub(crate) const PREFIX: &str = "/_mws/";

fn respond(status: u16, body: Value) -> HttpResponse {
    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Bytes::from(body.to_string()))
        .expect("valid response")
}

fn error(status: u16, message: impl Into<String>) -> HttpResponse {
    respond(status, json!({ "error": message.into() }))
}

fn ok() -> HttpResponse {
    respond(200, json!({ "status": "ok" }))
}

fn valid_snapshot_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn query_flag(request: &HttpRequest, key: &str) -> Option<String> {
    request.uri().query().and_then(|q| {
        q.split('&').filter_map(|kv| kv.split_once('=')).find(|(k, _)| *k == key).map(|(_, v)| v.to_string())
    })
}

fn body_json(request: &HttpRequest) -> Result<Value, String> {
    serde_json::from_slice(request.body()).map_err(|e| format!("request body is not JSON: {e}"))
}

impl Gateway {
    fn clock_doc(&self) -> HttpResponse {
        let now = self.emulated_time(chrono::Utc::now());
        respond(
            200,
            json!({
                "now": now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                "offsetSeconds": self.clock_offset().num_seconds(),
            }),
        )
    }

    pub(crate) async fn admin(&self, request: HttpRequest) -> HttpResponse {
        let path = request.uri().path().strip_prefix(PREFIX).unwrap_or_default().trim_end_matches('/').to_string();
        let segments: Vec<&str> = path.split('/').collect();
        let method = request.method().clone();
        match (&method, segments.as_slice()) {
            (&Method::GET, ["health"]) => self.health(),
            (&Method::GET, ["clock"]) => self.clock_doc(),
            (&Method::POST, ["clock"]) => {
                let doc = match body_json(&request) {
                    Ok(d) => d,
                    Err(e) => return error(400, e),
                };
                let seconds = |k: &str| doc.get(k).and_then(Value::as_i64);
                let offset = match (seconds("advanceSeconds"), seconds("offsetSeconds")) {
                    (Some(a), None) => self.clock_offset() + chrono::Duration::seconds(a),
                    (None, Some(o)) => chrono::Duration::seconds(o),
                    _ => return error(400, "give exactly one of advanceSeconds or offsetSeconds (whole seconds)"),
                };
                if offset < chrono::Duration::zero() {
                    return error(400, "the emulated clock cannot run behind the wall clock");
                }
                self.set_clock_offset(offset);
                self.clock_doc()
            }
            (&Method::GET, ["state"]) => {
                let _gate = self.state.gate.read().await;
                respond(200, self.export_state())
            }
            (&Method::PUT, ["state"]) => {
                let doc = match body_json(&request) {
                    Ok(d) => d,
                    Err(e) => return error(400, e),
                };
                let _gate = self.state.gate.write().await;
                match self.import_state(&doc) {
                    Ok(()) => {
                        self.flush_locked();
                        ok()
                    }
                    Err(e) => error(400, e),
                }
            }
            (&Method::POST, ["reset"]) => {
                let _gate = self.state.gate.write().await;
                let result = match query_flag(&request, "to").as_deref() {
                    None | Some("baseline") => self.reset_to_baseline(),
                    Some("empty") => {
                        self.reset_all();
                        Ok(())
                    }
                    Some(other) => return error(400, format!("unknown reset target {other:?}; use baseline or empty")),
                };
                match result {
                    Ok(()) => {
                        self.flush_locked();
                        ok()
                    }
                    Err(e) => error(500, e),
                }
            }
            (&Method::POST, ["scenario"]) => {
                let text = String::from_utf8_lossy(request.body()).into_owned();
                let scenario = match Scenario::parse(&text) {
                    Ok(s) => s,
                    Err(e) => return error(400, e),
                };
                let make_baseline = query_flag(&request, "baseline").as_deref() == Some("true");
                let _gate = self.state.gate.write().await;
                match self.apply_scenario(&scenario).await {
                    Ok(outputs) => {
                        if make_baseline {
                            if let Err(e) = self.set_baseline_to_current() {
                                return error(500, e);
                            }
                        }
                        self.flush_locked();
                        respond(200, json!({ "outputs": outputs }))
                    }
                    Err(e) => {
                        respond(400, json!({ "error": e.to_string(), "step": e.step.map(|i| i + 1), "code": e.code }))
                    }
                }
            }
            (&Method::GET, ["snapshots"]) => match self.snapshots() {
                Ok(list) => respond(
                    200,
                    json!({ "snapshots": list.iter().map(|s| json!({
                        "name": s.name,
                        "createdAt": s.created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    })).collect::<Vec<_>>() }),
                ),
                Err(e) => error(500, e),
            },
            (m, ["snapshots", name, rest @ ..]) => {
                if !valid_snapshot_name(name) {
                    return error(400, "snapshot names are 1-128 characters of A-Z, a-z, 0-9, '-', '_' and '.'");
                }
                match (m, rest) {
                    (&Method::PUT, []) | (&Method::POST, []) => {
                        let _gate = self.state.gate.read().await;
                        match self.save_snapshot(name) {
                            Ok(info) => respond(
                                200,
                                json!({ "name": info.name, "createdAt": info.created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true) }),
                            ),
                            Err(e) => error(500, e),
                        }
                    }
                    (&Method::GET, []) => match self.snapshot(name) {
                        Ok(Some(doc)) => respond(200, doc),
                        Ok(None) => error(404, format!("no snapshot named {name}")),
                        Err(e) => error(500, e),
                    },
                    (&Method::DELETE, []) => match self.delete_snapshot(name) {
                        Ok(true) => ok(),
                        Ok(false) => error(404, format!("no snapshot named {name}")),
                        Err(e) => error(500, e),
                    },
                    (&Method::POST, ["restore"]) => {
                        let doc = match self.snapshot(name) {
                            Ok(Some(doc)) => doc,
                            Ok(None) => return error(404, format!("no snapshot named {name}")),
                            Err(e) => return error(500, e),
                        };
                        let _gate = self.state.gate.write().await;
                        match self.import_state(&doc) {
                            Ok(()) => {
                                self.flush_locked();
                                ok()
                            }
                            Err(e) => error(500, e),
                        }
                    }
                    _ => error(404, format!("no control endpoint {method} {}", request.uri().path())),
                }
            }
            _ => error(404, format!("no control endpoint {method} {}", request.uri().path())),
        }
    }
}
