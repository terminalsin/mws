//! The sign-in pages a browser opens during sign-in, served without a
//! signature:
//!
//! * `GET /_aws/sso-oidc/device[?user_code=ABCD-EFGH]`: the device
//!   verification page (`verificationUri` of `StartDeviceAuthorization`).
//!   `POST` it a form with `user_code`, `username` (an Identity Store user
//!   name or primary email) and optionally `decision=deny` to approve or
//!   deny the request.
//! * `GET /authorize?response_type=code&client_id=...&redirect_uri=...`:
//!   the authorization endpoint of the authorization code grant (with PKCE
//!   `code_challenge` and `code_challenge_method`, `state` and `scopes`).
//!   With a `username` parameter, or when its form is posted, it redirects
//!   to `redirect_uri` with a `code`. `client_id` is a registered client, or
//!   an application ARN for `CreateTokenWithIAM`.
//!
//! MWS keeps no passwords: naming a user signs them in.

use bytes::Bytes;
use http::{Method, StatusCode};
use mws_core::{HttpRequest, HttpResponse, RequestContext};
use mws_ssoadmin::generated::types::Grant;

use crate::state::{Approval, AuthCode};
use crate::tokens::{random, GRANT_AUTHORIZATION_CODE};
use crate::SsoOidc;

pub const DEVICE_PATH: &str = "/_aws/sso-oidc/device";
pub const AUTHORIZE_PATH: &str = "/authorize";
const CODE_SECONDS: i64 = 600;

pub fn is_signin_request(request: &HttpRequest) -> bool {
    let path = request.uri().path().trim_end_matches('/');
    let method_ok = matches!(*request.method(), Method::GET | Method::POST);
    if path == DEVICE_PATH {
        return method_ok;
    }
    // `/authorize` alone could be an S3 bucket: the authorization request
    // always names a client.
    path == AUTHORIZE_PATH
        && method_ok
        && (request.uri().query().unwrap_or_default().contains("client_id=")
            || (*request.method() == Method::POST && String::from_utf8_lossy(request.body()).contains("client_id=")))
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn page(status: StatusCode, title: &str, body: &str) -> HttpResponse {
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{t}</title><style>body{{font-family:sans-serif;max-width:32em;margin:3em auto}}label,input,button{{display:block;margin:.5em 0}}</style></head><body><h1>{t}</h1>{body}</body></html>",
        t = esc(title)
    );
    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Bytes::from(html))
        .expect("valid response")
}

fn params(request: &HttpRequest) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> =
        form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes()).into_owned().collect();
    if *request.method() == Method::POST {
        out.extend(form_urlencoded::parse(request.body()).into_owned());
    }
    out
}

fn get<'a>(p: &'a [(String, String)], key: &str) -> Option<&'a str> {
    p.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v.as_str()).filter(|v| !v.is_empty())
}

impl SsoOidc {
    pub(crate) fn signin(&self, ctx: &RequestContext, request: &HttpRequest) -> HttpResponse {
        let p = params(request);
        if request.uri().path().trim_end_matches('/') == DEVICE_PATH {
            self.device_page(ctx, request, &p)
        } else {
            self.authorize_page(ctx, request, &p)
        }
    }

    fn device_page(&self, ctx: &RequestContext, request: &HttpRequest, p: &[(String, String)]) -> HttpResponse {
        let code = get(p, "user_code").unwrap_or_default().to_ascii_uppercase();
        let username = get(p, "username");
        if *request.method() == Method::GET || username.is_none() {
            return page(
                StatusCode::OK,
                "Authorize request",
                &format!(
                    "<form method=\"post\"><label>Code <input name=\"user_code\" value=\"{}\"></label><label>Username <input name=\"username\" autofocus></label><button name=\"decision\" value=\"allow\">Allow access</button><button name=\"decision\" value=\"deny\">Deny</button></form>",
                    esc(&code)
                ),
            );
        }
        let username = username.unwrap_or_default();
        let deny = get(p, "decision") == Some("deny");
        let mut st = self.lock();
        let now = ctx.received_at;
        let Some((_, device)) = st.devices.iter_mut().find(|(_, d)| d.user_code == code && d.expires_at > now) else {
            return page(StatusCode::BAD_REQUEST, "Authorize request", "The code is invalid or has expired.");
        };
        if device.approval != Approval::Pending {
            return page(StatusCode::BAD_REQUEST, "Authorize request", "This request was already answered.");
        }
        if deny {
            device.approval = Approval::Denied;
            return page(StatusCode::OK, "Request denied", "You denied the request. You can close this window.");
        }
        let store = device.identity_store_id.clone();
        drop(st);
        let Some(user) = self.identity.find_user(&store, username) else {
            return page(StatusCode::BAD_REQUEST, "Authorize request", "No user with that username exists.");
        };
        let mut st = self.lock();
        if let Some(d) = st.devices.values_mut().find(|d| d.user_code == code) {
            d.approval = Approval::Approved { user_id: user.user_id };
        }
        page(StatusCode::OK, "Request approved", "You can close this window and return to your application.")
    }

    fn authorize_page(&self, ctx: &RequestContext, request: &HttpRequest, p: &[(String, String)]) -> HttpResponse {
        let bad = |m: &str| page(StatusCode::BAD_REQUEST, "Sign in", &esc(m));
        if get(p, "response_type") != Some("code") {
            return bad("response_type must be code.");
        }
        let (Some(client_id), Some(redirect_uri)) = (get(p, "client_id"), get(p, "redirect_uri")) else {
            return bad("client_id and redirect_uri are required.");
        };
        let requested: Vec<String> = get(p, "scopes")
            .or_else(|| get(p, "scope"))
            .map(|s| s.split([' ', ',']).filter(|s| !s.is_empty()).map(str::to_string).collect())
            .unwrap_or_default();
        // A registered client, or an application (for CreateTokenWithIAM).
        let (store, scopes) = if let Some(app) = self.admin.application_info(client_id) {
            let Some(Grant::AuthorizationCode(g)) = app.grants.get(GRANT_AUTHORIZATION_CODE) else {
                return bad("The application has no authorization code grant.");
            };
            if !g.redirect_uris.iter().flatten().any(|u| u == redirect_uri) {
                return bad("The redirect URI isn't registered for the application.");
            }
            let scopes = if requested.is_empty() { app.scopes.clone() } else { requested };
            (app.identity_store_id, scopes)
        } else {
            let Some(c) = self.lock().clients.get(client_id).cloned() else {
                return bad("The client isn't registered.");
            };
            if !c.grant_types.iter().any(|g| g == GRANT_AUTHORIZATION_CODE) {
                return bad("The client may not use the authorization code grant.");
            }
            if !c.redirect_uris.iter().any(|u| u == redirect_uri) {
                return bad("The redirect URI isn't registered for the client.");
            }
            let store = c.issuer_url.as_deref().and_then(|u| self.store_for_start_url(u));
            let Some(store) = store else {
                return bad("The client names no AWS access portal (issuerUrl) to sign in to.");
            };
            let scopes = match Self::scopes_for(&c, Some(requested)) {
                Ok(s) => s,
                Err(e) => return bad(&e.message),
            };
            (store, scopes)
        };
        let Some(username) = get(p, "username") else {
            let hidden: String = p
                .iter()
                .filter(|(k, _)| k != "username")
                .map(|(k, v)| format!("<input type=\"hidden\" name=\"{}\" value=\"{}\">", esc(k), esc(v)))
                .collect();
            return page(
                StatusCode::OK,
                "Sign in",
                &format!(
                    "<form method=\"post\" action=\"{AUTHORIZE_PATH}\">{hidden}<label>Username <input name=\"username\" autofocus></label><button>Sign in and allow access</button></form>"
                ),
            );
        };
        let _ = request;
        let Some(user) = self.identity.find_user(&store, username) else {
            return bad("No user with that username exists.");
        };
        let code = random(48);
        self.lock().codes.insert(
            code.clone(),
            AuthCode {
                client_id: client_id.to_string(),
                redirect_uri: redirect_uri.to_string(),
                code_challenge: get(p, "code_challenge").map(str::to_string),
                code_challenge_method: get(p, "code_challenge_method").map(str::to_string),
                scopes,
                identity_store_id: store,
                user_id: user.user_id,
                expires_at: ctx.received_at + chrono::Duration::seconds(CODE_SECONDS),
            },
        );
        let mut q = form_urlencoded::Serializer::new(String::new());
        q.append_pair("code", &code);
        if let Some(state) = get(p, "state") {
            q.append_pair("state", state);
        }
        let sep = if redirect_uri.contains('?') { '&' } else { '?' };
        http::Response::builder()
            .status(StatusCode::FOUND)
            .header(http::header::LOCATION, format!("{redirect_uri}{sep}{}", q.finish()))
            .body(Bytes::new())
            .expect("valid response")
    }
}
