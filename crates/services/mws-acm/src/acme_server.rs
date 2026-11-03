//! The ACME (RFC 8555) server behind managed ACME endpoints.
//!
//! Each endpoint serves its directory at
//! `<MWS endpoint>/_acme/<endpoint id>/directory`. External account
//! binding is required: clients register with the key id and HMAC key from
//! `GetAcmeExternalAccountBindingCredentials`. Endpoints are `PRE_APPROVED`,
//! so identifiers covered by a `VALID` domain validation of the endpoint
//! are authorized up front and orders go straight to `ready`; anything else
//! is a `rejectedIdentifier`. Finalized orders are issued by the same CA as
//! ACM's public certificates and appear in ACM with key pair origin `ACME`.
//!
//! Requests are made as the binding's IAM role: ACM assumes it as
//! `acm.amazonaws.com` (its trust policy must allow that) and the role
//! needs `acm:RequestCertificate` to order and `acm:RevokeCertificate` to
//! revoke.

use bytes::Bytes;
use chrono::{DateTime, Duration, Utc};
use http::{Method, StatusCode};
use mws_core::{ConditionContext, HttpRequest, HttpResponse, RequestContext};
use serde_json::{json, Value};

use crate::jws::{self, Jws};
use crate::state::{AcmeAccount, AcmeEndpoint, AcmeOrder, Certificate, DomainValidation};
use crate::validation::{self, PUBLIC_VALIDITY_DAYS};
use crate::{pki, Acm};

pub const PREFIX: &str = "/_acme";

pub fn is_acme_request(request: &HttpRequest) -> bool {
    request.uri().path().starts_with(&format!("{PREFIX}/"))
}

const ERR: &str = "urn:ietf:params:acme:error:";

struct Problem {
    status: StatusCode,
    kind: &'static str,
    detail: String,
}

fn problem(status: StatusCode, kind: &'static str, detail: impl Into<String>) -> Problem {
    Problem { status, kind, detail: detail.into() }
}

fn malformed(detail: impl Into<String>) -> Problem {
    problem(StatusCode::BAD_REQUEST, "malformed", detail)
}

fn unauthorized(detail: impl Into<String>) -> Problem {
    problem(StatusCode::FORBIDDEN, "unauthorized", detail)
}

/// A successful ACME response.
struct Reply {
    status: StatusCode,
    body: Bytes,
    content_type: &'static str,
    location: Option<String>,
}

fn reply(status: StatusCode, body: Value) -> Reply {
    Reply { status, body: Bytes::from(body.to_string()), content_type: "application/json", location: None }
}

fn ts(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// URLs of one endpoint's resources.
struct Urls {
    base: String,
}

impl Urls {
    fn new(endpoint: &AcmeEndpoint) -> Self {
        Self { base: endpoint.url.trim_end_matches("/directory").to_string() }
    }
    fn at(&self, path: &str) -> String {
        format!("{}/{path}", self.base)
    }
    fn account(&self, id: &str) -> String {
        self.at(&format!("acct/{id}"))
    }
    fn order(&self, id: &str) -> String {
        self.at(&format!("order/{id}"))
    }
}

fn revocation_reason(code: i64) -> &'static str {
    match code {
        1 => "KEY_COMPROMISE",
        2 => "CA_COMPROMISE",
        3 => "AFFILIATION_CHANGED",
        4 => "SUPERSEDED",
        5 => "CESSATION_OF_OPERATION",
        6 => "CERTIFICATE_HOLD",
        8 => "REMOVE_FROM_CRL",
        9 => "PRIVILEGE_WITHDRAWN",
        10 => "A_A_COMPROMISE",
        _ => "UNSPECIFIED",
    }
}

/// Whether a domain validation covers identifier `name`.
fn covers(dv: &crate::state::AcmeDomainValidation, name: &str) -> bool {
    if dv.status != "VALID" {
        return false;
    }
    let d = &dv.domain;
    if let Some(rest) = name.strip_prefix("*.") {
        return (dv.wildcards && rest == d) || (dv.wildcards && dv.subdomains && rest.ends_with(&format!(".{d}")));
    }
    (dv.exact && name == d) || (dv.subdomains && name.ends_with(&format!(".{d}")))
}

impl Acm {
    fn new_nonce(&self) -> String {
        let nonce = jws::b64(&rand::random::<[u8; 18]>());
        let mut st = self.lock();
        if st.nonces.len() > 10_000 {
            st.nonces.clear();
        }
        st.nonces.insert(nonce.clone());
        nonce
    }

    fn respond(&self, urls: Option<&Urls>, result: Result<Reply, Problem>) -> HttpResponse {
        let nonce = self.new_nonce();
        let mut builder =
            http::Response::builder().header("Replay-Nonce", nonce).header(http::header::CACHE_CONTROL, "no-store");
        if let Some(u) = urls {
            builder = builder.header("Link", format!("<{}>;rel=\"index\"", u.at("directory")));
        }
        let response = match result {
            Ok(r) => {
                builder = builder.status(r.status).header(http::header::CONTENT_TYPE, r.content_type);
                if let Some(loc) = r.location {
                    builder = builder.header(http::header::LOCATION, loc);
                }
                builder.body(r.body)
            }
            Err(p) => {
                let body = json!({"type": format!("{ERR}{}", p.kind), "detail": p.detail, "status": p.status.as_u16()});
                builder
                    .status(p.status)
                    .header(http::header::CONTENT_TYPE, "application/problem+json")
                    .body(Bytes::from(body.to_string()))
            }
        };
        response.expect("valid response")
    }

    pub(crate) async fn acme_http(&self, ctx: &RequestContext, request: &HttpRequest) -> HttpResponse {
        let path = request.uri().path().to_string();
        let rest = path.strip_prefix(PREFIX).unwrap_or_default().trim_start_matches('/');
        let (endpoint_id, route) = rest.split_once('/').unwrap_or((rest, ""));
        let endpoint = {
            let st = self.lock();
            st.endpoints.values().find(|e| e.id == endpoint_id && e.status == "ACTIVE").cloned()
        };
        let Some(endpoint) = endpoint else {
            return self.respond(None, Err(problem(StatusCode::NOT_FOUND, "malformed", "No such ACME endpoint.")));
        };
        let urls = Urls::new(&endpoint);
        let method = request.method().clone();
        let result = match (method.clone(), route) {
            (Method::GET, "directory") => Ok(self.directory(&endpoint, &urls)),
            (Method::HEAD | Method::GET, "new-nonce") => Ok(Reply {
                status: if method == Method::HEAD { StatusCode::OK } else { StatusCode::NO_CONTENT },
                body: Bytes::new(),
                content_type: "application/json",
                location: None,
            }),
            (Method::POST, route) => self.acme_post(ctx, &endpoint, &urls, &path, route, request.body()).await,
            _ => Err(problem(StatusCode::METHOD_NOT_ALLOWED, "malformed", "Method not allowed.")),
        };
        self.respond(Some(&urls), result)
    }

    fn directory(&self, endpoint: &AcmeEndpoint, urls: &Urls) -> Reply {
        reply(
            StatusCode::OK,
            json!({
                "newNonce": urls.at("new-nonce"),
                "newAccount": urls.at("new-account"),
                "newOrder": urls.at("new-order"),
                "revokeCert": urls.at("revoke-cert"),
                "keyChange": urls.at("key-change"),
                "meta": {
                    "externalAccountRequired": true,
                    "website": "https://aws.amazon.com/certificate-manager/",
                    "caaIdentities": ["amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com"],
                    "profiles": {},
                    "contactRequired": endpoint.contact == "REQUIRED",
                }
            }),
        )
    }

    /// Check the JWS envelope: nonce, URL, and the signing key (a new
    /// `jwk` for new-account, otherwise the account in `kid`).
    fn authenticate(
        &self,
        urls: &Urls,
        endpoint: &AcmeEndpoint,
        path: &str,
        jws: &Jws,
        expect_jwk: bool,
    ) -> Result<Option<AcmeAccount>, Problem> {
        let nonce = jws.header("nonce").ok_or_else(|| problem(StatusCode::BAD_REQUEST, "badNonce", "No nonce."))?;
        if !self.lock().nonces.remove(nonce) {
            return Err(problem(StatusCode::BAD_REQUEST, "badNonce", "The nonce is not valid or was already used."));
        }
        let url = jws.header("url").ok_or_else(|| unauthorized("The JWS has no url header."))?;
        let url_path = url.find("://").and_then(|i| url[i + 3..].find('/').map(|j| &url[i + 3 + j..])).unwrap_or(url);
        if url_path != path {
            return Err(unauthorized(format!("The JWS url {url} does not match the request URL.")));
        }
        let alg = jws.header("alg").unwrap_or_default();
        if !["ES256", "ES384", "RS256"].contains(&alg) {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                "badSignatureAlgorithm",
                format!("Signature algorithm {alg} is not supported. Use ES256, ES384 or RS256."),
            ));
        }
        let has_jwk = jws.protected.get("jwk").is_some();
        let has_kid = jws.protected.get("kid").is_some();
        if has_jwk == has_kid {
            return Err(malformed("The JWS must carry exactly one of jwk and kid."));
        }
        if expect_jwk {
            let jwk = jws.protected.get("jwk").ok_or_else(|| malformed("This request must be signed with a jwk."))?;
            if !jws::supported_key(jwk) {
                return Err(problem(StatusCode::BAD_REQUEST, "badPublicKey", "The account key is not supported."));
            }
            if !jws.verify(jwk) {
                return Err(malformed("The JWS signature is invalid."));
            }
            return Ok(None);
        }
        let kid = jws.header("kid").ok_or_else(|| malformed("This request must be signed with a kid."))?;
        let account = {
            let st = self.lock();
            st.acme_accounts.values().find(|a| a.endpoint_arn == endpoint.arn && a.url == kid).cloned()
        };
        let account = account
            .ok_or_else(|| problem(StatusCode::BAD_REQUEST, "accountDoesNotExist", format!("No account {kid}.")))?;
        if !jws.verify(&account.jwk) {
            return Err(malformed("The JWS signature is invalid."));
        }
        if account.status != "VALID" {
            return Err(unauthorized(format!(
                "Account {} is {}.",
                urls.account(&account.id),
                account.status.to_lowercase()
            )));
        }
        Ok(Some(account))
    }

    async fn acme_post(
        &self,
        ctx: &RequestContext,
        endpoint: &AcmeEndpoint,
        urls: &Urls,
        path: &str,
        route: &str,
        body: &Bytes,
    ) -> Result<Reply, Problem> {
        let value: Value = serde_json::from_slice(body).map_err(|_| malformed("The request body is not JSON."))?;
        let jws = Jws::parse(&value).ok_or_else(|| malformed("The request body is not a flattened JWS."))?;
        let now = ctx.received_at;
        if route == "new-account" {
            self.authenticate(urls, endpoint, path, &jws, true)?;
            return self.new_account(endpoint, urls, &jws, now);
        }
        let account = self.authenticate(urls, endpoint, path, &jws, false)?.expect("kid-signed");
        let parts: Vec<&str> = route.split('/').collect();
        match parts.as_slice() {
            ["acct", id] if *id == account.id => self.update_account(urls, &account, &jws),
            ["acct", _] => Err(unauthorized("The account URL does not match the signing account.")),
            ["new-order"] => self.new_order(ctx, endpoint, urls, &account, &jws, now).await,
            ["order", id] => self.order_reply(urls, &account, id, StatusCode::OK),
            ["order", id, "finalize"] => self.finalize(ctx, endpoint, urls, &account, id, &jws, now).await,
            ["authz", order, idx] => self.authz(urls, &account, order, idx).map(|v| reply(StatusCode::OK, v)),
            ["chall", order, idx] => {
                let authz = self.authz(urls, &account, order, idx)?;
                let mut challenge = authz["challenges"][0].clone();
                challenge["status"] = json!("valid");
                Ok(Reply { location: None, ..reply(StatusCode::OK, challenge) })
            }
            ["cert", id] => self.download(endpoint, &account, id),
            ["revoke-cert"] => self.revoke(ctx, endpoint, &account, &jws, now).await,
            ["key-change"] => self.key_change(urls, endpoint, &account, &jws),
            _ => Err(problem(StatusCode::NOT_FOUND, "malformed", format!("Unknown resource {route}."))),
        }
    }

    fn account_json(&self, urls: &Urls, a: &AcmeAccount) -> Value {
        json!({
            "status": a.status.to_lowercase(),
            "contact": a.contacts,
            "orders": urls.at(&format!("acct/{}/orders", a.id)),
            "createdAt": ts(a.created_at),
        })
    }

    fn new_account(
        &self,
        endpoint: &AcmeEndpoint,
        urls: &Urls,
        jws: &Jws,
        now: DateTime<Utc>,
    ) -> Result<Reply, Problem> {
        let jwk = jws.protected.get("jwk").cloned().unwrap_or_default();
        let thumbprint = jws::thumbprint(&jwk).unwrap_or_default();
        let payload = jws.payload_json().unwrap_or_else(|| json!({}));
        let existing = {
            let st = self.lock();
            st.acme_accounts.values().find(|a| a.endpoint_arn == endpoint.arn && a.thumbprint == thumbprint).cloned()
        };
        if let Some(a) = existing {
            return Ok(Reply { location: Some(a.url.clone()), ..reply(StatusCode::OK, self.account_json(urls, &a)) });
        }
        if payload.get("onlyReturnExisting").and_then(Value::as_bool) == Some(true) {
            return Err(problem(StatusCode::BAD_REQUEST, "accountDoesNotExist", "No account exists for this key."));
        }
        let contacts: Vec<String> = payload
            .get("contact")
            .and_then(Value::as_array)
            .map(|c| c.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        if endpoint.contact == "REQUIRED" && contacts.is_empty() {
            return Err(problem(StatusCode::BAD_REQUEST, "invalidContact", "This endpoint requires a contact."));
        }
        if let Some(bad) = contacts.iter().find(|c| !c.starts_with("mailto:")) {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                "unsupportedContact",
                format!("Contact {bad} is not a mailto: URL."),
            ));
        }
        let eab_value = payload.get("externalAccountBinding").ok_or_else(|| {
            problem(
                StatusCode::BAD_REQUEST,
                "externalAccountRequired",
                "This endpoint requires external account binding.",
            )
        })?;
        let eab_jws = Jws::parse(eab_value).ok_or_else(|| malformed("externalAccountBinding is not a JWS."))?;
        let kid = eab_jws.header("kid").unwrap_or_default().to_string();
        let eab = {
            let st = self.lock();
            st.eabs.values().find(|e| e.endpoint_arn == endpoint.arn && e.key_id == kid).cloned()
        };
        let eab = eab.ok_or_else(|| unauthorized(format!("Unknown external account binding key id {kid}.")))?;
        if eab.revoked_at.is_some() {
            return Err(unauthorized("The external account binding has been revoked."));
        }
        if eab.expires_at.is_some_and(|t| t <= now) {
            return Err(unauthorized("The external account binding has expired."));
        }
        let mac = jws::unb64(&eab.mac_key).unwrap_or_default();
        if !eab_jws.verify_hmac(&mac) {
            return Err(unauthorized("The external account binding signature is invalid."));
        }
        if eab_jws.header("url") != jws.header("url") {
            return Err(unauthorized("The external account binding url does not match."));
        }
        let bound_key: Value = serde_json::from_slice(&eab_jws.payload).unwrap_or_default();
        if jws::thumbprint(&bound_key).as_deref() != Some(thumbprint.as_str()) {
            return Err(unauthorized("The external account binding is for a different key."));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let account = AcmeAccount {
            id: id.clone(),
            endpoint_arn: endpoint.arn.clone(),
            url: urls.account(&id),
            jwk,
            thumbprint,
            status: "VALID".into(),
            contacts,
            eab_arn: Some(eab.arn.clone()),
            created_at: now,
        };
        {
            let mut st = self.lock();
            if let Some(e) = st.eabs.get_mut(&eab.arn) {
                e.last_used_at = Some(now);
            }
            st.acme_accounts.insert(id, account.clone());
        }
        Ok(Reply {
            location: Some(account.url.clone()),
            ..reply(StatusCode::CREATED, self.account_json(urls, &account))
        })
    }

    fn update_account(&self, urls: &Urls, account: &AcmeAccount, jws: &Jws) -> Result<Reply, Problem> {
        let mut updated = account.clone();
        if let Some(payload) = jws.payload_json() {
            if let Some(c) = payload.get("contact").and_then(Value::as_array) {
                updated.contacts = c.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
            }
            match payload.get("status").and_then(Value::as_str) {
                Some("deactivated") => updated.status = "DEACTIVATED".into(),
                Some(other) => return Err(malformed(format!("Cannot set account status to {other}."))),
                None => {}
            }
        }
        self.lock().acme_accounts.insert(updated.id.clone(), updated.clone());
        Ok(Reply { location: Some(updated.url.clone()), ..reply(StatusCode::OK, self.account_json(urls, &updated)) })
    }

    /// A request context for the binding's role, as ACM assumes it.
    fn role_context(
        &self,
        ctx: &RequestContext,
        endpoint: &AcmeEndpoint,
        account: &AcmeAccount,
    ) -> Result<Option<RequestContext>, Problem> {
        let Some(sts) = &self.sts else { return Ok(None) };
        let role_arn = {
            let st = self.lock();
            account.eab_arn.as_ref().and_then(|a| st.eabs.get(a)).map(|e| e.role_arn.clone())
        };
        let Some(role_arn) = role_arn else {
            return Err(unauthorized("The account's external account binding no longer exists."));
        };
        let assume = mws_sts::ServiceAssume {
            role_arn: &role_arn,
            service_principal: "acm.amazonaws.com",
            session_name: "acm-acme",
            duration_seconds: 900,
            source_account: Some(&endpoint.account),
            source_arn: Some(&endpoint.arn),
            now: ctx.received_at,
        };
        let creds = sts
            .assume_role_as_service(&assume)
            .map_err(|_| unauthorized(format!("ACM could not assume role {role_arn}.")))?;
        let resolved = sts
            .credential_store()
            .resolve(&creds.access_key_id, Some(&creds.session_token), ctx.received_at)
            .ok()
            .flatten()
            .ok_or_else(|| unauthorized(format!("ACM could not assume role {role_arn}.")))?;
        let region = endpoint.arn.split(':').nth(3).unwrap_or(&ctx.region).to_string();
        Ok(Some(RequestContext { caller: resolved.caller, region, source_ip: None, ..ctx.clone() }))
    }

    fn order_json(&self, urls: &Urls, o: &AcmeOrder) -> Value {
        let mut v = json!({
            "status": o.status,
            "expires": ts(o.expires),
            "identifiers": o.identifiers.iter().map(|i| json!({"type": "dns", "value": i})).collect::<Vec<_>>(),
            "authorizations": (0..o.identifiers.len()).map(|i| urls.at(&format!("authz/{}/{i}", o.id))).collect::<Vec<_>>(),
            "finalize": urls.at(&format!("order/{}/finalize", o.id)),
        });
        if let Some(arn) = &o.certificate_arn {
            let id = arn.rsplit('/').next().unwrap_or_default();
            v["certificate"] = json!(urls.at(&format!("cert/{id}")));
        }
        if let Some(e) = &o.error {
            v["error"] = e.clone();
        }
        v
    }

    async fn new_order(
        &self,
        ctx: &RequestContext,
        endpoint: &AcmeEndpoint,
        urls: &Urls,
        account: &AcmeAccount,
        jws: &Jws,
        now: DateTime<Utc>,
    ) -> Result<Reply, Problem> {
        let payload = jws.payload_json().ok_or_else(|| malformed("new-order needs a payload."))?;
        let mut identifiers = Vec::new();
        for i in payload.get("identifiers").and_then(Value::as_array).cloned().unwrap_or_default() {
            if i.get("type").and_then(Value::as_str) != Some("dns") {
                return Err(problem(
                    StatusCode::BAD_REQUEST,
                    "unsupportedIdentifier",
                    "Only dns identifiers are supported.",
                ));
            }
            let v = i.get("value").and_then(Value::as_str).unwrap_or_default().to_ascii_lowercase();
            if v.is_empty() {
                return Err(malformed("An identifier has no value."));
            }
            if !identifiers.contains(&v) {
                identifiers.push(v);
            }
        }
        if identifiers.is_empty() {
            return Err(malformed("The order has no identifiers."));
        }
        if payload.get("notBefore").is_some() || payload.get("notAfter").is_some() {
            return Err(malformed("This server does not support notBefore and notAfter in orders."));
        }
        if let Some(role_ctx) = self.role_context(ctx, endpoint, account)? {
            let mut cond = ConditionContext::new();
            cond.insert("acm:DomainNames".into(), identifiers.clone());
            role_ctx.authorize("acm:RequestCertificate", "*", cond).map_err(|e| unauthorized(e.message))?;
        }
        let rejected: Vec<&String> = {
            let st = self.lock();
            identifiers
                .iter()
                .filter(|name| {
                    !st.domain_validations.values().any(|dv| dv.endpoint_arn == endpoint.arn && covers(dv, name))
                })
                .collect()
        };
        if let Some(name) = rejected.first() {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                "rejectedIdentifier",
                format!("The identifier {name} is not covered by a valid domain validation of this ACME endpoint."),
            ));
        }
        let order = AcmeOrder {
            id: uuid::Uuid::new_v4().simple().to_string(),
            endpoint_arn: endpoint.arn.clone(),
            account_id: account.id.clone(),
            identifiers,
            status: "ready".into(),
            expires: now + Duration::days(7),
            certificate_arn: None,
            error: None,
        };
        self.lock().acme_orders.insert(order.id.clone(), order.clone());
        Ok(Reply { location: Some(urls.order(&order.id)), ..reply(StatusCode::CREATED, self.order_json(urls, &order)) })
    }

    fn order_for(&self, account: &AcmeAccount, id: &str) -> Result<AcmeOrder, Problem> {
        let st = self.lock();
        st.acme_orders
            .get(id)
            .filter(|o| o.account_id == account.id)
            .cloned()
            .ok_or_else(|| problem(StatusCode::NOT_FOUND, "malformed", format!("No order {id}.")))
    }

    fn order_reply(&self, urls: &Urls, account: &AcmeAccount, id: &str, status: StatusCode) -> Result<Reply, Problem> {
        let o = self.order_for(account, id)?;
        Ok(Reply { location: Some(urls.order(&o.id)), ..reply(status, self.order_json(urls, &o)) })
    }

    fn authz(&self, urls: &Urls, account: &AcmeAccount, order: &str, idx: &str) -> Result<Value, Problem> {
        let o = self.order_for(account, order)?;
        let i: usize = idx.parse().map_err(|_| malformed("Bad authorization index."))?;
        let name = o
            .identifiers
            .get(i)
            .ok_or_else(|| problem(StatusCode::NOT_FOUND, "malformed", "No such authorization."))?;
        let wildcard = name.starts_with("*.");
        let mut v = json!({
            "identifier": {"type": "dns", "value": validation::base_domain(name)},
            "status": "valid",
            "expires": ts(o.expires),
            "challenges": [{
                "type": "dns-01",
                "url": urls.at(&format!("chall/{order}/{i}")),
                "status": "valid",
                "token": jws::b64(format!("{order}/{i}").as_bytes()),
            }],
        });
        if wildcard {
            v["wildcard"] = json!(true);
        }
        Ok(v)
    }

    #[allow(clippy::too_many_arguments)]
    async fn finalize(
        &self,
        ctx: &RequestContext,
        endpoint: &AcmeEndpoint,
        urls: &Urls,
        account: &AcmeAccount,
        id: &str,
        jws: &Jws,
        now: DateTime<Utc>,
    ) -> Result<Reply, Problem> {
        let order = self.order_for(account, id)?;
        if order.status != "ready" {
            return Err(problem(StatusCode::FORBIDDEN, "orderNotReady", format!("The order is {}.", order.status)));
        }
        if let Some(role_ctx) = self.role_context(ctx, endpoint, account)? {
            let mut cond = ConditionContext::new();
            cond.insert("acm:DomainNames".into(), order.identifiers.clone());
            role_ctx.authorize("acm:RequestCertificate", "*", cond).map_err(|e| unauthorized(e.message))?;
        }
        let payload = jws.payload_json().ok_or_else(|| malformed("finalize needs a payload."))?;
        let der = payload
            .get("csr")
            .and_then(Value::as_str)
            .and_then(jws::unb64)
            .ok_or_else(|| problem(StatusCode::BAD_REQUEST, "badCSR", "The CSR is missing or not base64url."))?;
        let csr = pki::parse_csr_der(&der).ok_or_else(|| {
            problem(StatusCode::BAD_REQUEST, "badCSR", "The CSR is malformed or its signature is invalid.")
        })?;
        let mut names = csr.dns_names.clone();
        if let Some(cn) = &csr.common_name {
            let cn = cn.to_ascii_lowercase();
            if !names.contains(&cn) {
                names.push(cn);
            }
        }
        let mut wanted = order.identifiers.clone();
        wanted.sort();
        names.sort();
        names.dedup();
        if names != wanted {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                "badCSR",
                "The CSR's names do not match the order's identifiers.",
            ));
        }
        if !endpoint.allowed_key_algorithms.contains(&csr.key_algorithm) {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                "badCSR",
                format!(
                    "Key algorithm {} is not allowed by this endpoint ({}).",
                    csr.key_algorithm,
                    endpoint.allowed_key_algorithms.join(", ")
                ),
            ));
        }
        let common_name =
            csr.common_name.clone().map(|c| c.to_ascii_lowercase()).unwrap_or_else(|| order.identifiers[0].clone());
        let mut sans = vec![common_name.clone()];
        sans.extend(order.identifiers.iter().filter(|i| **i != common_name).cloned());
        let region = endpoint.arn.split(':').nth(3).unwrap_or(&ctx.region).to_string();
        let arn =
            format!("arn:{}:acm:{region}:{}:certificate/{}", ctx.partition, endpoint.account, uuid::Uuid::new_v4());
        let mut st = self.lock();
        let ca = validation::issuer(&mut st, &csr.key_algorithm, now)
            .map_err(|e| problem(StatusCode::INTERNAL_SERVER_ERROR, "serverInternal", e.message))?;
        let pem = pki::issue_leaf(
            &ca,
            &pki::LeafRequest {
                common_name: &common_name,
                names: &sans,
                spki_der: &csr.spki_der,
                not_before: now,
                not_after: now + Duration::days(PUBLIC_VALIDITY_DAYS),
            },
        )
        .map_err(|e| problem(StatusCode::INTERNAL_SERVER_ERROR, "serverInternal", e.message))?;
        let cert = Certificate {
            arn: arn.clone(),
            account: endpoint.account.clone(),
            region,
            domain_name: common_name,
            sans: sans.clone(),
            ty: "AMAZON_ISSUED".into(),
            status: "ISSUED".into(),
            failure_reason: None,
            created_at: Some(now),
            issued_at: Some(now),
            imported_at: None,
            revoked_at: None,
            revocation_reason: None,
            key_algorithm: csr.key_algorithm.clone(),
            ca_arn: None,
            ct_logging: "ENABLED".into(),
            export_option: "DISABLED".into(),
            managed_by: None,
            validations: sans
                .iter()
                .map(|d| DomainValidation {
                    domain: d.clone(),
                    validation_domain: validation::base_domain(d).to_string(),
                    method: None,
                    status: "SUCCESS".into(),
                    requested_method: None,
                    requested_status: None,
                })
                .collect(),
            method_update: None,
            cert_pem: Some(pem),
            chain_pem: Some(ca.cert_pem.clone()),
            key_der: None,
            imported_key: None,
            exported: false,
            renewal: None,
            tags: endpoint.certificate_tags.clone(),
            origin: "ACME".into(),
            acme_endpoint_arn: Some(endpoint.arn.clone()),
            acme_account_id: Some(account.id.clone()),
            pca_certificate_arn: None,
            emails_sent: 0,
        };
        st.certificates.insert(arn.clone(), cert);
        let o = st.acme_orders.get_mut(&order.id).expect("order exists");
        o.status = "valid".into();
        o.certificate_arn = Some(arn);
        let o = o.clone();
        drop(st);
        Ok(Reply { location: Some(urls.order(&o.id)), ..reply(StatusCode::OK, self.order_json(urls, &o)) })
    }

    fn download(&self, endpoint: &AcmeEndpoint, account: &AcmeAccount, id: &str) -> Result<Reply, Problem> {
        let st = self.lock();
        let cert = st
            .certificates
            .values()
            .find(|c| {
                c.acme_endpoint_arn.as_deref() == Some(endpoint.arn.as_str())
                    && c.acme_account_id.as_deref() == Some(account.id.as_str())
                    && c.arn.rsplit('/').next() == Some(id)
            })
            .ok_or_else(|| problem(StatusCode::NOT_FOUND, "malformed", format!("No certificate {id}.")))?;
        let body =
            format!("{}{}", cert.cert_pem.clone().unwrap_or_default(), cert.chain_pem.clone().unwrap_or_default());
        Ok(Reply {
            status: StatusCode::OK,
            body: Bytes::from(body),
            content_type: "application/pem-certificate-chain",
            location: None,
        })
    }

    async fn revoke(
        &self,
        ctx: &RequestContext,
        endpoint: &AcmeEndpoint,
        account: &AcmeAccount,
        jws: &Jws,
        now: DateTime<Utc>,
    ) -> Result<Reply, Problem> {
        let payload = jws.payload_json().ok_or_else(|| malformed("revoke-cert needs a payload."))?;
        let der = payload
            .get("certificate")
            .and_then(Value::as_str)
            .and_then(jws::unb64)
            .ok_or_else(|| malformed("The certificate is missing or not base64url."))?;
        let reason = payload.get("reason").and_then(Value::as_i64).unwrap_or(0);
        if !(0..=10).contains(&reason) || reason == 7 {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                "badRevocationReason",
                format!("Reason {reason} is not allowed."),
            ));
        }
        let arn = {
            let st = self.lock();
            st.certificates
                .values()
                .find(|c| {
                    c.acme_endpoint_arn.as_deref() == Some(endpoint.arn.as_str())
                        && c.cert_pem.as_deref().and_then(pki::first_cert_der).as_deref() == Some(der.as_slice())
                })
                .map(|c| (c.arn.clone(), c.acme_account_id.clone(), c.status.clone()))
        };
        let Some((arn, owner, status)) = arn else {
            return Err(problem(StatusCode::NOT_FOUND, "malformed", "This endpoint did not issue that certificate."));
        };
        if owner.as_deref() != Some(account.id.as_str()) {
            return Err(unauthorized("The certificate was issued to a different account."));
        }
        if status == "REVOKED" {
            return Err(problem(StatusCode::BAD_REQUEST, "alreadyRevoked", "The certificate is already revoked."));
        }
        if let Some(role_ctx) = self.role_context(ctx, endpoint, account)? {
            role_ctx
                .authorize("acm:RevokeCertificate", &arn, ConditionContext::new())
                .map_err(|e| unauthorized(e.message))?;
        }
        if let Some(c) = self.lock().certificates.get_mut(&arn) {
            c.status = "REVOKED".into();
            c.revoked_at = Some(now);
            c.revocation_reason = Some(revocation_reason(reason).into());
        }
        Ok(Reply { status: StatusCode::OK, body: Bytes::new(), content_type: "application/json", location: None })
    }

    fn key_change(
        &self,
        urls: &Urls,
        endpoint: &AcmeEndpoint,
        account: &AcmeAccount,
        outer: &Jws,
    ) -> Result<Reply, Problem> {
        let inner_value: Value =
            serde_json::from_slice(&outer.payload).map_err(|_| malformed("key-change needs an inner JWS."))?;
        let inner = Jws::parse(&inner_value).ok_or_else(|| malformed("key-change needs an inner JWS."))?;
        let new_key =
            inner.protected.get("jwk").cloned().ok_or_else(|| malformed("The inner JWS must carry a jwk."))?;
        if inner.header("url") != outer.header("url") || !jws::supported_key(&new_key) || !inner.verify(&new_key) {
            return Err(malformed("The inner JWS is invalid."));
        }
        let payload = inner.payload_json().unwrap_or_default();
        if payload.get("account").and_then(Value::as_str) != Some(account.url.as_str())
            || payload.get("oldKey").and_then(jws::thumbprint).as_deref() != Some(account.thumbprint.as_str())
        {
            return Err(malformed("The key change does not match the account and its current key."));
        }
        let thumbprint = jws::thumbprint(&new_key).unwrap_or_default();
        let mut st = self.lock();
        if let Some(other) =
            st.acme_accounts.values().find(|a| a.endpoint_arn == endpoint.arn && a.thumbprint == thumbprint)
        {
            let url = other.url.clone();
            drop(st);
            return Err(Problem {
                status: StatusCode::CONFLICT,
                kind: "malformed",
                detail: format!("The new key already belongs to {url}."),
            });
        }
        let a = st.acme_accounts.get_mut(&account.id).expect("account exists");
        a.jwk = new_key;
        a.thumbprint = thumbprint;
        let a = a.clone();
        drop(st);
        Ok(Reply { location: Some(a.url.clone()), ..reply(StatusCode::OK, self.account_json(urls, &a)) })
    }
}
