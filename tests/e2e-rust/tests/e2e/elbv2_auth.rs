//! Application Load Balancer authentication actions through the official
//! Rust SDK: the OpenID Connect login flow against a local IdP (redirect,
//! code exchange, session cookie, signed user claims for the target) and
//! `jwt-validation` of bearer tokens against a JWKS.

use std::sync::Arc;

use aws_sdk_elasticloadbalancingv2::types::{
    Action, ActionTypeEnum, AuthenticateOidcActionConditionalBehaviorEnum, AuthenticateOidcActionConfig, Certificate,
    JwtValidationActionAdditionalClaim, JwtValidationActionAdditionalClaimFormatEnum, JwtValidationActionConfig,
    PathPatternConditionConfig, ProtocolEnum, RuleCondition, TargetDescription, TargetHealthStateEnum,
};
use base64::Engine;
use mws_e2e::{Idp, Mws};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::elbv2::{
    client, default_network, forward, https_request, imported_certificate, ip_target_group, listener_address,
    wait_for_health, Backend,
};

const CLIENT_ID: &str = "client-1";
const CLIENT_SECRET: &str = "secret-1";

/// An OpenID Connect provider's token and user info endpoints over HTTPS.
/// The code `good` exchanges for the access token `at-1`; anything else
/// is refused.
struct OidcProvider {
    base: String,
    _server: tokio::task::JoinHandle<()>,
}

impl OidcProvider {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("https://localhost:{}", listener.local_addr().unwrap().port());
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls_pki_types::CertificateDer::from(cert.cert.der().to_vec())],
                rustls_pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into()),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let issuer = base.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { return };
                let acceptor = acceptor.clone();
                let issuer = issuer.clone();
                tokio::spawn(async move {
                    let Ok(mut s) = acceptor.accept(tcp).await else { return };
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let (head, body) = loop {
                        let n = s.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else { continue };
                        let head = String::from_utf8_lossy(&buf[..end]).to_string();
                        let len: usize = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if buf.len() >= end + 4 + len {
                            break (head, String::from_utf8_lossy(&buf[end + 4..end + 4 + len]).to_string());
                        }
                    };
                    let header = |name: &str| {
                        head.lines()
                            .filter_map(|l| l.split_once(':'))
                            .find(|(k, _)| k.trim().eq_ignore_ascii_case(name))
                            .map(|(_, v)| v.trim().to_string())
                            .unwrap_or_default()
                    };
                    let path = head.split(' ').nth(1).unwrap_or("/").to_string();
                    let basic = format!(
                        "Basic {}",
                        base64::engine::general_purpose::STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"))
                    );
                    let (status, body) = match path.as_str() {
                        "/token"
                            if header("authorization") == basic
                                && body.contains("grant_type=authorization_code")
                                && body.contains("code=good") =>
                        {
                            let id_token = mws_e2e::jwt(serde_json::json!({
                                "iss": issuer, "aud": CLIENT_ID, "sub": "user-1",
                                "exp": chrono::Utc::now().timestamp() + 3600,
                            }));
                            let tokens = serde_json::json!({
                                "access_token": "at-1", "id_token": id_token, "token_type": "Bearer", "expires_in": 3600,
                            });
                            ("200 OK", tokens.to_string())
                        }
                        "/token" => ("400 Bad Request", r#"{"error":"invalid_grant"}"#.to_string()),
                        "/userinfo" if header("authorization") == "Bearer at-1" => {
                            ("200 OK", r#"{"sub":"user-1","email":"user@example.com"}"#.to_string())
                        }
                        _ => ("401 Unauthorized", String::new()),
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(response.as_bytes()).await;
                    let _ = s.shutdown().await;
                });
            }
        });
        Self { base, _server: server }
    }

    fn config(
        &self,
        on_unauthenticated: AuthenticateOidcActionConditionalBehaviorEnum,
    ) -> AuthenticateOidcActionConfig {
        AuthenticateOidcActionConfig::builder()
            .issuer(&self.base)
            .authorization_endpoint(format!("{}/authorize", self.base))
            .token_endpoint(format!("{}/token", self.base))
            .user_info_endpoint(format!("{}/userinfo", self.base))
            .client_id(CLIENT_ID)
            .client_secret(CLIENT_SECRET)
            .on_unauthenticated_request(on_unauthenticated)
            .build()
    }
}

fn query_param(url: &str, name: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == name).then(|| percent_decode(v))
    })
}

fn percent_decode(v: &str) -> String {
    let b = v.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            out.push(u8::from_str_radix(&v[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

/// An HTTPS load balancer for `app.example.com` with `default_actions`,
/// forwarding to one healthy backend: `(listener address, lb ARN,
/// listener ARN, target group ARN)`.
async fn https_load_balancer(mws: &Mws, name: &str, backend: &Backend) -> (String, String, String, String) {
    let elb = client(mws).await;
    let (vpc, subnets) = default_network(mws).await;
    let (cert, _) = imported_certificate(mws, "app.example.com").await;
    let lb = elb.create_load_balancer().name(name).set_subnets(Some(subnets)).send().await.unwrap();
    let lb_arn = lb.load_balancers()[0].load_balancer_arn().unwrap().to_string();
    let tg = ip_target_group(&elb, name, &vpc, ProtocolEnum::Http).await;
    elb.register_targets()
        .target_group_arn(&tg)
        .targets(TargetDescription::builder().id("127.0.0.1").port(backend.port()).build())
        .send()
        .await
        .unwrap();
    let listener = elb
        .create_listener()
        .load_balancer_arn(&lb_arn)
        .protocol(ProtocolEnum::Https)
        .port(443)
        .certificates(Certificate::builder().certificate_arn(cert).build())
        .default_actions(forward(&tg))
        .send()
        .await
        .unwrap();
    let listener_arn = listener.listeners()[0].listener_arn().unwrap().to_string();
    wait_for_health(&elb, &tg, &[(backend.port(), TargetHealthStateEnum::Healthy)]).await;
    (listener_address(mws, &listener_arn).await, lb_arn, listener_arn, tg)
}

fn path_rule(pattern: &str) -> RuleCondition {
    RuleCondition::builder()
        .field("path-pattern")
        .path_pattern_config(PathPatternConditionConfig::builder().values(pattern).build())
        .build()
}

#[tokio::test]
async fn authenticate_oidc_logs_users_in_and_signs_their_claims() {
    let mws = Mws::start().await;
    let elb = client(&mws).await;
    let idp = OidcProvider::start().await;
    let backend = Backend::start("app").await;
    let (addr, lb_arn, listener_arn, tg) = https_load_balancer(&mws, "oidc", &backend).await;
    let host = "app.example.com";

    let oidc = |order: i32, behavior| {
        Action::builder()
            .r#type(ActionTypeEnum::AuthenticateOidc)
            .order(order)
            .authenticate_oidc_config(idp.config(behavior))
            .build()
    };
    let mut fwd = forward(&tg);
    fwd.order = Some(2);
    let rule = elb
        .create_rule()
        .listener_arn(&listener_arn)
        .priority(10)
        .conditions(path_rule("/app*"))
        .actions(oidc(1, AuthenticateOidcActionConditionalBehaviorEnum::Authenticate))
        .actions(fwd.clone())
        .send()
        .await
        .unwrap();
    // ELB never returns the client secret.
    let stored = rule.rules()[0].actions()[0].authenticate_oidc_config().unwrap();
    assert_eq!(stored.client_secret(), None);
    assert_eq!(stored.scope(), Some("openid"));
    elb.create_rule()
        .listener_arn(&listener_arn)
        .priority(20)
        .conditions(path_rule("/api*"))
        .actions(oidc(1, AuthenticateOidcActionConditionalBehaviorEnum::Deny))
        .actions(fwd.clone())
        .send()
        .await
        .unwrap();
    elb.create_rule()
        .listener_arn(&listener_arn)
        .priority(30)
        .conditions(path_rule("/public*"))
        .actions(oidc(1, AuthenticateOidcActionConditionalBehaviorEnum::Allow))
        .actions(fwd)
        .send()
        .await
        .unwrap();

    // Unauthenticated: off to the IdP's authorization endpoint.
    let login = https_request(&addr, host, "/app/page?x=1", &[]).await;
    assert_eq!(login.status, 302, "{}", login.body);
    let location = login.header("location").unwrap().to_string();
    assert!(location.starts_with(&format!("{}/authorize?", idp.base)), "{location}");
    assert_eq!(query_param(&location, "response_type").as_deref(), Some("code"));
    assert_eq!(query_param(&location, "client_id").as_deref(), Some(CLIENT_ID));
    assert_eq!(query_param(&location, "scope").as_deref(), Some("openid"));
    assert_eq!(query_param(&location, "redirect_uri").as_deref(), Some("https://app.example.com/oauth2/idpresponse"));
    let state = query_param(&location, "state").unwrap();

    // The IdP sends the browser back with a code.
    let callback = https_request(&addr, host, &format!("/oauth2/idpresponse?code=good&state={state}"), &[]).await;
    assert_eq!(callback.status, 302, "{}", callback.body);
    assert_eq!(callback.header("location"), Some("https://app.example.com/app/page?x=1"));
    let set_cookie = callback.header("set-cookie").unwrap().to_string();
    assert!(set_cookie.starts_with("AWSELBAuthSessionCookie-0="), "{set_cookie}");
    assert!(set_cookie.contains("Secure") && set_cookie.contains("HttpOnly"), "{set_cookie}");
    let cookie = set_cookie.split(';').next().unwrap().to_string();

    // Logged in: the target sees who the user is.
    let page = https_request(&addr, host, "/app/page?x=1", &[("Cookie", &cookie)]).await;
    assert_eq!(page.status, 200, "{}", page.body);
    let seen = page.json();
    let headers = &seen["headers"];
    assert_eq!(headers["x-amzn-oidc-identity"], "user-1");
    assert_eq!(headers["x-amzn-oidc-accesstoken"], "at-1");
    let data = headers["x-amzn-oidc-data"].as_str().unwrap();

    // x-amzn-oidc-data is an ES256 JWT, base64url with padding, signed by
    // the load balancer with a key published by kid.
    let b64 = base64::engine::general_purpose::URL_SAFE;
    let parts: Vec<&str> = data.split('.').collect();
    assert_eq!(parts.len(), 3);
    let header: serde_json::Value = serde_json::from_slice(&b64.decode(parts[0]).unwrap()).unwrap();
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["signer"], lb_arn.as_str());
    assert_eq!(header["client"], CLIENT_ID);
    assert_eq!(header["iss"], idp.base.as_str());
    let claims: serde_json::Value = serde_json::from_slice(&b64.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(claims["sub"], "user-1");
    assert_eq!(claims["email"], "user@example.com");
    let region = lb_arn.split(':').nth(3).unwrap();
    let kid = header["kid"].as_str().unwrap();
    let (status, _, pem) = mws.raw("GET", &format!("/_aws/elb/public-keys/{region}/{kid}"), &[], b"").await;
    assert_eq!(status, 200);
    let pem = String::from_utf8(pem).unwrap();
    let b64_body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let spki = base64::engine::general_purpose::STANDARD.decode(b64_body).unwrap();
    let point = &spki[spki.len() - 65..];
    let key = aws_lc_rs::signature::UnparsedPublicKey::new(&aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED, point);
    key.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &b64.decode(parts[2]).unwrap())
        .expect("x-amzn-oidc-data signature verifies with the published key");
    // The public key host serves it too.
    let (status, _, _) = mws
        .raw("GET", &format!("/{kid}"), &[("Host", &format!("public-keys.auth.elb.{region}.amazonaws.com"))], b"")
        .await;
    assert_eq!(status, 200);

    // A forged identity header is replaced.
    let page = https_request(&addr, host, "/app/x", &[("Cookie", &cookie), ("x-amzn-oidc-identity", "admin")]).await;
    assert_eq!(page.json()["headers"]["x-amzn-oidc-identity"], "user-1");

    // deny answers 401 without a session; allow passes through.
    assert_eq!(https_request(&addr, host, "/api/items", &[]).await.status, 401);
    assert_eq!(https_request(&addr, host, "/api/items", &[("Cookie", &cookie)]).await.status, 200);
    let public = https_request(&addr, host, "/public/doc", &[]).await;
    assert_eq!(public.status, 200);
    assert!(public.json()["headers"].get("x-amzn-oidc-data").is_none());

    // A code the IdP refuses ends in ELB's 561 page.
    let login = https_request(&addr, host, "/app/again", &[]).await;
    let state = query_param(login.header("location").unwrap(), "state").unwrap();
    let failed = https_request(&addr, host, &format!("/oauth2/idpresponse?code=bad&state={state}"), &[]).await;
    assert_eq!(failed.status, 561, "{}", failed.body);
    // An unknown state is not a login in progress.
    let stray = https_request(&addr, host, "/oauth2/idpresponse?code=good&state=nope", &[]).await;
    assert_ne!(stray.status, 302);

    // Modifying the rule with UseExistingClientSecret keeps logins working.
    let rules = elb.describe_rules().listener_arn(&listener_arn).send().await.unwrap();
    let app_rule = rules.rules().iter().find(|r| r.priority() == Some("10")).unwrap().rule_arn().unwrap().to_string();
    let mut cfg = idp.config(AuthenticateOidcActionConditionalBehaviorEnum::Authenticate);
    cfg.client_secret = None;
    cfg.use_existing_client_secret = Some(true);
    let mut fwd = forward(&tg);
    fwd.order = Some(2);
    elb.modify_rule()
        .rule_arn(&app_rule)
        .actions(
            Action::builder().r#type(ActionTypeEnum::AuthenticateOidc).order(1).authenticate_oidc_config(cfg).build(),
        )
        .actions(fwd)
        .send()
        .await
        .unwrap();
    let login = https_request(&addr, host, "/app/third", &[]).await;
    let state = query_param(login.header("location").unwrap(), "state").unwrap();
    let callback = https_request(&addr, host, &format!("/oauth2/idpresponse?code=good&state={state}"), &[]).await;
    assert_eq!(callback.status, 302, "{}", callback.body);
    backend.stop();
}

#[tokio::test]
async fn jwt_validation_checks_bearer_tokens() {
    let mws = Mws::start().await;
    let elb = client(&mws).await;
    let idp = Idp::start().await;
    let backend = Backend::start("api").await;
    let (addr, _, listener_arn, tg) = https_load_balancer(&mws, "jwt", &backend).await;
    let host = "app.example.com";

    let config = JwtValidationActionConfig::builder()
        .issuer(&idp.issuer)
        .jwks_endpoint(format!("{}/keys", idp.issuer))
        .additional_claims(
            JwtValidationActionAdditionalClaim::builder()
                .name("scope")
                .format(JwtValidationActionAdditionalClaimFormatEnum::SpaceSeparatedValues)
                .values("orders:read")
                .build(),
        )
        .build();
    let mut fwd = forward(&tg);
    fwd.order = Some(2);
    elb.create_rule()
        .listener_arn(&listener_arn)
        .priority(1)
        .conditions(path_rule("/orders*"))
        .actions(Action::builder().r#type(ActionTypeEnum::JwtValidation).order(1).jwt_validation_config(config).build())
        .actions(fwd)
        .send()
        .await
        .unwrap();
    let now = chrono::Utc::now().timestamp();
    let call = |token: String| {
        let addr = addr.clone();
        async move { https_request(&addr, host, "/orders/1", &[("Authorization", &format!("Bearer {token}"))]).await }
    };

    let good = idp.token(serde_json::json!({"sub": "svc", "exp": now + 600, "scope": "orders:read orders:write"}));
    let ok = call(good.clone()).await;
    assert_eq!(ok.status, 200, "{}", ok.body);
    // The target gets the token as sent.
    assert_eq!(ok.json()["headers"]["authorization"], format!("Bearer {good}"));

    let missing = https_request(&addr, host, "/orders/1", &[]).await;
    assert_eq!(missing.status, 401);
    assert!(missing.header("www-authenticate").unwrap().starts_with("Bearer"), "{:?}", missing.headers);

    let expired = idp.token(serde_json::json!({"sub": "svc", "exp": now - 60, "scope": "orders:read"}));
    let r = call(expired).await;
    assert_eq!(r.status, 401);
    assert_eq!(r.header("www-authenticate"), Some("Bearer error=\"invalid_token\""));

    let no_scope = idp.token(serde_json::json!({"sub": "svc", "exp": now + 600, "scope": "orders:write"}));
    let r = call(no_scope).await;
    assert_eq!(r.status, 401);
    assert_eq!(r.header("www-authenticate"), Some("Bearer error=\"insufficient_scope\""));

    // A token whose signature does not match the JWKS.
    let mut forged = good.rsplit_once('.').unwrap().0.to_string();
    forged.push_str(".AAAA");
    assert_eq!(call(forged).await.status, 401);

    // Not yet valid.
    let early =
        idp.token(serde_json::json!({"sub": "svc", "exp": now + 600, "nbf": now + 300, "scope": "orders:read"}));
    assert_eq!(call(early).await.status, 401);

    // Paths without the rule are not checked.
    assert_eq!(https_request(&addr, host, "/health", &[]).await.status, 200);
    backend.stop();
}
