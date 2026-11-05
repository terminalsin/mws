//! Other user credentials: SSH public keys, X.509 signing certificates,
//! service-specific credentials, and server certificates.

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use md5::{Digest, Md5};
use mws_core::{RequestContext, ServiceError};
use rand::Rng;
use x509_parser::prelude::*;

use crate::common::*;
use crate::generated::{errors, types};
use crate::ops::users::Subject;
use crate::state::{ServerCertificate, ServiceCredential, SigningCertificate, SshPublicKey, State};
use crate::Iam;

const MAX_SSH_KEYS: usize = 5;
const MAX_SIGNING_CERTS: usize = 2;
const MAX_SERVICE_CREDS_PER_SERVICE: usize = 2;
const MAX_SERVER_CERTS: usize = 20;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn random_id(prefix: &str, len: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    let tail: String = (0..len).map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char).collect();
    format!("{prefix}{tail}")
}

fn status_from(s: &str) -> Result<bool, ServiceError> {
    match s {
        "Active" => Ok(true),
        "Inactive" => Ok(false),
        other => Err(validation(format!(
            "1 validation error detected: Value '{other}' at 'status' failed to satisfy constraint: Member must satisfy enum value set: [Active, Inactive]"
        ))),
    }
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    let b64 = B64.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----"));
    out
}

// ---------------------------------------------------------------------------
// SSH keys: OpenSSH `ssh-rsa` or PEM SubjectPublicKeyInfo, RSA >= 2048 bits.

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

fn der_uint(v: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = v.iter().copied().skip_while(|b| *b == 0).collect();
    if v.first().is_none_or(|b| b & 0x80 != 0) {
        v.insert(0, 0);
    }
    der_tlv(0x02, &v)
}

fn ssh_string(buf: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let len = u32::from_be_bytes(buf.get(*pos..*pos + 4)?.try_into().ok()?) as usize;
    let out = buf.get(*pos + 4..*pos + 4 + len)?.to_vec();
    *pos += 4 + len;
    Some(out)
}

/// (exponent, modulus) from an OpenSSH or PEM RSA public key.
fn rsa_components(body: &str) -> Result<(Vec<u8>, Vec<u8>), ServiceError> {
    let body = body.trim();
    if let Some(rest) = body.strip_prefix("ssh-rsa ") {
        let blob = rest.split_whitespace().next().and_then(|b| B64.decode(b).ok()).ok_or_else(invalid_key)?;
        let mut pos = 0;
        let ty = ssh_string(&blob, &mut pos).ok_or_else(invalid_key)?;
        if ty != b"ssh-rsa" {
            return Err(invalid_key());
        }
        let e = ssh_string(&blob, &mut pos).ok_or_else(invalid_key)?;
        let n = ssh_string(&blob, &mut pos).ok_or_else(invalid_key)?;
        return Ok((e, n));
    }
    if body.starts_with("-----BEGIN PUBLIC KEY-----") {
        let (_, pem) = parse_x509_pem(body.as_bytes()).map_err(|_| invalid_key())?;
        let (_, spki) = SubjectPublicKeyInfo::from_der(&pem.contents).map_err(|_| invalid_key())?;
        if let Ok(x509_parser::public_key::PublicKey::RSA(rsa)) = spki.parsed() {
            return Ok((rsa.exponent.to_vec(), rsa.modulus.to_vec()));
        }
        return Err(invalid_key());
    }
    Err(errors::unrecognized_public_key_encoding("The SSH public key must be in ssh-rsa or PEM format."))
}

fn invalid_key() -> ServiceError {
    errors::invalid_public_key("The public key is not valid.")
}

fn ssh_blob(e: &[u8], n: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in [b"ssh-rsa".to_vec(), mpint(e), mpint(n)] {
        out.extend((part.len() as u32).to_be_bytes());
        out.extend(part);
    }
    out
}

fn mpint(v: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = v.iter().copied().skip_while(|b| *b == 0).collect();
    if v.first().is_some_and(|b| b & 0x80 != 0) {
        v.insert(0, 0);
    }
    v
}

fn spki_pem(e: &[u8], n: &[u8]) -> String {
    let rsa_key = der_tlv(0x30, &[der_uint(n), der_uint(e)].concat());
    let alg = der_tlv(
        0x30,
        &[&[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01][..], &[0x05, 0x00]].concat(),
    );
    let mut bits = vec![0u8];
    bits.extend(rsa_key);
    pem_encode("PUBLIC KEY", &der_tlv(0x30, &[alg, der_tlv(0x03, &bits)].concat()))
}

fn modulus_bits(n: &[u8]) -> usize {
    let n: Vec<u8> = n.iter().copied().skip_while(|b| *b == 0).collect();
    n.first().map(|b| (n.len() - 1) * 8 + (8 - b.leading_zeros() as usize)).unwrap_or(0)
}

fn md5_fingerprint(blob: &[u8]) -> String {
    Md5::digest(blob).iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

impl SshPublicKey {
    fn wire(&self, user_name: &str, encoding: &str) -> types::SSHPublicKey {
        let body = match (encoding, rsa_components(&self.body)) {
            ("PEM", Ok((e, n))) => spki_pem(&e, &n),
            (_, Ok((e, n))) => format!("ssh-rsa {}", B64.encode(ssh_blob(&e, &n))),
            _ => self.body.clone(),
        };
        types::SSHPublicKey {
            user_name: user_name.to_string(),
            ssh_public_key_id: self.id.clone(),
            fingerprint: self.fingerprint.clone(),
            ssh_public_key_body: body,
            status: status_str(self.active).into(),
            upload_date: Some(self.uploaded),
        }
    }
}

impl State {
    fn user_name_of(&self, key: &str) -> String {
        self.user(key).map(|u| u.name.clone()).unwrap_or_else(|| key.to_string())
    }
}

fn no_such_ssh_key(id: &str) -> ServiceError {
    errors::no_such_entity(format!("The Public Key with id {id} cannot be found."))
}

// ---------------------------------------------------------------------------

fn parse_cert(body: &str) -> Result<(Vec<u8>, DateTime<Utc>), ServiceError> {
    let malformed = || {
        errors::malformed_certificate("Unable to parse certificate. Please ensure the certificate is in PEM format.")
    };
    let (_, pem) = parse_x509_pem(body.trim().as_bytes()).map_err(|_| malformed())?;
    if pem.label != "CERTIFICATE" {
        return Err(malformed());
    }
    let (_, cert) = X509Certificate::from_der(&pem.contents).map_err(|_| malformed())?;
    let expiry = DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0).unwrap_or_default();
    Ok((cert.public_key().raw.to_vec(), expiry))
}

/// The SubjectPublicKeyInfo bits a PEM private key corresponds to.
fn private_key_public_bits(pem_str: &str) -> Option<Vec<u8>> {
    use aws_lc_rs::signature::{self, EcdsaKeyPair, KeyPair, RsaKeyPair};
    let (_, pem) = parse_x509_pem(pem_str.trim().as_bytes()).ok()?;
    let der = &pem.contents;
    match pem.label.as_str() {
        "RSA PRIVATE KEY" => RsaKeyPair::from_der(der).ok().map(|k| k.public_key().as_ref().to_vec()),
        "EC PRIVATE KEY" => [&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &signature::ECDSA_P384_SHA384_ASN1_SIGNING]
            .into_iter()
            .find_map(|alg| EcdsaKeyPair::from_private_key_der(alg, der).ok())
            .map(|k| k.public_key().as_ref().to_vec()),
        "PRIVATE KEY" => RsaKeyPair::from_pkcs8(der).ok().map(|k| k.public_key().as_ref().to_vec()).or_else(|| {
            [&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &signature::ECDSA_P384_SHA384_ASN1_SIGNING]
                .into_iter()
                .find_map(|alg| EcdsaKeyPair::from_pkcs8(alg, der).ok())
                .map(|k| k.public_key().as_ref().to_vec())
        }),
        _ => None,
    }
}

fn spki_bits(spki_der: &[u8]) -> Option<Vec<u8>> {
    let (_, spki) = SubjectPublicKeyInfo::from_der(spki_der).ok()?;
    Some(spki.subject_public_key.data.to_vec())
}

impl ServerCertificate {
    fn metadata(&self) -> types::ServerCertificateMetadata {
        types::ServerCertificateMetadata {
            path: self.path.clone(),
            server_certificate_name: self.name.clone(),
            server_certificate_id: self.id.clone(),
            arn: self.arn.clone(),
            upload_date: Some(self.uploaded),
            expiration: self.expiration,
        }
    }
}

fn no_such_server_cert(name: &str) -> ServiceError {
    errors::no_such_entity(format!("The Server Certificate with name {name} cannot be found."))
}

impl Iam {
    // --- SSH public keys --------------------------------------------------

    pub fn upload_ssh_public_key(
        &self,
        ctx: &RequestContext,
        input: types::UploadSSHPublicKeyRequest,
    ) -> Result<types::UploadSSHPublicKeyResponse, ServiceError> {
        self.authorize(ctx, "UploadSSHPublicKey", &self.user_arn_or_default(&input.user_name))?;
        let (e, n) = rsa_components(&input.ssh_public_key_body)?;
        if modulus_bits(&n) < 2048 {
            return Err(errors::invalid_public_key("The public key must be at least 2048 bits long."));
        }
        let fingerprint = md5_fingerprint(&ssh_blob(&e, &n));
        let mut state = self.write();
        let user = state.user(&input.user_name).ok_or_else(|| no_such_user(&input.user_name))?;
        let (key, name) = (user.name.to_lowercase(), user.name.clone());
        let mine: Vec<&SshPublicKey> = state.ssh_keys.values().filter(|k| k.user == key).collect();
        if mine.iter().any(|k| k.fingerprint == fingerprint) {
            return Err(errors::duplicate_ssh_public_key(
                "The SSH public key specified is already uploaded for this user.",
            ));
        }
        if mine.len() >= MAX_SSH_KEYS {
            return Err(errors::limit_exceeded(format!("Cannot exceed quota for PublicKeysPerUser: {MAX_SSH_KEYS}")));
        }
        let ssh = SshPublicKey {
            id: random_id("APKA", 16),
            user: key,
            body: input.ssh_public_key_body.trim().to_string(),
            fingerprint,
            active: true,
            uploaded: Utc::now(),
        };
        let out = ssh.wire(&name, "SSH");
        state.ssh_keys.insert(ssh.id.clone(), ssh);
        Ok(types::UploadSSHPublicKeyResponse { ssh_public_key: Some(out) })
    }

    pub fn get_ssh_public_key(
        &self,
        ctx: &RequestContext,
        input: types::GetSSHPublicKeyRequest,
    ) -> Result<types::GetSSHPublicKeyResponse, ServiceError> {
        self.authorize(ctx, "GetSSHPublicKey", &self.user_arn_or_default(&input.user_name))?;
        let state = self.read();
        let user = state.user(&input.user_name).ok_or_else(|| no_such_user(&input.user_name))?;
        let key = state
            .ssh_keys
            .get(&input.ssh_public_key_id)
            .filter(|k| k.user == user.name.to_lowercase())
            .ok_or_else(|| no_such_ssh_key(&input.ssh_public_key_id))?;
        Ok(types::GetSSHPublicKeyResponse { ssh_public_key: Some(key.wire(&user.name, &input.encoding)) })
    }

    pub fn list_ssh_public_keys(
        &self,
        ctx: &RequestContext,
        input: types::ListSSHPublicKeysRequest,
    ) -> Result<types::ListSSHPublicKeysResponse, ServiceError> {
        let user_name = match self.subject(ctx, input.user_name)? {
            Subject::User(n) => n,
            Subject::Root => {
                self.authorize(ctx, "ListSSHPublicKeys", &ctx.caller.arn)?;
                return Ok(types::ListSSHPublicKeysResponse {
                    ssh_public_keys: Some(vec![]),
                    is_truncated: false,
                    marker: None,
                });
            }
        };
        self.authorize(ctx, "ListSSHPublicKeys", &self.user_arn_or_default(&user_name))?;
        let state = self.read();
        let user = state.user(&user_name).ok_or_else(|| no_such_user(&user_name))?;
        let all: Vec<types::SSHPublicKeyMetadata> = state
            .ssh_keys
            .values()
            .filter(|k| k.user == user.name.to_lowercase())
            .map(|k| types::SSHPublicKeyMetadata {
                user_name: user.name.clone(),
                ssh_public_key_id: k.id.clone(),
                status: status_str(k.active).into(),
                upload_date: k.uploaded,
            })
            .collect();
        let (page, truncated, marker) =
            paginate(&all, |k| k.ssh_public_key_id.clone(), input.marker.as_deref(), input.max_items)?;
        Ok(types::ListSSHPublicKeysResponse { ssh_public_keys: Some(page), is_truncated: truncated, marker })
    }

    pub fn update_ssh_public_key(
        &self,
        ctx: &RequestContext,
        input: types::UpdateSSHPublicKeyRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "UpdateSSHPublicKey", &self.user_arn_or_default(&input.user_name))?;
        let active = status_from(&input.status)?;
        let mut state = self.write();
        let key = state.user(&input.user_name).ok_or_else(|| no_such_user(&input.user_name))?.name.to_lowercase();
        let k = state
            .ssh_keys
            .get_mut(&input.ssh_public_key_id)
            .filter(|k| k.user == key)
            .ok_or_else(|| no_such_ssh_key(&input.ssh_public_key_id))?;
        k.active = active;
        Ok(())
    }

    pub fn delete_ssh_public_key(
        &self,
        ctx: &RequestContext,
        input: types::DeleteSSHPublicKeyRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "DeleteSSHPublicKey", &self.user_arn_or_default(&input.user_name))?;
        let mut state = self.write();
        let key = state.user(&input.user_name).ok_or_else(|| no_such_user(&input.user_name))?.name.to_lowercase();
        if state.ssh_keys.get(&input.ssh_public_key_id).is_none_or(|k| k.user != key) {
            return Err(no_such_ssh_key(&input.ssh_public_key_id));
        }
        state.ssh_keys.remove(&input.ssh_public_key_id);
        Ok(())
    }

    // --- Signing certificates ---------------------------------------------

    fn cert_subject(
        &self,
        ctx: &RequestContext,
        user_name: Option<String>,
    ) -> Result<(Option<String>, String), ServiceError> {
        Ok(match self.subject(ctx, user_name)? {
            Subject::User(n) => {
                let arn = self.user_arn_or_default(&n);
                (Some(n), arn)
            }
            Subject::Root => (None, ctx.caller.arn.clone()),
        })
    }

    pub fn upload_signing_certificate(
        &self,
        ctx: &RequestContext,
        input: types::UploadSigningCertificateRequest,
    ) -> Result<types::UploadSigningCertificateResponse, ServiceError> {
        let (user, arn) = self.cert_subject(ctx, input.user_name)?;
        self.authorize(ctx, "UploadSigningCertificate", &arn)?;
        parse_cert(&input.certificate_body)?;
        let mut state = self.write();
        let (key, name) = match &user {
            Some(n) => {
                let u = state.user(n).ok_or_else(|| no_such_user(n))?;
                (Some(u.name.to_lowercase()), u.name.clone())
            }
            None => (None, String::new()),
        };
        let body = input.certificate_body.trim().to_string();
        let mine: Vec<&SigningCertificate> = state.signing_certificates.values().filter(|c| c.user == key).collect();
        if mine.iter().any(|c| c.body == body) {
            return Err(errors::duplicate_certificate("The certificate is already uploaded."));
        }
        if mine.len() >= MAX_SIGNING_CERTS {
            return Err(errors::limit_exceeded(format!(
                "Cannot exceed quota for CertificatesPerUser: {MAX_SIGNING_CERTS}"
            )));
        }
        let cert = SigningCertificate { id: random_id("", 32), user: key, body, active: true, uploaded: Utc::now() };
        let out = types::SigningCertificate {
            user_name: name,
            certificate_id: cert.id.clone(),
            certificate_body: cert.body.clone(),
            status: "Active".into(),
            upload_date: Some(cert.uploaded),
        };
        state.signing_certificates.insert(cert.id.clone(), cert);
        Ok(types::UploadSigningCertificateResponse { certificate: out })
    }

    pub fn list_signing_certificates(
        &self,
        ctx: &RequestContext,
        input: types::ListSigningCertificatesRequest,
    ) -> Result<types::ListSigningCertificatesResponse, ServiceError> {
        let (user, arn) = self.cert_subject(ctx, input.user_name)?;
        self.authorize(ctx, "ListSigningCertificates", &arn)?;
        let state = self.read();
        let key = match &user {
            Some(n) => Some(state.user(n).ok_or_else(|| no_such_user(n))?.name.to_lowercase()),
            None => None,
        };
        let all: Vec<types::SigningCertificate> = state
            .signing_certificates
            .values()
            .filter(|c| c.user == key)
            .map(|c| types::SigningCertificate {
                user_name: key.as_deref().map(|k| state.user_name_of(k)).unwrap_or_default(),
                certificate_id: c.id.clone(),
                certificate_body: c.body.clone(),
                status: status_str(c.active).into(),
                upload_date: Some(c.uploaded),
            })
            .collect();
        let (page, truncated, marker) =
            paginate(&all, |c| c.certificate_id.clone(), input.marker.as_deref(), input.max_items)?;
        Ok(types::ListSigningCertificatesResponse { certificates: page, is_truncated: truncated, marker })
    }

    fn signing_cert_mut<'a>(
        state: &'a mut State,
        user: &Option<String>,
        id: &str,
    ) -> Result<&'a mut SigningCertificate, ServiceError> {
        let key = match user {
            Some(n) => Some(state.user(n).ok_or_else(|| no_such_user(n))?.name.to_lowercase()),
            None => None,
        };
        state
            .signing_certificates
            .get_mut(id)
            .filter(|c| c.user == key)
            .ok_or_else(|| errors::no_such_entity(format!("The Certificate with id {id} cannot be found.")))
    }

    pub fn update_signing_certificate(
        &self,
        ctx: &RequestContext,
        input: types::UpdateSigningCertificateRequest,
    ) -> Result<(), ServiceError> {
        let (user, arn) = self.cert_subject(ctx, input.user_name)?;
        self.authorize(ctx, "UpdateSigningCertificate", &arn)?;
        let active = status_from(&input.status)?;
        let mut state = self.write();
        Self::signing_cert_mut(&mut state, &user, &input.certificate_id)?.active = active;
        Ok(())
    }

    pub fn delete_signing_certificate(
        &self,
        ctx: &RequestContext,
        input: types::DeleteSigningCertificateRequest,
    ) -> Result<(), ServiceError> {
        let (user, arn) = self.cert_subject(ctx, input.user_name)?;
        self.authorize(ctx, "DeleteSigningCertificate", &arn)?;
        let mut state = self.write();
        Self::signing_cert_mut(&mut state, &user, &input.certificate_id)?;
        state.signing_certificates.remove(&input.certificate_id);
        Ok(())
    }

    // --- Service-specific credentials --------------------------------------

    fn service_cred_wire(
        &self,
        state: &State,
        c: &ServiceCredential,
        with_secret: bool,
    ) -> types::ServiceSpecificCredential {
        types::ServiceSpecificCredential {
            create_date: c.created,
            expiration_date: c.expires,
            service_name: c.service.clone(),
            service_user_name: c.service_user_name.clone(),
            service_password: if with_secret && c.service != "bedrock.amazonaws.com" {
                c.password.clone()
            } else {
                String::new()
            },
            service_credential_alias: (c.service == "bedrock.amazonaws.com").then(|| c.service_user_name.clone()),
            service_credential_secret: (with_secret && c.service == "bedrock.amazonaws.com")
                .then(|| c.password.clone()),
            service_specific_credential_id: c.id.clone(),
            user_name: state.user_name_of(&c.user),
            status: status_str(c.active).into(),
        }
    }

    pub fn create_service_specific_credential(
        &self,
        ctx: &RequestContext,
        input: types::CreateServiceSpecificCredentialRequest,
    ) -> Result<types::CreateServiceSpecificCredentialResponse, ServiceError> {
        self.authorize(ctx, "CreateServiceSpecificCredential", &self.user_arn_or_default(&input.user_name))?;
        let service = input.service_name.as_str();
        if !matches!(service, "codecommit.amazonaws.com" | "cassandra.amazonaws.com" | "bedrock.amazonaws.com") {
            return Err(errors::service_not_supported(format!(
                "Service {service} is not supported for service-specific credentials."
            )));
        }
        if input.credential_age_days.is_some() && service != "bedrock.amazonaws.com" {
            return Err(validation("CredentialAgeDays is only supported for bedrock.amazonaws.com."));
        }
        let mut state = self.write();
        let user = state.user(&input.user_name).ok_or_else(|| no_such_user(&input.user_name))?;
        let (key, name) = (user.name.to_lowercase(), user.name.clone());
        let existing = state.service_credentials.values().filter(|c| c.user == key && c.service == service).count();
        if existing >= MAX_SERVICE_CREDS_PER_SERVICE {
            return Err(errors::limit_exceeded(format!(
                "Cannot exceed quota for ServiceSpecificCredentialsPerUserPerService: {MAX_SERVICE_CREDS_PER_SERVICE}"
            )));
        }
        let mut secret = [0u8; 33];
        rand::thread_rng().fill(&mut secret[..]);
        let account = self.account_id().to_string();
        let service_user_name = match service {
            "bedrock.amazonaws.com" => format!("BedrockAPIKey-{}-at-{account}", random_id("", 4).to_lowercase()),
            _ => format!("{name}-at-{account}"),
        };
        // A Bedrock API key is `ABSK` and the base64 of `alias:secret`; the
        // whole key is what a client sends as its bearer token.
        let password = match service {
            "bedrock.amazonaws.com" => {
                format!("ABSK{}", B64.encode(format!("{service_user_name}:{}", B64.encode(secret))))
            }
            _ => B64.encode(secret),
        };
        let now = Utc::now();
        let cred = ServiceCredential {
            id: random_id("ACCA", 17),
            user: key,
            service: service.to_string(),
            service_user_name,
            password,
            active: true,
            created: now,
            expires: input.credential_age_days.map(|d| now + Duration::days(d as i64)),
        };
        let out = self.service_cred_wire(&state, &cred, true);
        state.service_credentials.insert(cred.id.clone(), cred);
        Ok(types::CreateServiceSpecificCredentialResponse { service_specific_credential: Some(out) })
    }

    pub fn list_service_specific_credentials(
        &self,
        ctx: &RequestContext,
        input: types::ListServiceSpecificCredentialsRequest,
    ) -> Result<types::ListServiceSpecificCredentialsResponse, ServiceError> {
        let all_users = input.all_users.unwrap_or(false);
        let user_key = if all_users {
            self.authorize(ctx, "ListServiceSpecificCredentials", "*")?;
            None
        } else {
            let Subject::User(n) = self.subject(ctx, input.user_name)? else {
                return Err(validation("Must specify userName when calling with non-User credentials"));
            };
            self.authorize(ctx, "ListServiceSpecificCredentials", &self.user_arn_or_default(&n))?;
            Some(self.read().user(&n).ok_or_else(|| no_such_user(&n))?.name.to_lowercase())
        };
        let state = self.read();
        let all: Vec<types::ServiceSpecificCredentialMetadata> = state
            .service_credentials
            .values()
            .filter(|c| user_key.as_ref().is_none_or(|u| &c.user == u))
            .filter(|c| input.service_name.as_ref().is_none_or(|s| &c.service == s))
            .map(|c| {
                let w = self.service_cred_wire(&state, c, false);
                types::ServiceSpecificCredentialMetadata {
                    user_name: w.user_name,
                    status: w.status,
                    service_user_name: w.service_user_name,
                    service_credential_alias: w.service_credential_alias,
                    create_date: w.create_date,
                    expiration_date: w.expiration_date,
                    service_specific_credential_id: w.service_specific_credential_id,
                    service_name: w.service_name,
                }
            })
            .collect();
        let (page, truncated, marker) =
            paginate(&all, |c| c.service_specific_credential_id.clone(), input.marker.as_deref(), input.max_items)?;
        Ok(types::ListServiceSpecificCredentialsResponse {
            service_specific_credentials: Some(page),
            marker,
            is_truncated: truncated,
        })
    }

    fn service_cred_mut<'a>(
        &self,
        ctx: &RequestContext,
        state: &'a mut State,
        user_name: Option<String>,
        id: &str,
    ) -> Result<&'a mut ServiceCredential, ServiceError> {
        let Subject::User(n) = self.subject(ctx, user_name)? else {
            return Err(validation("Must specify userName when calling with non-User credentials"));
        };
        let key = state.user(&n).ok_or_else(|| no_such_user(&n))?.name.to_lowercase();
        state
            .service_credentials
            .get_mut(id)
            .filter(|c| c.user == key)
            .ok_or_else(|| errors::no_such_entity(format!("No such credential {id} exists")))
    }

    fn cred_user_arn(&self, ctx: &RequestContext, user_name: &Option<String>) -> Result<String, ServiceError> {
        Ok(match self.subject(ctx, user_name.clone())? {
            Subject::User(n) => self.user_arn_or_default(&n),
            Subject::Root => ctx.caller.arn.clone(),
        })
    }

    pub fn update_service_specific_credential(
        &self,
        ctx: &RequestContext,
        input: types::UpdateServiceSpecificCredentialRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "UpdateServiceSpecificCredential", &self.cred_user_arn(ctx, &input.user_name)?)?;
        let active = status_from(&input.status)?;
        let mut state = self.write();
        self.service_cred_mut(ctx, &mut state, input.user_name, &input.service_specific_credential_id)?.active = active;
        Ok(())
    }

    pub fn reset_service_specific_credential(
        &self,
        ctx: &RequestContext,
        input: types::ResetServiceSpecificCredentialRequest,
    ) -> Result<types::ResetServiceSpecificCredentialResponse, ServiceError> {
        self.authorize(ctx, "ResetServiceSpecificCredential", &self.cred_user_arn(ctx, &input.user_name)?)?;
        let mut state = self.write();
        let mut secret = [0u8; 33];
        rand::thread_rng().fill(&mut secret[..]);
        let c = self.service_cred_mut(ctx, &mut state, input.user_name, &input.service_specific_credential_id)?;
        c.password = B64.encode(secret);
        let c = c.clone();
        Ok(types::ResetServiceSpecificCredentialResponse {
            service_specific_credential: Some(self.service_cred_wire(&state, &c, true)),
        })
    }

    pub fn delete_service_specific_credential(
        &self,
        ctx: &RequestContext,
        input: types::DeleteServiceSpecificCredentialRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "DeleteServiceSpecificCredential", &self.cred_user_arn(ctx, &input.user_name)?)?;
        let mut state = self.write();
        self.service_cred_mut(ctx, &mut state, input.user_name, &input.service_specific_credential_id)?;
        state.service_credentials.remove(&input.service_specific_credential_id);
        Ok(())
    }

    // --- Server certificates ----------------------------------------------

    pub fn upload_server_certificate(
        &self,
        ctx: &RequestContext,
        input: types::UploadServerCertificateRequest,
    ) -> Result<types::UploadServerCertificateResponse, ServiceError> {
        let path = input.path.unwrap_or_else(|| "/".into());
        let arn = self.entity_arn("server-certificate", &path, &input.server_certificate_name);
        let tags = tags_from_wire(input.tags)?;
        self.authorize_with(ctx, "UploadServerCertificate", &arn, request_tag_context(&tags))?;
        let (spki, expiration) = parse_cert(&input.certificate_body)?;
        if let Some(chain) = &input.certificate_chain {
            for pem in Pem::iter_from_buffer(chain.as_bytes()) {
                let pem = pem.map_err(|_| errors::malformed_certificate("Unable to parse certificate chain."))?;
                X509Certificate::from_der(&pem.contents)
                    .map_err(|_| errors::malformed_certificate("Unable to parse certificate chain."))?;
            }
        }
        let key_bits = private_key_public_bits(&input.private_key).ok_or_else(|| {
            errors::malformed_certificate("Unable to parse private key. Please ensure the key is in PEM format.")
        })?;
        if spki_bits(&spki) != Some(key_bits) {
            return Err(errors::key_pair_mismatch("The public key in the certificate does not match the private key."));
        }
        let mut state = self.write();
        let key = input.server_certificate_name.to_lowercase();
        if state.server_certificates.contains_key(&key) {
            return Err(errors::entity_already_exists(format!(
                "The Server Certificate with name {} already exists.",
                input.server_certificate_name
            )));
        }
        if state.server_certificates.len() >= MAX_SERVER_CERTS {
            return Err(errors::limit_exceeded(format!(
                "Cannot exceed quota for ServerCertificatesPerAccount: {MAX_SERVER_CERTS}"
            )));
        }
        let cert = ServerCertificate {
            name: input.server_certificate_name,
            path,
            id: random_id("ASCA", 17),
            arn,
            body: input.certificate_body.trim().to_string(),
            chain: input.certificate_chain.map(|c| c.trim().to_string()),
            uploaded: Utc::now(),
            expiration: Some(expiration),
            tags,
        };
        let out = (cert.metadata(), tags_to_wire(&cert.tags));
        state.server_certificates.insert(key, cert);
        Ok(types::UploadServerCertificateResponse { server_certificate_metadata: Some(out.0), tags: out.1 })
    }

    pub fn get_server_certificate(
        &self,
        ctx: &RequestContext,
        input: types::GetServerCertificateRequest,
    ) -> Result<types::GetServerCertificateResponse, ServiceError> {
        let arn = self.server_cert_arn(&input.server_certificate_name);
        self.authorize(ctx, "GetServerCertificate", &arn)?;
        let state = self.read();
        let c = state
            .server_certificates
            .get(&input.server_certificate_name.to_lowercase())
            .ok_or_else(|| no_such_server_cert(&input.server_certificate_name))?;
        Ok(types::GetServerCertificateResponse {
            server_certificate: types::ServerCertificate {
                server_certificate_metadata: c.metadata(),
                certificate_body: c.body.clone(),
                certificate_chain: c.chain.clone(),
                tags: tags_to_wire(&c.tags),
            },
        })
    }

    fn server_cert_arn(&self, name: &str) -> String {
        self.read()
            .server_certificates
            .get(&name.to_lowercase())
            .map(|c| c.arn.clone())
            .unwrap_or_else(|| self.entity_arn("server-certificate", "/", name))
    }

    pub fn list_server_certificates(
        &self,
        ctx: &RequestContext,
        input: types::ListServerCertificatesRequest,
    ) -> Result<types::ListServerCertificatesResponse, ServiceError> {
        self.authorize(ctx, "ListServerCertificates", "*")?;
        let state = self.read();
        let prefix = input.path_prefix.as_deref().unwrap_or("/");
        let all: Vec<types::ServerCertificateMetadata> =
            state.server_certificates.values().filter(|c| c.path.starts_with(prefix)).map(|c| c.metadata()).collect();
        let (page, truncated, marker) =
            paginate(&all, |c| c.server_certificate_name.to_lowercase(), input.marker.as_deref(), input.max_items)?;
        Ok(types::ListServerCertificatesResponse {
            server_certificate_metadata_list: page,
            is_truncated: truncated,
            marker,
        })
    }

    pub fn update_server_certificate(
        &self,
        ctx: &RequestContext,
        input: types::UpdateServerCertificateRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "UpdateServerCertificate", &self.server_cert_arn(&input.server_certificate_name))?;
        if let Some(new) = &input.new_server_certificate_name {
            let path = input.new_path.clone().unwrap_or_else(|| "/".into());
            self.authorize(ctx, "UpdateServerCertificate", &self.entity_arn("server-certificate", &path, new))?;
        }
        let mut state = self.write();
        let old_key = input.server_certificate_name.to_lowercase();
        let mut cert = state
            .server_certificates
            .get(&old_key)
            .cloned()
            .ok_or_else(|| no_such_server_cert(&input.server_certificate_name))?;
        let new_key = input.new_server_certificate_name.as_deref().map(str::to_lowercase).unwrap_or(old_key.clone());
        if new_key != old_key && state.server_certificates.contains_key(&new_key) {
            return Err(errors::entity_already_exists(format!(
                "The Server Certificate with name {} already exists.",
                input.new_server_certificate_name.unwrap_or_default()
            )));
        }
        if let Some(p) = input.new_path {
            cert.path = p;
        }
        if let Some(n) = input.new_server_certificate_name {
            cert.name = n;
        }
        cert.arn = self.entity_arn("server-certificate", &cert.path, &cert.name);
        state.server_certificates.remove(&old_key);
        state.server_certificates.insert(new_key, cert);
        Ok(())
    }

    pub fn delete_server_certificate(
        &self,
        ctx: &RequestContext,
        input: types::DeleteServerCertificateRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "DeleteServerCertificate", &self.server_cert_arn(&input.server_certificate_name))?;
        let mut state = self.write();
        state
            .server_certificates
            .remove(&input.server_certificate_name.to_lowercase())
            .ok_or_else(|| no_such_server_cert(&input.server_certificate_name))?;
        Ok(())
    }

    pub fn tag_server_certificate(
        &self,
        ctx: &RequestContext,
        input: types::TagServerCertificateRequest,
    ) -> Result<(), ServiceError> {
        let tags = tags_from_wire(Some(input.tags))?;
        let arn = self.server_cert_arn(&input.server_certificate_name);
        self.authorize_with(ctx, "TagServerCertificate", &arn, request_tag_context(&tags))?;
        let mut state = self.write();
        let c = state
            .server_certificates
            .get_mut(&input.server_certificate_name.to_lowercase())
            .ok_or_else(|| no_such_server_cert(&input.server_certificate_name))?;
        merge_tags(&mut c.tags, tags, "TagsPerServerCertificate")
    }

    pub fn untag_server_certificate(
        &self,
        ctx: &RequestContext,
        input: types::UntagServerCertificateRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "UntagServerCertificate", &self.server_cert_arn(&input.server_certificate_name))?;
        let mut state = self.write();
        let c = state
            .server_certificates
            .get_mut(&input.server_certificate_name.to_lowercase())
            .ok_or_else(|| no_such_server_cert(&input.server_certificate_name))?;
        remove_tags(&mut c.tags, &input.tag_keys);
        Ok(())
    }

    pub fn list_server_certificate_tags(
        &self,
        ctx: &RequestContext,
        input: types::ListServerCertificateTagsRequest,
    ) -> Result<types::ListServerCertificateTagsResponse, ServiceError> {
        self.authorize(ctx, "ListServerCertificateTags", &self.server_cert_arn(&input.server_certificate_name))?;
        let state = self.read();
        let c = state
            .server_certificates
            .get(&input.server_certificate_name.to_lowercase())
            .ok_or_else(|| no_such_server_cert(&input.server_certificate_name))?;
        let tags = tags_list(&c.tags);
        let (page, truncated, marker) = paginate(&tags, |t| t.key.clone(), input.marker.as_deref(), input.max_items)?;
        Ok(types::ListServerCertificateTagsResponse { tags: page, is_truncated: truncated, marker })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_and_pem_forms_round_trip() {
        let n = vec![0xc0; 256];
        let e = vec![1, 0, 1];
        let openssh = format!("ssh-rsa {} test@host", B64.encode(ssh_blob(&e, &n)));
        let (e2, n2) = rsa_components(&openssh).unwrap();
        assert_eq!(modulus_bits(&n2), 2048);
        let pem = spki_pem(&e2, &n2);
        let (e3, n3) = rsa_components(&pem).unwrap();
        assert_eq!((mpint(&e3), mpint(&n3)), (mpint(&e), mpint(&n)));
        assert!(rsa_components("ssh-dss AAAA").is_err());
    }
}
