//! Connector for SCEP through the official SDK, and its SCEP endpoint
//! through an independent SCEP client built on RustCrypto's CMS crate: a
//! device enrolls with a challenge password and gets a certificate the
//! shared Private CA issued.

use aws_sdk_pcaconnectorscep::error::ProvideErrorMetadata;
use aws_sdk_pcaconnectorscep::Client as Scep;
use aws_sdk_ram::Client as Ram;
use cms::builder::{
    ContentEncryptionAlgorithm, EnvelopedDataBuilder, KeyEncryptionInfo, KeyTransRecipientInfoBuilder,
    SignedDataBuilder, SignerInfoBuilder,
};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::ContentInfo;
use cms::enveloped_data::{EnvelopedData, RecipientIdentifier, RecipientInfo};
use cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier};
use mws_e2e::Mws;
use rsa::pkcs8::DecodePrivateKey;
use x509_cert::attr::Attribute;
use x509_cert::der::asn1::{ObjectIdentifier, OctetString, PrintableStringRef, SetOfVec};
use x509_cert::der::referenced::OwnedToRef;
use x509_cert::der::{Any, Decode, Encode};
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;
use x509_parser::prelude::*;

use crate::acmpca::{active_root, assert_signed_by};

const SCEP_PERMISSION: &str =
    "arn:aws:ram::aws:permission/AWSRAMBlankEndEntityCertificateAPICSRPassthroughIssuanceCertificateAuthority";
const MESSAGE_TYPE: &str = "2.16.840.1.113733.1.9.2";
const PKI_STATUS: &str = "2.16.840.1.113733.1.9.3";
const FAIL_INFO: &str = "2.16.840.1.113733.1.9.4";
const SENDER_NONCE: &str = "2.16.840.1.113733.1.9.5";
const RECIPIENT_NONCE: &str = "2.16.840.1.113733.1.9.6";
const TRANSACTION_ID: &str = "2.16.840.1.113733.1.9.7";

/// A device: its RSA key and self-signed transient certificate.
struct Device {
    key: rcgen::KeyPair,
    rsa: rsa::RsaPrivateKey,
    cert: Certificate,
}

fn device(cn: &str) -> Device {
    let key = rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048).unwrap();
    let rsa = rsa::RsaPrivateKey::from_pkcs8_der(&key.serialize_der()).unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name.push(rcgen::DnType::CommonName, cn);
    let cert = params.self_signed(&key).unwrap();
    let cert = Certificate::from_der(cert.der()).unwrap();
    Device { key, rsa, cert }
}

/// A PKCS#10 request with a `challengePassword` attribute.
fn csr(d: &Device, cn: &str, password: Option<&str>) -> Vec<u8> {
    let mut params = rcgen::CertificateParams::new(vec![format!("{cn}.devices.test")]).unwrap();
    params.distinguished_name.push(rcgen::DnType::CommonName, cn);
    let attrs = match password {
        Some(p) => {
            let value = PrintableStringRef::new(p).unwrap().to_der().unwrap();
            let mut set = vec![0x31, value.len() as u8];
            set.extend(value);
            vec![rcgen::Attribute { oid: &[1, 2, 840, 113549, 1, 9, 7], values: set }]
        }
        None => Vec::new(),
    };
    params.serialize_request_with_attributes(&d.key, attrs).unwrap().der().to_vec()
}

fn attribute(oid: &str, value: Any) -> Attribute {
    let mut values = SetOfVec::new();
    values.insert(value).unwrap();
    Attribute { oid: ObjectIdentifier::new_unwrap(oid), values }
}

fn printable(s: &str) -> Any {
    Any::encode_from(&PrintableStringRef::new(s).unwrap()).unwrap()
}

/// A SCEP `pkiMessage`: `content` enveloped for the RA, signed by the
/// device.
fn pki_message(d: &Device, ra: &Certificate, message_type: &str, transaction: &str, content: &[u8]) -> Vec<u8> {
    let mut rng = rand_core_06::OsRng;
    let mut key_rng = rand_core_06::OsRng;
    let ra_key = rsa::RsaPublicKey::try_from(ra.tbs_certificate.subject_public_key_info.owned_to_ref()).unwrap();
    let rid = RecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: ra.tbs_certificate.issuer.clone(),
        serial_number: ra.tbs_certificate.serial_number.clone(),
    });
    let mut env = EnvelopedDataBuilder::new(None, content, ContentEncryptionAlgorithm::Aes256Cbc, None).unwrap();
    env.add_recipient_info(
        KeyTransRecipientInfoBuilder::new(rid, KeyEncryptionInfo::Rsa(ra_key), &mut key_rng).unwrap(),
    )
    .unwrap();
    let enveloped = env.build_with_rng(&mut rng).unwrap();
    let envelope = ContentInfo { content_type: const_oid_enveloped(), content: Any::encode_from(&enveloped).unwrap() }
        .to_der()
        .unwrap();

    let encap = EncapsulatedContentInfo {
        econtent_type: ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1"),
        econtent: Some(Any::encode_from(&OctetString::new(envelope).unwrap()).unwrap()),
    };
    let signer = rsa::pkcs1v15::SigningKey::<sha2_010::Sha256>::new(d.rsa.clone());
    let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: d.cert.tbs_certificate.issuer.clone(),
        serial_number: d.cert.tbs_certificate.serial_number.clone(),
    });
    let digest =
        AlgorithmIdentifierOwned { oid: ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"), parameters: None };
    let mut si = SignerInfoBuilder::new(&signer, sid, digest.clone(), &encap, None).unwrap();
    si.add_signed_attribute(attribute(MESSAGE_TYPE, printable(message_type))).unwrap();
    si.add_signed_attribute(attribute(TRANSACTION_ID, printable(transaction))).unwrap();
    si.add_signed_attribute(attribute(
        SENDER_NONCE,
        Any::encode_from(&OctetString::new(vec![7u8; 16]).unwrap()).unwrap(),
    ))
    .unwrap();
    let signed = SignedDataBuilder::new(&encap)
        .add_digest_algorithm(digest)
        .unwrap()
        .add_certificate(CertificateChoices::Certificate(d.cert.clone()))
        .unwrap()
        .add_signer_info::<_, rsa::pkcs1v15::Signature>(si)
        .unwrap()
        .build()
        .unwrap();
    signed.to_der().unwrap()
}

fn const_oid_enveloped() -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.3")
}

/// What a `CertRep` says: its status attributes and, on success, the
/// certificates in its envelope (opened with the device key).
struct CertRep {
    status: String,
    fail_info: Option<String>,
    recipient_nonce: Vec<u8>,
    transaction: String,
    certs: Vec<Vec<u8>>,
}

fn read_cert_rep(body: &[u8], d: &Device, ra: &Certificate) -> CertRep {
    let info = ContentInfo::from_der(body).expect("a CMS ContentInfo");
    let sd: SignedData = info.content.decode_as().unwrap();
    let si = sd.signer_infos.0.get(0).expect("a signer");
    let attrs = si.signed_attrs.as_ref().expect("signed attributes");
    // The RA signed it.
    let ra_der = ra.to_der().unwrap();
    let (_, ra_parsed) = X509Certificate::from_der(&ra_der).unwrap();
    aws_lc_rs::signature::UnparsedPublicKey::new(
        &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256,
        ra_parsed.public_key().subject_public_key.data.as_ref(),
    )
    .verify(&attrs.to_der().unwrap(), si.signature.as_bytes())
    .expect("the RA's signature verifies");
    let get = |oid: &str| -> Option<Any> {
        attrs.iter().find(|a| a.oid == ObjectIdentifier::new_unwrap(oid)).map(|a| a.values.get(0).unwrap().clone())
    };
    let text = |oid: &str| get(oid).map(|v| String::from_utf8(v.value().to_vec()).unwrap());
    assert_eq!(text(MESSAGE_TYPE).as_deref(), Some("3"), "a CertRep");
    let mut certs = Vec::new();
    if let Some(econtent) = &sd.encap_content_info.econtent {
        let envelope: OctetString = econtent.decode_as().unwrap();
        let env_info = ContentInfo::from_der(envelope.as_bytes()).unwrap();
        let ed: EnvelopedData = env_info.content.decode_as().unwrap();
        let RecipientInfo::Ktri(ktri) = ed.recip_infos.0.get(0).unwrap() else { panic!("key transport") };
        let cek = d.rsa.decrypt(rsa::Pkcs1v15Encrypt, ktri.enc_key.as_bytes()).expect("encrypted to the device key");
        let alg = &ed.encrypted_content.content_enc_alg;
        let iv: OctetString = alg.parameters.as_ref().unwrap().decode_as().unwrap();
        let ciphertext = ed.encrypted_content.encrypted_content.as_ref().unwrap().as_bytes();
        use cbc::cipher::{BlockDecryptMut, KeyIvInit};
        let plain = match cek.len() {
            32 => cbc::Decryptor::<aes::Aes256>::new_from_slices(&cek, iv.as_bytes())
                .unwrap()
                .decrypt_padded_vec_mut::<cbc::cipher::block_padding::Pkcs7>(ciphertext)
                .unwrap(),
            n => panic!("unexpected key length {n}"),
        };
        let inner = ContentInfo::from_der(&plain).unwrap();
        let degenerate: SignedData = inner.content.decode_as().unwrap();
        for c in degenerate.certificates.unwrap().0.iter() {
            if let CertificateChoices::Certificate(c) = c {
                certs.push(c.to_der().unwrap());
            }
        }
    }
    CertRep {
        status: text(PKI_STATUS).unwrap(),
        fail_info: text(FAIL_INFO),
        recipient_nonce: get(RECIPIENT_NONCE).map(|v| v.value().to_vec()).unwrap_or_default(),
        transaction: text(TRANSACTION_ID).unwrap_or_default(),
        certs,
    }
}

/// A connector once it has left `CREATING` (Connector for SCEP has no SDK
/// waiter, so poll as AWS's own examples do).
pub(crate) async fn wait_connector(scep: &Scep, arn: &str) -> aws_sdk_pcaconnectorscep::types::Connector {
    for _ in 0..300 {
        let got = scep.get_connector().connector_arn(arn).send().await.unwrap();
        let c = got.connector().unwrap().clone();
        if c.status().map(|s| s.as_str()) != Some("CREATING") {
            return c;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("connector {arn} is still CREATING");
}

/// Wait until a deleted connector is gone (it is `DELETING` first).
async fn wait_connector_gone(scep: &Scep, arn: &str) {
    for _ in 0..300 {
        match scep.get_connector().connector_arn(arn).send().await {
            Err(e) if e.code() == Some("ResourceNotFoundException") => return,
            Ok(got) => assert_eq!(got.connector().unwrap().status().unwrap().as_str(), "DELETING"),
            Err(e) => panic!("{e:?}"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("connector {arn} was not deleted");
}

fn pem_of(der: &[u8]) -> String {
    use base64::Engine;
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::engine::general_purpose::STANDARD.encode(der)
    )
}

#[tokio::test]
async fn devices_enroll_over_scep_with_a_ca_shared_through_ram() {
    let mws = Mws::start().await;
    let root = mws.root_sdk_config().await;
    let pca = aws_sdk_acmpca::Client::new(&root);
    let scep = Scep::new(&root);
    let ram = Ram::new(&root);
    let (ca, ca_pem) = active_root(&pca).await;

    // Not shared with the connector yet: it fails, as in AWS.
    let failed = scep.create_connector().certificate_authority_arn(&ca).send().await.unwrap();
    let failed = failed.connector_arn().unwrap().to_string();
    // Connectors are CREATING first, like in AWS (for the settle window, which
    // a heavily loaded test run can outlast before this call).
    let got = scep.get_connector().connector_arn(&failed).send().await.unwrap();
    let status = got.connector().unwrap().status().unwrap().as_str().to_string();
    if status == "CREATING" {
        let err = scep.delete_connector().connector_arn(&failed).send().await.unwrap_err();
        assert_eq!(err.code(), Some("ConflictException"));
    } else {
        assert_eq!(status, "FAILED");
    }
    let got = wait_connector(&scep, &failed).await;
    assert_eq!(got.status().unwrap().as_str(), "FAILED");
    assert_eq!(got.status_reason().unwrap().as_str(), "PRIVATECA_ACCESS_DENIED");
    let err = scep.create_challenge().connector_arn(&failed).send().await.unwrap_err();
    assert_eq!(err.code(), Some("ValidationException"));
    scep.delete_connector().connector_arn(&failed).send().await.unwrap();
    wait_connector_gone(&scep, &failed).await;

    // Share the CA with the connector's service principal, as the AWS
    // setup guide does.
    ram.create_resource_share()
        .name("MyPcaConnectorScepResourceShare")
        .permission_arns(SCEP_PERMISSION)
        .resource_arns(&ca)
        .principals("pca-connector-scep.amazonaws.com")
        .sources("123456789012")
        .send()
        .await
        .unwrap();
    let created = scep.create_connector().certificate_authority_arn(&ca).tags("env", "test").send().await.unwrap();
    let arn = created.connector_arn().unwrap().to_string();
    assert!(arn.starts_with("arn:aws:pca-connector-scep:us-east-1:123456789012:connector/"));
    let connector = wait_connector(&scep, &arn).await;
    assert_eq!(connector.status().unwrap().as_str(), "ACTIVE");
    assert_eq!(connector.r#type().unwrap().as_str(), "GENERAL_PURPOSE");
    let endpoint = connector.endpoint().unwrap().to_string();
    assert!(endpoint.starts_with(&mws.endpoint), "{endpoint}");
    let listed = scep.list_connectors().send().await.unwrap();
    assert_eq!(listed.connectors().len(), 1);

    // Challenge passwords.
    let challenge = scep.create_challenge().connector_arn(&arn).tags("device", "laptop").send().await.unwrap();
    let challenge = challenge.challenge().unwrap();
    let challenge_arn = challenge.arn().unwrap().to_string();
    let password = challenge.password().unwrap().to_string();
    let fetched = scep.get_challenge_password().challenge_arn(&challenge_arn).send().await.unwrap();
    assert_eq!(fetched.password(), Some(password.as_str()));
    let meta = scep.get_challenge_metadata().challenge_arn(&challenge_arn).send().await.unwrap();
    assert_eq!(meta.challenge_metadata().unwrap().connector_arn(), Some(arn.as_str()));
    let all = scep.list_challenge_metadata().connector_arn(&arn).send().await.unwrap();
    assert_eq!(all.challenges().len(), 1);
    scep.tag_resource().resource_arn(&challenge_arn).tags("owner", "it").send().await.unwrap();
    scep.untag_resource().resource_arn(&challenge_arn).tag_keys("device").send().await.unwrap();
    let tags = scep.list_tags_for_resource().resource_arn(&challenge_arn).send().await.unwrap();
    assert_eq!(tags.tags().unwrap().keys().collect::<Vec<_>>(), vec!["owner"]);
    let tags = scep.list_tags_for_resource().resource_arn(&arn).send().await.unwrap();
    assert_eq!(tags.tags().unwrap().get("env").map(String::as_str), Some("test"));

    // SCEP: capabilities and the CA chain (the RA certificate first).
    let (status, headers, caps) =
        mws.raw("GET", &format!("{endpoint}/pkiclient.exe?operation=GetCACaps"), &[], b"").await;
    assert_eq!(status, 200);
    let caps = String::from_utf8(caps).unwrap();
    assert!(caps.lines().any(|l| l == "AES") && caps.lines().any(|l| l == "POSTPKIOperation"), "{caps}");
    assert!(headers.iter().any(|(k, v)| k == "content-type" && v == "text/plain"));
    let (status, headers, body) = mws.raw("GET", &format!("{endpoint}?operation=GetCACert"), &[], b"").await;
    assert_eq!(status, 200);
    assert!(headers.iter().any(|(k, v)| k == "content-type" && v == "application/x-x509-ca-ra-cert"));
    let certs: SignedData = ContentInfo::from_der(&body).unwrap().content.decode_as().unwrap();
    let certs: Vec<Certificate> = certs
        .certificates
        .unwrap()
        .0
        .iter()
        .filter_map(|c| match c {
            CertificateChoices::Certificate(c) => Some(c.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(certs.len(), 2);
    // The RA certificate is the one the CA issued (a CMS SET has no order
    // once decoded); the other is the CA itself.
    let ca_der = parse_x509_pem(ca_pem.as_bytes()).unwrap().1.contents;
    let (ca_certs, ra_certs): (Vec<_>, Vec<_>) = certs.into_iter().partition(|c| c.to_der().unwrap() == ca_der);
    assert_eq!((ca_certs.len(), ra_certs.len()), (1, 1));
    let ra = ra_certs[0].clone();
    assert_signed_by(&pem_of(&ra.to_der().unwrap()), &ca_pem);

    // Enroll (PKCSReq) over POST.
    let d = device("laptop-1");
    let request = pki_message(&d, &ra, "19", "tx-1", &csr(&d, "laptop-1", Some(&password)));
    let (status, headers, body) = mws
        .raw(
            "POST",
            &format!("{endpoint}/pkiclient.exe?operation=PKIOperation"),
            &[("Content-Type", "application/x-pki-message")],
            &request,
        )
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert!(headers.iter().any(|(k, v)| k == "content-type" && v == "application/x-pki-message"));
    let rep = read_cert_rep(&body, &d, &ra);
    assert_eq!(rep.status, "0");
    assert_eq!(rep.transaction, "tx-1");
    assert_eq!(rep.recipient_nonce, vec![7u8; 16]);
    assert_eq!(rep.certs.len(), 1);
    let issued_pem = pem_of(&rep.certs[0]);
    assert_signed_by(&issued_pem, &ca_pem);
    let (_, issued) = X509Certificate::from_der(&rep.certs[0]).unwrap();
    assert_eq!(issued.subject().iter_common_name().next().unwrap().as_str().unwrap(), "laptop-1");
    assert_eq!(issued.public_key().raw, d.cert.tbs_certificate.subject_public_key_info.to_der().unwrap().as_slice());
    let eku = issued.extended_key_usage().unwrap().expect("an EKU").value;
    assert!(eku.client_auth, "no EKU in the CSR means clientAuth");
    let days = (issued.validity().not_after.timestamp() - issued.validity().not_before.timestamp()) / 86400;
    assert!((364..=366).contains(&days), "one year by default, got {days} days");
    // Private CA knows the certificate.
    let serial: String = issued.raw_serial().iter().map(|b| format!("{b:02x}")).collect();
    let got = crate::acmpca::wait_cert(&pca, &ca, &format!("{ca}/certificate/{serial}")).await;
    assert!(got.certificate().is_some());

    // GetCertInitial for the same transaction returns it again (over GET).
    use base64::Engine;
    let poll = pki_message(&d, &ra, "20", "tx-1", b"poll");
    let message = urlencoding::encode(&base64::engine::general_purpose::STANDARD.encode(&poll)).into_owned();
    let (status, _, body) =
        mws.raw("GET", &format!("{endpoint}?operation=PKIOperation&message={message}"), &[], b"").await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(read_cert_rep(&body, &d, &ra).certs, rep.certs);

    // A wrong challenge password is refused with a SCEP failure.
    let bad = pki_message(&d, &ra, "19", "tx-2", &csr(&d, "laptop-1", Some("not-the-password")));
    let (status, _, body) = mws.raw("POST", &format!("{endpoint}?operation=PKIOperation"), &[], &bad).await;
    assert_eq!(status, 400);
    let rep = read_cert_rep(&body, &d, &ra);
    assert_eq!(rep.status, "2");
    assert_eq!(rep.fail_info.as_deref(), Some("2"));
    assert!(rep.certs.is_empty());
    // No password at all.
    let none = pki_message(&d, &ra, "19", "tx-3", &csr(&d, "laptop-1", None));
    let (status, _, body) = mws.raw("POST", &format!("{endpoint}?operation=PKIOperation"), &[], &none).await;
    assert_eq!(status, 400);
    assert!(String::from_utf8_lossy(&body).contains("Exactly one challenge password is required"));
    // Garbage, and an unknown connector.
    let (status, _, body) = mws.raw("POST", &format!("{endpoint}?operation=PKIOperation"), &[], b"garbage").await;
    assert_eq!(status, 400);
    assert!(String::from_utf8_lossy(&body).contains("invalid Cryptographic Message Syntax"));
    let (status, _, _) =
        mws.raw("GET", &format!("{}/_aws/pca-connector-scep/nope?operation=GetCACaps", mws.endpoint), &[], b"").await;
    assert_eq!(status, 404);

    // Deleting the challenge stops it working.
    scep.delete_challenge().challenge_arn(&challenge_arn).send().await.unwrap();
    let again = pki_message(&d, &ra, "19", "tx-4", &csr(&d, "laptop-1", Some(&password)));
    let (status, _, _) = mws.raw("POST", &format!("{endpoint}?operation=PKIOperation"), &[], &again).await;
    assert_eq!(status, 400);

    // Removing the share takes the connector's access away.
    let shares =
        ram.get_resource_shares().resource_owner(aws_sdk_ram::types::ResourceOwner::SelfValue).send().await.unwrap();
    let share_arn = shares.resource_shares()[0].resource_share_arn().unwrap().to_string();
    ram.delete_resource_share().resource_share_arn(&share_arn).send().await.unwrap();
    let challenge = scep.create_challenge().connector_arn(&arn).send().await.unwrap();
    let password = challenge.challenge().unwrap().password().unwrap().to_string();
    let denied = pki_message(&d, &ra, "19", "tx-5", &csr(&d, "laptop-1", Some(&password)));
    let (status, _, body) = mws.raw("POST", &format!("{endpoint}?operation=PKIOperation"), &[], &denied).await;
    assert_eq!(status, 401, "{}", String::from_utf8_lossy(&body));

    scep.delete_connector().connector_arn(&arn).send().await.unwrap();
    let got = scep.get_connector().connector_arn(&arn).send().await.unwrap();
    assert_eq!(got.connector().unwrap().status().unwrap().as_str(), "DELETING");
    let err = scep.delete_connector().connector_arn(&arn).send().await.unwrap_err();
    assert_eq!(err.code(), Some("ConflictException"));
    wait_connector_gone(&scep, &arn).await;
}

#[tokio::test]
async fn connectors_check_their_ca_and_type() {
    let mws = Mws::start().await;
    let root = mws.root_sdk_config().await;
    let scep = Scep::new(&root);
    let err = scep
        .create_connector()
        .certificate_authority_arn(
            "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/11111111-1111-1111-1111-111111111111",
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("ResourceNotFoundException"));

    // A CA certificate valid for less than a year is refused.
    let pca = aws_sdk_acmpca::Client::new(&root);
    let (ca, _) = active_root(&pca).await;
    mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds": 293760000}"#)).await;
    let err = scep.create_connector().certificate_authority_arn(&ca).send().await.unwrap_err();
    assert!(matches!(err.code(), Some("ValidationException")), "{err:?}");
    mws.control("POST", "/_mws/clock", Some(r#"{"offsetSeconds": 0}"#)).await;

    // Intune connectors have an OpenID configuration and no static passwords.
    let (ca, _) = active_root(&pca).await;
    let intune = scep
        .create_connector()
        .certificate_authority_arn(&ca)
        .mobile_device_management(aws_sdk_pcaconnectorscep::types::MobileDeviceManagement::Intune(
            aws_sdk_pcaconnectorscep::types::IntuneConfiguration::builder()
                .azure_application_id("11111111-2222-3333-4444-555555555555")
                .domain("example.onmicrosoft.com")
                .build()
                .unwrap(),
        ))
        .send()
        .await
        .unwrap();
    let arn = intune.connector_arn().unwrap();
    let got = wait_connector(&scep, arn).await;
    assert_eq!(got.r#type().unwrap().as_str(), "INTUNE");
    assert!(got.open_id_configuration().unwrap().issuer().is_some());
    let err = scep.create_challenge().connector_arn(arn).send().await.unwrap_err();
    assert_eq!(err.code(), Some("ValidationException"));
}
