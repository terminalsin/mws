//! SAML 2.0 response handling for `AssumeRoleWithSAML`.
//!
//! MWS checks what AWS checks in the assertion (issuer registered as the
//! named SAML provider, audience, validity window, the Role and
//! RoleSessionName attributes); the XML signature is checked in
//! [`crate::saml_sig`].

use base64::Engine;
use chrono::{DateTime, Utc};

const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const METADATA: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
pub const ATTR_ROLE: &str = "https://aws.amazon.com/SAML/Attributes/Role";
pub const ATTR_SESSION_NAME: &str = "https://aws.amazon.com/SAML/Attributes/RoleSessionName";
pub const ATTR_SESSION_DURATION: &str = "https://aws.amazon.com/SAML/Attributes/SessionDuration";
pub const ATTR_SOURCE_IDENTITY: &str = "https://aws.amazon.com/SAML/Attributes/SourceIdentity";
pub const ATTR_TAG_PREFIX: &str = "https://aws.amazon.com/SAML/Attributes/PrincipalTag:";
pub const ATTR_TRANSITIVE: &str = "https://aws.amazon.com/SAML/Attributes/TransitiveTagKeys";

#[derive(Debug, Default)]
pub struct Assertion {
    pub issuer: String,
    pub subject: Option<String>,
    pub subject_format: Option<String>,
    pub audiences: Vec<String>,
    pub recipient: Option<String>,
    pub not_before: Option<DateTime<Utc>>,
    pub not_on_or_after: Option<DateTime<Utc>>,
    /// Attribute name → values.
    pub attributes: Vec<(String, Vec<String>)>,
}

impl Assertion {
    pub fn attribute(&self, name: &str) -> Option<&[String]> {
        self.attributes.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_slice())
    }

    /// `persistent`, `transient`, or the full format URI for other formats.
    pub fn subject_type(&self) -> Option<String> {
        self.subject_format.as_ref().map(|f| {
            f.strip_prefix("urn:oasis:names:tc:SAML:2.0:nameid-format:")
                .or_else(|| f.strip_prefix("urn:oasis:names:tc:SAML:1.1:nameid-format:"))
                .unwrap_or(f)
                .to_string()
        })
    }
}

fn time(s: Option<&str>) -> Option<DateTime<Utc>> {
    s.and_then(|v| DateTime::parse_from_rfc3339(v).ok()).map(|d| d.with_timezone(&Utc))
}

/// The XML of a base64-encoded SAML response.
pub fn decode(encoded: &str) -> Option<String> {
    let cleaned: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = base64::engine::general_purpose::STANDARD.decode(cleaned).ok()?;
    String::from_utf8(bytes).ok()
}

/// Parse a base64-encoded SAML `Response` (or bare `Assertion`).
pub fn parse(encoded: &str) -> Option<Assertion> {
    let xml = decode(encoded)?;
    let doc = roxmltree::Document::parse(&xml).ok()?;
    let assertion = doc.descendants().find(|n| n.has_tag_name((ASSERTION, "Assertion")))?;
    fn child<'a, 'i>(n: roxmltree::Node<'a, 'i>, name: &str) -> Option<roxmltree::Node<'a, 'i>> {
        n.children().find(|c| c.has_tag_name((ASSERTION, name)))
    }
    let mut out = Assertion { issuer: child(assertion, "Issuer")?.text()?.trim().to_string(), ..Default::default() };
    if let Some(subject) = child(assertion, "Subject") {
        if let Some(id) = child(subject, "NameID") {
            out.subject = id.text().map(|t| t.trim().to_string());
            out.subject_format = id.attribute("Format").map(str::to_string);
        }
        if let Some(data) = subject.descendants().find(|n| n.has_tag_name((ASSERTION, "SubjectConfirmationData"))) {
            out.recipient = data.attribute("Recipient").map(str::to_string);
            out.not_on_or_after = time(data.attribute("NotOnOrAfter"));
        }
    }
    if let Some(conditions) = child(assertion, "Conditions") {
        out.not_before = time(conditions.attribute("NotBefore"));
        if let Some(t) = time(conditions.attribute("NotOnOrAfter")) {
            out.not_on_or_after = Some(out.not_on_or_after.map_or(t, |s| s.min(t)));
        }
        out.audiences = conditions
            .descendants()
            .filter(|n| n.has_tag_name((ASSERTION, "Audience")))
            .filter_map(|n| n.text().map(|t| t.trim().to_string()))
            .collect();
    }
    for attr in assertion.descendants().filter(|n| n.has_tag_name((ASSERTION, "Attribute"))) {
        let Some(name) = attr.attribute("Name") else { continue };
        let values = attr
            .children()
            .filter(|n| n.has_tag_name((ASSERTION, "AttributeValue")))
            .map(|n| n.text().unwrap_or_default().trim().to_string())
            .collect();
        out.attributes.push((name.to_string(), values));
    }
    Some(out)
}

/// The `entityID` a SAML provider's metadata declares.
pub fn metadata_entity_id(metadata: &str) -> Option<String> {
    let doc = roxmltree::Document::parse(metadata).ok()?;
    doc.descendants()
        .find(|n| n.has_tag_name((METADATA, "EntityDescriptor")))?
        .attribute("entityID")
        .map(str::to_string)
}

/// AWS's `NameQualifier`: base64(SHA-1(issuer + account id + "/" + provider name)).
pub fn name_qualifier(issuer: &str, account: &str, provider_name: &str) -> String {
    let digest = aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
        format!("{issuer}{account}/{provider_name}").as_bytes(),
    );
    base64::engine::general_purpose::STANDARD.encode(digest.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_response() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
<saml:Assertion><saml:Issuer>https://idp.example.com</saml:Issuer>
<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">alice</saml:NameID>
<saml:SubjectConfirmation><saml:SubjectConfirmationData Recipient="https://signin.aws.amazon.com/saml" NotOnOrAfter="2099-01-01T00:00:00Z"/></saml:SubjectConfirmation></saml:Subject>
<saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"><saml:AudienceRestriction><saml:Audience>https://signin.aws.amazon.com/saml</saml:Audience></saml:AudienceRestriction></saml:Conditions>
<saml:AttributeStatement><saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName"><saml:AttributeValue>alice</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
</saml:Assertion></samlp:Response>"#;
        let a = parse(&base64::engine::general_purpose::STANDARD.encode(xml)).unwrap();
        assert_eq!(a.issuer, "https://idp.example.com");
        assert_eq!(a.subject_type().as_deref(), Some("persistent"));
        assert_eq!(a.attribute(ATTR_SESSION_NAME).unwrap(), ["alice"]);
        assert_eq!(a.audiences, ["https://signin.aws.amazon.com/saml"]);
    }
}
