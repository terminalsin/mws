//! XML signature verification for SAML responses (XML-DSig with exclusive
//! or inclusive canonicalization, enveloped signatures), as
//! `AssumeRoleWithSAML` requires: the assertion, or the response that
//! carries it, must be signed by a certificate in the SAML provider's
//! metadata.

use std::collections::BTreeMap;

use base64::Engine;
use roxmltree::{Document, Node, NodeType};

const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
const METADATA: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const EXC_C14N_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
const C14N: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const C14N_COMMENTS: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// How to canonicalize.
#[derive(Clone)]
enum Mode {
    Exclusive { inclusive_prefixes: Vec<String> },
    Inclusive,
}

fn mode_for(algorithm: &str, transform: Option<Node<'_, '_>>) -> Option<(Mode, bool)> {
    match algorithm {
        EXC_C14N | EXC_C14N_COMMENTS => {
            let prefixes = transform
                .and_then(|t| t.children().find(|c| c.is_element() && c.tag_name().name() == "InclusiveNamespaces"))
                .and_then(|n| n.attribute("PrefixList"))
                .map(|l| {
                    l.split_whitespace().map(|p| if p == "#default" { String::new() } else { p.to_string() }).collect()
                })
                .unwrap_or_default();
            Some((Mode::Exclusive { inclusive_prefixes: prefixes }, algorithm == EXC_C14N_COMMENTS))
        }
        C14N | C14N_COMMENTS => Some((Mode::Inclusive, algorithm == C14N_COMMENTS)),
        _ => None,
    }
}

/// The qualified name of an element as written.
fn element_qname<'a>(xml: &'a str, node: Node<'_, '_>) -> &'a str {
    let raw = &xml[node.range().start + 1..];
    let end = raw.find(|c: char| c.is_whitespace() || c == '/' || c == '>').unwrap_or(raw.len());
    &raw[..end]
}

fn prefix_of(qname: &str) -> &str {
    qname.split_once(':').map(|(p, _)| p).unwrap_or("")
}

fn escape_text(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

fn escape_attr(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

struct Canon<'x> {
    xml: &'x str,
    mode: Mode,
    comments: bool,
    /// A node left out (the enveloped signature).
    skip: Option<roxmltree::NodeId>,
}

impl Canon<'_> {
    fn render(&self, node: Node<'_, '_>, rendered: &BTreeMap<String, String>, out: &mut String) {
        if Some(node.id()) == self.skip {
            return;
        }
        match node.node_type() {
            NodeType::Element => self.element(node, rendered, out),
            NodeType::Text => escape_text(node.text().unwrap_or_default(), out),
            NodeType::Comment if self.comments => {
                out.push_str("<!--");
                out.push_str(node.text().unwrap_or_default());
                out.push_str("-->");
            }
            NodeType::PI => {
                if let Some(pi) = node.pi() {
                    out.push_str("<?");
                    out.push_str(pi.target);
                    if let Some(v) = pi.value {
                        out.push(' ');
                        out.push_str(v);
                    }
                    out.push_str("?>");
                }
            }
            _ => {}
        }
    }

    fn element(&self, node: Node<'_, '_>, rendered: &BTreeMap<String, String>, out: &mut String) {
        let qname = element_qname(self.xml, node);
        // Namespace bindings in scope here, by prefix ("" = default).
        let scope: BTreeMap<String, String> = node
            .namespaces()
            .filter(|ns| ns.name() != Some("xml"))
            .map(|ns| (ns.name().unwrap_or("").to_string(), ns.uri().to_string()))
            .collect();
        let attrs: Vec<(String, String, String, String)> = node
            .attributes()
            .map(|a| {
                let q = self.xml[a.range_qname()].to_string();
                (a.namespace().unwrap_or("").to_string(), a.name().to_string(), q, a.value().to_string())
            })
            .collect();
        let candidates: Vec<String> = match &self.mode {
            Mode::Inclusive => scope.keys().cloned().chain(std::iter::once(String::new())).collect(),
            Mode::Exclusive { inclusive_prefixes } => {
                let mut used = vec![prefix_of(qname).to_string()];
                used.extend(attrs.iter().map(|a| prefix_of(&a.2).to_string()).filter(|p| !p.is_empty() && p != "xml"));
                used.extend(inclusive_prefixes.iter().filter(|p| scope.contains_key(*p) || p.is_empty()).cloned());
                used
            }
        };
        let mut decls: BTreeMap<String, String> = BTreeMap::new();
        for p in candidates {
            let uri = scope.get(&p).cloned().unwrap_or_default();
            let already = rendered.get(&p);
            let needed = if p.is_empty() {
                // xmlns="" only to undo a default an ancestor rendered.
                match already {
                    Some(prev) => prev != &uri,
                    None => !uri.is_empty(),
                }
            } else {
                already != Some(&uri) && !uri.is_empty()
            };
            if needed {
                decls.insert(p, uri);
            }
        }
        out.push('<');
        out.push_str(qname);
        for (p, uri) in &decls {
            if p.is_empty() {
                out.push_str(" xmlns=\"");
            } else {
                out.push_str(" xmlns:");
                out.push_str(p);
                out.push_str("=\"");
            }
            escape_attr(uri, out);
            out.push('"');
        }
        let mut sorted = attrs;
        sorted.sort_by(|a, b| (a.0.as_str(), a.1.as_str()).cmp(&(b.0.as_str(), b.1.as_str())));
        for (_, _, q, v) in &sorted {
            out.push(' ');
            out.push_str(q);
            out.push_str("=\"");
            escape_attr(v, out);
            out.push('"');
        }
        out.push('>');
        let mut inner = rendered.clone();
        inner.extend(decls);
        for child in node.children() {
            self.render(child, &inner, out);
        }
        out.push_str("</");
        out.push_str(qname);
        out.push('>');
    }
}

fn canonicalize(xml: &str, apex: Node<'_, '_>, mode: Mode, comments: bool, skip: Option<roxmltree::NodeId>) -> String {
    let canon = Canon { xml, mode, comments, skip };
    let mut out = String::new();
    canon.render(apex, &BTreeMap::new(), &mut out);
    out
}

fn child<'a, 'i>(n: Node<'a, 'i>, ns: &str, name: &str) -> Option<Node<'a, 'i>> {
    n.children().find(|c| c.has_tag_name((ns, name)))
}

fn b64(s: &str) -> Option<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(cleaned).ok()
}

fn digest(algorithm: &str, data: &[u8]) -> Option<Vec<u8>> {
    use aws_lc_rs::digest;
    let alg = match algorithm {
        "http://www.w3.org/2000/09/xmldsig#sha1" => &digest::SHA1_FOR_LEGACY_USE_ONLY,
        "http://www.w3.org/2001/04/xmlenc#sha256" => &digest::SHA256,
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => &digest::SHA384,
        "http://www.w3.org/2001/04/xmlenc#sha512" => &digest::SHA512,
        _ => return None,
    };
    Some(digest::digest(alg, data).as_ref().to_vec())
}

/// Certificates (DER) the metadata lists for signing.
pub fn signing_certificates(metadata: &str) -> Vec<Vec<u8>> {
    let Ok(doc) = Document::parse(metadata) else { return vec![] };
    doc.descendants()
        .filter(|n| n.has_tag_name((METADATA, "KeyDescriptor")))
        .filter(|n| n.attribute("use").is_none_or(|u| u == "signing"))
        .flat_map(|n| n.descendants().filter(|c| c.has_tag_name((DSIG, "X509Certificate"))))
        .filter_map(|c| b64(c.text().unwrap_or_default()))
        .collect()
}

fn verify_signature_value(algorithm: &str, cert_der: &[u8], message: &[u8], sig: &[u8]) -> bool {
    use aws_lc_rs::signature::{self, UnparsedPublicKey};
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(cert_der) else { return false };
    let key = cert.public_key().subject_public_key.data.as_ref();
    let rsa: Option<&'static signature::RsaParameters> = match algorithm {
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => Some(&signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => Some(&signature::RSA_PKCS1_2048_8192_SHA256),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => Some(&signature::RSA_PKCS1_2048_8192_SHA384),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => Some(&signature::RSA_PKCS1_2048_8192_SHA512),
        _ => None,
    };
    if let Some(params) = rsa {
        return UnparsedPublicKey::new(params, key).verify(message, sig).is_ok();
    }
    let ec: &'static signature::EcdsaVerificationAlgorithm = match algorithm {
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" => &signature::ECDSA_P256_SHA256_FIXED,
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384" => &signature::ECDSA_P384_SHA384_FIXED,
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512" => &signature::ECDSA_P521_SHA512_FIXED,
        _ => return false,
    };
    UnparsedPublicKey::new(ec, key).verify(message, sig).is_ok()
}

fn element_id<'a>(n: Node<'a, '_>) -> Option<&'a str> {
    n.attribute("ID").or_else(|| n.attribute("AssertionID")).or_else(|| n.attribute("Id"))
}

/// Whether `signed` (an element carrying an enveloped `ds:Signature`)
/// verifies against one of `certs`.
fn verify_element(xml: &str, doc: &Document<'_>, signed: Node<'_, '_>, certs: &[Vec<u8>]) -> bool {
    let Some(sig) = child(signed, DSIG, "Signature") else { return false };
    let Some(info) = child(sig, DSIG, "SignedInfo") else { return false };
    let (Some(c14n), Some(method)) =
        (child(info, DSIG, "CanonicalizationMethod"), child(info, DSIG, "SignatureMethod"))
    else {
        return false;
    };
    let Some((info_mode, info_comments)) = mode_for(c14n.attribute("Algorithm").unwrap_or_default(), Some(c14n)) else {
        return false;
    };
    let references: Vec<Node<'_, '_>> = info.children().filter(|c| c.has_tag_name((DSIG, "Reference"))).collect();
    // Exactly one reference, and it must name the signed element itself.
    let [reference] = references.as_slice() else { return false };
    let uri = reference.attribute("URI").unwrap_or_default();
    let target_ok = match uri.strip_prefix('#') {
        Some(id) => element_id(signed) == Some(id),
        None => uri.is_empty() && doc.root_element() == signed,
    };
    if !target_ok {
        return false;
    }
    // IDs must be unique, or a wrapped copy could be the one verified.
    if let Some(id) = element_id(signed) {
        if doc.descendants().filter(|n| n.is_element() && element_id(*n) == Some(id)).count() != 1 {
            return false;
        }
    }
    let mut mode = Mode::Exclusive { inclusive_prefixes: vec![] };
    let mut comments = false;
    let mut enveloped = false;
    if let Some(transforms) = child(*reference, DSIG, "Transforms") {
        for t in transforms.children().filter(|c| c.has_tag_name((DSIG, "Transform"))) {
            let alg = t.attribute("Algorithm").unwrap_or_default();
            if alg == ENVELOPED {
                enveloped = true;
            } else if let Some((m, c)) = mode_for(alg, Some(t)) {
                mode = m;
                comments = c;
            } else {
                return false;
            }
        }
    }
    if !enveloped {
        return false;
    }
    let (Some(digest_method), Some(digest_value)) =
        (child(*reference, DSIG, "DigestMethod"), child(*reference, DSIG, "DigestValue"))
    else {
        return false;
    };
    let canonical = canonicalize(xml, signed, mode, comments, Some(sig.id()));
    let Some(computed) = digest(digest_method.attribute("Algorithm").unwrap_or_default(), canonical.as_bytes()) else {
        return false;
    };
    if b64(digest_value.text().unwrap_or_default()).as_deref() != Some(computed.as_slice()) {
        return false;
    }
    let Some(value) = child(sig, DSIG, "SignatureValue").and_then(|v| b64(v.text().unwrap_or_default())) else {
        return false;
    };
    let signed_info = canonicalize(xml, info, info_mode, info_comments, None);
    let algorithm = method.attribute("Algorithm").unwrap_or_default();
    certs.iter().any(|c| verify_signature_value(algorithm, c, signed_info.as_bytes(), &value))
}

/// Check that `assertion_xml` (a SAML Response or bare Assertion) carries a
/// valid signature over the assertion AWS will read: on the assertion
/// itself or on the response that contains it.
pub fn verify(xml: &str, certs: &[Vec<u8>]) -> bool {
    const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
    const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
    let Ok(doc) = Document::parse(xml) else { return false };
    let Some(assertion) = doc.descendants().find(|n| n.has_tag_name((ASSERTION, "Assertion"))) else { return false };
    if verify_element(xml, &doc, assertion, certs) {
        return true;
    }
    let root = doc.root_element();
    root.has_tag_name((PROTOCOL, "Response"))
        && assertion.parent() == Some(root)
        && verify_element(xml, &doc, root, certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(xml: &str, mode: Mode) -> String {
        let doc = Document::parse(xml).unwrap();
        let apex = doc.root_element().first_element_child().unwrap();
        canonicalize(xml, apex, mode, false, None)
    }

    #[test]
    fn exclusive_canonicalization_renders_only_used_namespaces() {
        let xml = r#"<a:root xmlns:a="urn:a" xmlns:b="urn:b" xmlns="urn:d"><a:child z='1' b:y="2&lt;" a="x"><!--c--><b:x/>t&amp;</a:child></a:root>"#;
        assert_eq!(
            canon(xml, Mode::Exclusive { inclusive_prefixes: vec![] }),
            r#"<a:child xmlns:a="urn:a" xmlns:b="urn:b" a="x" z="1" b:y="2&lt;"><b:x></b:x>t&amp;</a:child>"#
        );
        assert_eq!(
            canon(xml, Mode::Inclusive),
            r#"<a:child xmlns="urn:d" xmlns:a="urn:a" xmlns:b="urn:b" a="x" z="1" b:y="2&lt;"><b:x></b:x>t&amp;</a:child>"#
        );
    }
}
