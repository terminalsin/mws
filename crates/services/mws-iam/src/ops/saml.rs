//! SAML 2.0 identity providers.

use chrono::{DateTime, Duration, Utc};
use mws_core::{RequestContext, ServiceError};

use crate::common::*;
use crate::generated::{errors, types};
use crate::state::SamlProvider;
use crate::Iam;

const MAX_SAML_PROVIDERS: usize = 100;
const MAX_PRIVATE_KEYS: usize = 2;
const MD_NS: &str = "urn:oasis:names:tc:SAML:2.0:metadata";

fn invalid_metadata() -> ServiceError {
    errors::invalid_input("Could not parse metadata")
}

/// Checks the document is SAML metadata describing an IdP and returns its
/// `validUntil` (AWS uses 100 years from now when absent).
fn parse_metadata(doc: &str) -> Result<DateTime<Utc>, ServiceError> {
    let xml = roxmltree::Document::parse(doc).map_err(|_| invalid_metadata())?;
    let root = xml.root_element();
    let descriptor = match (root.tag_name().namespace(), root.tag_name().name()) {
        (Some(MD_NS), "EntityDescriptor") => root,
        (Some(MD_NS), "EntitiesDescriptor") => {
            root.children().find(|n| n.has_tag_name((MD_NS, "EntityDescriptor"))).ok_or_else(invalid_metadata)?
        }
        _ => return Err(invalid_metadata()),
    };
    if !descriptor.children().any(|n| n.has_tag_name((MD_NS, "IDPSSODescriptor"))) {
        return Err(invalid_metadata());
    }
    match descriptor.attribute("validUntil").or_else(|| root.attribute("validUntil")) {
        Some(v) => DateTime::parse_from_rfc3339(v).map(|d| d.with_timezone(&Utc)).map_err(|_| invalid_metadata()),
        None => Ok(Utc::now() + Duration::days(365 * 100)),
    }
}

fn check_mode(mode: &Option<String>) -> Result<(), ServiceError> {
    match mode.as_deref() {
        None | Some("Allowed") | Some("Required") => Ok(()),
        Some(other) => Err(validation(format!(
            "1 validation error detected: Value '{other}' at 'assertionEncryptionMode' failed to satisfy constraint: Member must satisfy enum value set: [Required, Allowed]"
        ))),
    }
}

fn check_private_key(pem: &str) -> Result<(), ServiceError> {
    let ok = x509_parser::pem::parse_x509_pem(pem.trim().as_bytes())
        .is_ok_and(|(_, p)| matches!(p.label.as_str(), "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY"));
    if ok {
        Ok(())
    } else {
        Err(errors::invalid_input("The private key is not a valid PEM-encoded private key."))
    }
}

fn key_id() -> String {
    uuid::Uuid::new_v4().simple().to_string().to_uppercase()[..26].to_string()
}

fn no_such_provider(arn: &str) -> ServiceError {
    errors::no_such_entity(format!("Manifest not found for arn {arn}"))
}

fn private_keys(p: &SamlProvider) -> Option<Vec<types::SAMLPrivateKey>> {
    Some(
        p.private_keys
            .iter()
            .map(|(id, _, ts)| types::SAMLPrivateKey { key_id: Some(id.clone()), timestamp: Some(*ts) })
            .collect(),
    )
}

impl Iam {
    pub fn create_saml_provider(
        &self,
        ctx: &RequestContext,
        input: types::CreateSAMLProviderRequest,
    ) -> Result<types::CreateSAMLProviderResponse, ServiceError> {
        let arn = self.entity_arn("saml-provider", "/", &input.name);
        let tags = tags_from_wire(input.tags)?;
        self.authorize_with(ctx, "CreateSAMLProvider", &arn, request_tag_context(&tags))?;
        check_mode(&input.assertion_encryption_mode)?;
        let valid_until = parse_metadata(&input.saml_metadata_document)?;
        if let Some(k) = &input.add_private_key {
            check_private_key(k)?;
        }
        if input.assertion_encryption_mode.as_deref() == Some("Required") && input.add_private_key.is_none() {
            return Err(errors::invalid_input("A private key is required when AssertionEncryptionMode is Required."));
        }
        let mut state = self.write();
        if state.saml_providers.contains_key(&arn) {
            return Err(errors::entity_already_exists(format!("SAMLProvider {} already exists", input.name)));
        }
        if state.saml_providers.len() >= MAX_SAML_PROVIDERS {
            return Err(errors::limit_exceeded(format!(
                "Cannot exceed quota for SAMLProvidersPerAccount: {MAX_SAML_PROVIDERS}"
            )));
        }
        let now = Utc::now();
        let provider = SamlProvider {
            arn: arn.clone(),
            uuid: format!("a-{}", uuid::Uuid::new_v4().simple()),
            metadata: input.saml_metadata_document,
            created: now,
            valid_until,
            tags,
            assertion_encryption_mode: input.assertion_encryption_mode,
            private_keys: input.add_private_key.map(|k| vec![(key_id(), k, now)]).unwrap_or_default(),
        };
        let tags = tags_to_wire(&provider.tags);
        state.saml_providers.insert(arn.clone(), provider);
        Ok(types::CreateSAMLProviderResponse { saml_provider_arn: Some(arn), tags })
    }

    pub fn get_saml_provider(
        &self,
        ctx: &RequestContext,
        input: types::GetSAMLProviderRequest,
    ) -> Result<types::GetSAMLProviderResponse, ServiceError> {
        self.authorize(ctx, "GetSAMLProvider", &input.saml_provider_arn)?;
        let state = self.read();
        let p = state
            .saml_providers
            .get(&input.saml_provider_arn)
            .ok_or_else(|| no_such_provider(&input.saml_provider_arn))?;
        Ok(types::GetSAMLProviderResponse {
            saml_provider_uuid: Some(p.uuid.clone()),
            saml_metadata_document: Some(p.metadata.clone()),
            create_date: Some(p.created),
            valid_until: Some(p.valid_until),
            tags: tags_to_wire(&p.tags),
            assertion_encryption_mode: p.assertion_encryption_mode.clone(),
            private_key_list: private_keys(p),
        })
    }

    pub fn list_saml_providers(
        &self,
        ctx: &RequestContext,
        _input: types::ListSAMLProvidersRequest,
    ) -> Result<types::ListSAMLProvidersResponse, ServiceError> {
        self.authorize(ctx, "ListSAMLProviders", "*")?;
        let state = self.read();
        Ok(types::ListSAMLProvidersResponse {
            saml_provider_list: Some(
                state
                    .saml_providers
                    .values()
                    .map(|p| types::SAMLProviderListEntry {
                        arn: Some(p.arn.clone()),
                        valid_until: Some(p.valid_until),
                        create_date: Some(p.created),
                    })
                    .collect(),
            ),
        })
    }

    pub fn update_saml_provider(
        &self,
        ctx: &RequestContext,
        input: types::UpdateSAMLProviderRequest,
    ) -> Result<types::UpdateSAMLProviderResponse, ServiceError> {
        self.authorize(ctx, "UpdateSAMLProvider", &input.saml_provider_arn)?;
        check_mode(&input.assertion_encryption_mode)?;
        if input.saml_metadata_document.is_none()
            && input.assertion_encryption_mode.is_none()
            && input.add_private_key.is_none()
            && input.remove_private_key.is_none()
        {
            return Err(errors::invalid_input("At least one of the update parameters must be specified."));
        }
        let valid_until = input.saml_metadata_document.as_deref().map(parse_metadata).transpose()?;
        if let Some(k) = &input.add_private_key {
            check_private_key(k)?;
        }
        let mut state = self.write();
        let p = state
            .saml_providers
            .get_mut(&input.saml_provider_arn)
            .ok_or_else(|| no_such_provider(&input.saml_provider_arn))?;
        let mut keys = p.private_keys.clone();
        if let Some(id) = &input.remove_private_key {
            let before = keys.len();
            keys.retain(|(k, _, _)| k != id);
            if keys.len() == before {
                return Err(errors::invalid_input(format!("The private key with id {id} does not exist.")));
            }
        }
        if let Some(k) = input.add_private_key {
            if keys.len() >= MAX_PRIVATE_KEYS {
                return Err(errors::limit_exceeded(format!(
                    "Cannot exceed quota for PrivateKeysPerSAMLProvider: {MAX_PRIVATE_KEYS}"
                )));
            }
            keys.push((key_id(), k, Utc::now()));
        }
        let mode = input.assertion_encryption_mode.or_else(|| p.assertion_encryption_mode.clone());
        if mode.as_deref() == Some("Required") && keys.is_empty() {
            return Err(errors::invalid_input("A private key is required when AssertionEncryptionMode is Required."));
        }
        p.private_keys = keys;
        p.assertion_encryption_mode = mode;
        if let (Some(doc), Some(until)) = (input.saml_metadata_document, valid_until) {
            p.metadata = doc;
            p.valid_until = until;
        }
        Ok(types::UpdateSAMLProviderResponse { saml_provider_arn: Some(input.saml_provider_arn) })
    }

    pub fn delete_saml_provider(
        &self,
        ctx: &RequestContext,
        input: types::DeleteSAMLProviderRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "DeleteSAMLProvider", &input.saml_provider_arn)?;
        self.write()
            .saml_providers
            .remove(&input.saml_provider_arn)
            .ok_or_else(|| no_such_provider(&input.saml_provider_arn))?;
        Ok(())
    }

    pub fn tag_saml_provider(
        &self,
        ctx: &RequestContext,
        input: types::TagSAMLProviderRequest,
    ) -> Result<(), ServiceError> {
        let tags = tags_from_wire(Some(input.tags))?;
        self.authorize_with(ctx, "TagSAMLProvider", &input.saml_provider_arn, request_tag_context(&tags))?;
        let mut state = self.write();
        let p = state
            .saml_providers
            .get_mut(&input.saml_provider_arn)
            .ok_or_else(|| no_such_provider(&input.saml_provider_arn))?;
        merge_tags(&mut p.tags, tags, "TagsPerSAMLProvider")
    }

    pub fn untag_saml_provider(
        &self,
        ctx: &RequestContext,
        input: types::UntagSAMLProviderRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "UntagSAMLProvider", &input.saml_provider_arn)?;
        let mut state = self.write();
        let p = state
            .saml_providers
            .get_mut(&input.saml_provider_arn)
            .ok_or_else(|| no_such_provider(&input.saml_provider_arn))?;
        remove_tags(&mut p.tags, &input.tag_keys);
        Ok(())
    }

    pub fn list_saml_provider_tags(
        &self,
        ctx: &RequestContext,
        input: types::ListSAMLProviderTagsRequest,
    ) -> Result<types::ListSAMLProviderTagsResponse, ServiceError> {
        self.authorize(ctx, "ListSAMLProviderTags", &input.saml_provider_arn)?;
        let state = self.read();
        let p = state
            .saml_providers
            .get(&input.saml_provider_arn)
            .ok_or_else(|| no_such_provider(&input.saml_provider_arn))?;
        let tags = tags_list(&p.tags);
        let (page, truncated, marker) = paginate(&tags, |t| t.key.clone(), input.marker.as_deref(), input.max_items)?;
        Ok(types::ListSAMLProviderTagsResponse { tags: page, is_truncated: truncated, marker })
    }

    /// Metadata document of a SAML provider, for STS AssumeRoleWithSAML.
    pub fn saml_provider_metadata(&self, arn: &str) -> Option<String> {
        self.read_for_arn(arn).saml_providers.get(arn).map(|p| p.metadata.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_must_describe_an_idp() {
        let ok = r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x" validUntil="2030-01-01T00:00:00Z"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></md:EntityDescriptor>"#;
        assert_eq!(parse_metadata(ok).unwrap().to_rfc3339(), "2030-01-01T00:00:00+00:00");
        assert!(parse_metadata("<a/>").is_err());
        assert!(parse_metadata("not xml").is_err());
    }
}
