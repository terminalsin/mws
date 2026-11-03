//! Importing key material into keys with origin `EXTERNAL`.

use chrono::{Duration, Utc};
use mws_core::{RequestContext, ServiceError};

use super::{require_not_pending_deletion, spec, validation, Access};
use crate::crypto::{self, Spec};
use crate::generated::{errors, types};
use crate::state::{ImportParams, Key, Material};
use crate::Kms;

fn require_external(key: &Key) -> Result<(), ServiceError> {
    if key.origin != "EXTERNAL" {
        return Err(errors::unsupported_operation(format!(
            "{} origin is {} which is not valid for this operation.",
            key.arn, key.origin
        )));
    }
    Ok(())
}

impl Kms {
    pub(crate) fn get_parameters_for_import(
        &self,
        ctx: &RequestContext,
        input: types::GetParametersForImportRequest,
    ) -> Result<types::GetParametersForImportResponse, ServiceError> {
        let t = self.authorize_key(
            ctx,
            &input.key_id,
            Access::new("GetParametersForImport")
                .condition("kms:WrappingAlgorithm", vec![input.wrapping_algorithm.clone()])
                .condition("kms:WrappingKeySpec", vec![input.wrapping_key_spec.clone()]),
        )?;
        {
            let st = self.lock();
            let key = st.key(&t.arn)?;
            require_external(key)?;
            require_not_pending_deletion(key)?;
        }
        let bits = match input.wrapping_key_spec.as_str() {
            "RSA_2048" => 2048,
            "RSA_3072" => 3072,
            "RSA_4096" => 4096,
            other => {
                return Err(errors::unsupported_operation(format!(
                    "WrappingKeySpec {other} is only supported in the AWS China Regions."
                )))
            }
        };
        if input.wrapping_algorithm == "SM2PKE" {
            return Err(errors::unsupported_operation(
                "WrappingAlgorithm SM2PKE is only supported in the AWS China Regions.",
            ));
        }
        let wrapping_key = crypto::generate(Spec::Rsa(bits))?;
        let public_key = crypto::public_key_der(Spec::Rsa(bits), &wrapping_key)?;
        let token = crypto::random_bytes(64);
        let valid_to = Utc::now() + Duration::hours(24);
        self.lock().imports.insert(
            crypto::hex(&token),
            ImportParams {
                key_arn: t.arn.clone(),
                wrapping_algorithm: input.wrapping_algorithm,
                wrapping_key_spec: input.wrapping_key_spec,
                wrapping_key,
                valid_to,
            },
        );
        Ok(types::GetParametersForImportResponse {
            key_id: Some(t.arn),
            import_token: Some(token),
            public_key: Some(public_key),
            parameters_valid_to: Some(valid_to),
        })
    }

    pub(crate) fn import_key_material(
        &self,
        ctx: &RequestContext,
        input: types::ImportKeyMaterialRequest,
    ) -> Result<types::ImportKeyMaterialResponse, ServiceError> {
        let model = input.expiration_model.clone().unwrap_or_else(|| {
            if input.valid_to.is_some() { "KEY_MATERIAL_EXPIRES" } else { "KEY_MATERIAL_DOES_NOT_EXPIRE" }.into()
        });
        let mut access = Access::new("ImportKeyMaterial").condition("kms:ExpirationModel", vec![model.clone()]);
        if let Some(v) = input.valid_to {
            access = access.condition("kms:ValidTo", vec![v.timestamp().to_string()]);
        }
        let t = self.authorize_key(ctx, &input.key_id, access)?;
        match (model.as_str(), input.valid_to) {
            ("KEY_MATERIAL_EXPIRES", None) => {
                return Err(validation("ValidTo is required when ExpirationModel is KEY_MATERIAL_EXPIRES."))
            }
            ("KEY_MATERIAL_DOES_NOT_EXPIRE", Some(_)) => {
                return Err(validation("ValidTo cannot be set when ExpirationModel is KEY_MATERIAL_DOES_NOT_EXPIRE."))
            }
            (_, Some(v)) if v <= Utc::now() || v > Utc::now() + Duration::days(365) => {
                return Err(validation("ValidTo must be in the future and no more than 365 days from now."));
            }
            _ => {}
        }
        let mut st = self.lock();
        let params = st
            .imports
            .get(&crypto::hex(&input.import_token))
            .cloned()
            .ok_or_else(|| errors::invalid_import_token("Import token is invalid or expired."))?;
        if params.key_arn != t.arn {
            return Err(errors::invalid_import_token("The import token is not valid for the specified KMS key."));
        }
        let key = st.key(&t.arn)?;
        require_external(key)?;
        require_not_pending_deletion(key)?;
        let material =
            crypto::unwrap_import(&params.wrapping_key, &params.wrapping_algorithm, &input.encrypted_key_material)
                .ok_or_else(|| errors::invalid_ciphertext(""))?;
        if !crypto::validate_material(spec(key), &material) {
            return Err(errors::incorrect_key_material(format!(
                "The key material is not valid for key spec {}.",
                key.key_spec
            )));
        }
        let id = crypto::material_id(&material);
        if let Some(requested) = &input.key_material_id {
            if *requested != id {
                return Err(errors::incorrect_key_material(
                    "The key material doesn't match the KeyMaterialId that you specified.",
                ));
            }
        }
        let new_material = input.import_type.as_deref() == Some("NEW_KEY_MATERIAL");
        // Material that was deleted or expired keeps its id: only the same
        // material can be imported again.
        let known = key.materials.iter().any(|m| m.id == id);
        if !known && !key.materials.is_empty() && !new_material {
            return Err(errors::incorrect_key_material(
                "The key material doesn't match the key material previously imported into this key.",
            ));
        }
        if new_material && key.current().is_some() && !key.is_symmetric() {
            return Err(errors::unsupported_operation("Only symmetric encryption keys support new key material."));
        }
        let rotation_pending = new_material && key.current().is_some() && !known;
        let valid_to = input.valid_to;
        let key = st.key_mut(&t.arn)?;
        if let Some(m) = key.materials.iter_mut().find(|m| m.id == id) {
            m.secret = material;
            m.expiration_model = Some(model);
            m.valid_to = valid_to;
            if input.key_material_description.is_some() {
                m.description = input.key_material_description;
            }
        } else {
            key.materials.push(Material {
                id: id.clone(),
                secret: material,
                created_at: Utc::now(),
                rotation_type: None,
                imported: true,
                description: input.key_material_description,
                expiration_model: Some(model),
                valid_to,
                pending: rotation_pending,
            });
        }
        if key.current().is_none() && !rotation_pending {
            key.current_material = Some(id.clone());
        }
        if key.state == "PendingImport" && key.current().is_some() {
            key.state = if key.enabled_flag { "Enabled" } else { "Disabled" }.into();
        }
        st.imports.remove(&crypto::hex(&input.import_token));
        st.sync_replicas(&t.arn);
        Ok(types::ImportKeyMaterialResponse { key_id: Some(t.arn), key_material_id: Some(id) })
    }

    pub(crate) fn delete_imported_key_material(
        &self,
        ctx: &RequestContext,
        input: types::DeleteImportedKeyMaterialRequest,
    ) -> Result<types::DeleteImportedKeyMaterialResponse, ServiceError> {
        let t = self.authorize_key(ctx, &input.key_id, Access::new("DeleteImportedKeyMaterial"))?;
        let mut st = self.lock();
        let key = st.key_mut(&t.arn)?;
        require_external(key)?;
        require_not_pending_deletion(key)?;
        let id = match input.key_material_id.or_else(|| key.current_material.clone()) {
            Some(id) => id,
            None => return Err(errors::kms_invalid_state(format!("{} is pending import.", key.arn))),
        };
        if key.material(&id).is_none() {
            return Err(errors::not_found(format!("Key material {id} does not exist for key {}.", key.arn)));
        }
        // The id stays behind so that only the same material can be
        // imported again.
        for m in key.materials.iter_mut().filter(|m| m.id == id) {
            m.secret.clear();
        }
        if key.current().is_none() {
            key.state = "PendingImport".into();
        }
        Ok(types::DeleteImportedKeyMaterialResponse { key_id: Some(t.arn), key_material_id: Some(id) })
    }
}
