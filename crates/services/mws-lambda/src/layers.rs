//! Layers: versioned zips extracted alongside a function's code.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::functions::{paginate, timestamp};
use crate::generated::{errors, types};
use crate::names;
use crate::state::{Layer, LayerVersion};
use crate::Lambda;

fn matches(v: &LayerVersion, runtime: Option<&str>, arch: Option<&str>) -> bool {
    runtime.is_none_or(|r| v.compatible_runtimes.as_ref().is_some_and(|c| c.iter().any(|x| x == r)))
        && arch.is_none_or(|a| v.compatible_architectures.as_ref().is_some_and(|c| c.iter().any(|x| x == a)))
}

impl Lambda {
    /// `(layer ARN, layer version ARN)` for a layer name or ARN.
    pub(crate) fn layer_arns(&self, ctx: &RequestContext, layer: &str, version: i64) -> (String, String) {
        let arn = if layer.starts_with("arn:") {
            layer.to_string()
        } else {
            format!("arn:{}:lambda:{}:{}:layer:{layer}", ctx.partition, ctx.region, names::account_of(ctx))
        };
        let version_arn = format!("{arn}:{version}");
        (arn, version_arn)
    }

    pub(crate) fn layer_not_found() -> ServiceError {
        errors::resource_not_found("The resource you requested does not exist.")
    }

    fn version_response(&self, ctx: &RequestContext, l: &Layer, v: &LayerVersion) -> types::GetLayerVersionResponse {
        types::GetLayerVersionResponse {
            content: Some(types::LayerVersionContentOutput {
                location: Some(self.download_url(ctx, &v.code_hex)),
                code_sha256: Some(v.code_sha256.clone()),
                code_size: v.code_size,
                ..Default::default()
            }),
            layer_arn: Some(l.arn.clone()),
            layer_version_arn: Some(format!("{}:{}", l.arn, v.version)),
            description: v.description.clone(),
            created_date: Some(v.created_date.clone()),
            version: v.version,
            compatible_architectures: v.compatible_architectures.clone(),
            compatible_runtimes: v.compatible_runtimes.clone(),
            license_info: v.license_info.clone(),
        }
    }

    fn list_item(l: &Layer, v: &LayerVersion) -> types::LayerVersionsListItem {
        types::LayerVersionsListItem {
            layer_version_arn: Some(format!("{}:{}", l.arn, v.version)),
            version: v.version,
            description: v.description.clone(),
            created_date: Some(v.created_date.clone()),
            compatible_architectures: v.compatible_architectures.clone(),
            compatible_runtimes: v.compatible_runtimes.clone(),
            license_info: v.license_info.clone(),
        }
    }

    pub async fn publish_layer_version(
        &self,
        ctx: &RequestContext,
        input: types::PublishLayerVersionRequest,
    ) -> Result<types::PublishLayerVersionResponse, ServiceError> {
        let (arn, _) = self.layer_arns(ctx, &input.layer_name, 0);
        ctx.authorize("lambda:PublishLayerVersion", &arn, ConditionContext::new())?;
        let c = &input.content;
        let zip = match (&c.zip_file, &c.s3_bucket, &c.s3_key) {
            (Some(z), _, _) => Self::direct_zip(z.clone())?,
            (None, Some(b), Some(k)) => self.zip_from_s3(ctx, b, k, c.s3_object_version.as_deref()).await?,
            _ => return Err(errors::invalid_parameter_value("Please provide a source for layer content.")),
        };
        let stored = self.store_zip(zip)?;
        let name = arn.rsplit(':').next().unwrap_or_default().to_string();
        let account = arn.split(':').nth(4).unwrap_or_default().to_string();
        let mut st = self.write();
        let layer = st.layers.entry(arn.clone()).or_insert_with(|| Layer {
            account_id: account,
            name,
            arn: arn.clone(),
            ..Default::default()
        });
        layer.last_version += 1;
        let v = LayerVersion {
            version: layer.last_version,
            description: input.description.clone(),
            created_date: timestamp(ctx.received_at),
            compatible_runtimes: input.compatible_runtimes.clone(),
            compatible_architectures: input.compatible_architectures.clone(),
            license_info: input.license_info.clone(),
            code_hex: stored.hex,
            code_sha256: stored.sha256,
            code_size: stored.size,
            ..Default::default()
        };
        layer.versions.insert(v.version, v.clone());
        let r = self.version_response(ctx, layer, &v);
        Ok(types::PublishLayerVersionResponse {
            content: r.content,
            layer_arn: r.layer_arn,
            layer_version_arn: r.layer_version_arn,
            description: r.description,
            created_date: r.created_date,
            version: r.version,
            compatible_architectures: r.compatible_architectures,
            compatible_runtimes: r.compatible_runtimes,
            license_info: r.license_info,
        })
    }

    fn get_layer_version_by(
        &self,
        ctx: &RequestContext,
        layer_arn: &str,
        version: i64,
    ) -> Result<types::GetLayerVersionResponse, ServiceError> {
        let version_arn = format!("{layer_arn}:{version}");
        let policy = {
            let st = self.read();
            st.layers.get(layer_arn).and_then(|l| l.versions.get(&version)).and_then(|v| {
                (!v.policy.is_empty()).then(|| {
                    serde_json::json!({"Version": "2012-10-17", "Id": "default", "Statement": v.policy}).to_string()
                })
            })
        };
        ctx.authorize_with_resource_policy(
            "lambda:GetLayerVersion",
            &version_arn,
            policy.as_deref(),
            ConditionContext::new(),
        )?;
        let st = self.read();
        let l = st.layers.get(layer_arn).ok_or_else(Self::layer_not_found)?;
        let v = l.versions.get(&version).ok_or_else(Self::layer_not_found)?;
        Ok(self.version_response(ctx, l, v))
    }

    pub async fn get_layer_version(
        &self,
        ctx: &RequestContext,
        input: types::GetLayerVersionRequest,
    ) -> Result<types::GetLayerVersionResponse, ServiceError> {
        let (arn, _) = self.layer_arns(ctx, &input.layer_name, input.version_number);
        self.get_layer_version_by(ctx, &arn, input.version_number)
    }

    pub async fn get_layer_version_by_arn(
        &self,
        ctx: &RequestContext,
        input: types::GetLayerVersionByArnRequest,
    ) -> Result<types::GetLayerVersionResponse, ServiceError> {
        let (layer, version) = input
            .arn
            .rsplit_once(':')
            .and_then(|(l, v)| Some((l.to_string(), v.parse::<i64>().ok()?)))
            .ok_or_else(|| errors::invalid_parameter_value(format!("Invalid layer version ARN: {}", input.arn)))?;
        self.get_layer_version_by(ctx, &layer, version)
    }

    pub async fn delete_layer_version(
        &self,
        ctx: &RequestContext,
        input: types::DeleteLayerVersionRequest,
    ) -> Result<(), ServiceError> {
        let (arn, version_arn) = self.layer_arns(ctx, &input.layer_name, input.version_number);
        ctx.authorize("lambda:DeleteLayerVersion", &version_arn, ConditionContext::new())?;
        let mut st = self.write();
        if let Some(l) = st.layers.get_mut(&arn) {
            l.versions.remove(&input.version_number);
            if l.versions.is_empty() {
                st.layers.remove(&arn);
            }
        }
        Ok(())
    }

    pub async fn list_layers(
        &self,
        ctx: &RequestContext,
        input: types::ListLayersRequest,
    ) -> Result<types::ListLayersResponse, ServiceError> {
        ctx.authorize("lambda:ListLayers", "*", ConditionContext::new())?;
        let account = names::account_of(ctx);
        let st = self.read();
        let items: Vec<types::LayersListItem> = st
            .layers
            .values()
            .filter(|l| l.account_id == account && l.arn.split(':').nth(3) == Some(ctx.region.as_str()))
            .filter_map(|l| {
                let latest = l.versions.values().rev().find(|v| {
                    matches(v, input.compatible_runtime.as_deref(), input.compatible_architecture.as_deref())
                })?;
                Some(types::LayersListItem {
                    layer_name: Some(l.name.clone()),
                    layer_arn: Some(l.arn.clone()),
                    latest_matching_version: Some(Self::list_item(l, latest)),
                })
            })
            .collect();
        let (page, next) = paginate(&items, input.marker.as_deref(), input.max_items, 50);
        Ok(types::ListLayersResponse { layers: Some(page), next_marker: next })
    }

    pub async fn list_layer_versions(
        &self,
        ctx: &RequestContext,
        input: types::ListLayerVersionsRequest,
    ) -> Result<types::ListLayerVersionsResponse, ServiceError> {
        let (arn, _) = self.layer_arns(ctx, &input.layer_name, 0);
        ctx.authorize("lambda:ListLayerVersions", &arn, ConditionContext::new())?;
        let st = self.read();
        let items: Vec<types::LayerVersionsListItem> = st
            .layers
            .get(&arn)
            .map(|l| {
                l.versions
                    .values()
                    .rev()
                    .filter(|v| {
                        matches(v, input.compatible_runtime.as_deref(), input.compatible_architecture.as_deref())
                    })
                    .map(|v| Self::list_item(l, v))
                    .collect()
            })
            .unwrap_or_default();
        let (page, next) = paginate(&items, input.marker.as_deref(), input.max_items, 50);
        Ok(types::ListLayerVersionsResponse { layer_versions: Some(page), next_marker: next })
    }
}
