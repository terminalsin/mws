//! Mobile push: platform applications and their endpoints. Messages to
//! endpoints land in the outbox.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types;
use crate::names::{self, account_of};
use crate::state::{PlatformApplication, PlatformEndpoint};
use crate::topics::paginate;
use crate::{errors, Sns};

const PLATFORMS: &[&str] = &[
    "ADM",
    "APNS",
    "APNS_SANDBOX",
    "APNS_VOIP",
    "APNS_VOIP_SANDBOX",
    "BAIDU",
    "GCM",
    "MACOS",
    "MACOS_SANDBOX",
    "MPNS",
    "WNS",
];
const APP_ATTRIBUTES: &[&str] = &[
    "PlatformCredential",
    "PlatformPrincipal",
    "EventEndpointCreated",
    "EventEndpointDeleted",
    "EventEndpointUpdated",
    "EventDeliveryFailure",
    "SuccessFeedbackRoleArn",
    "FailureFeedbackRoleArn",
    "SuccessFeedbackSampleRate",
    "ApplePlatformTeamID",
    "ApplePlatformBundleID",
];
const SECRET_ATTRIBUTES: &[&str] = &["PlatformCredential", "PlatformPrincipal"];
const ENDPOINT_ATTRIBUTES: &[&str] = &["CustomUserData", "Enabled", "Token"];
const APP_PAGE: usize = 15;
const ENDPOINT_PAGE: usize = 100;

fn check_app_attributes(attrs: &BTreeMap<String, String>) -> Result<(), ServiceError> {
    for (k, v) in attrs {
        if !APP_ATTRIBUTES.contains(&k.as_str()) {
            return Err(errors::invalid(format!("Attributes Reason: Invalid attribute name: {k}")));
        }
        if k.starts_with("Event") && !v.is_empty() && names::parse_sns_arn(v).is_none() {
            return Err(errors::invalid(format!("Attributes Reason: {k} must be a topic ARN")));
        }
        if k == "SuccessFeedbackSampleRate" && !v.parse::<u32>().is_ok_and(|r| r <= 100) {
            return Err(errors::invalid("Attributes Reason: SuccessFeedbackSampleRate must be between 0 and 100"));
        }
    }
    Ok(())
}

fn check_endpoint_attributes(attrs: &BTreeMap<String, String>) -> Result<(), ServiceError> {
    for (k, v) in attrs {
        if !ENDPOINT_ATTRIBUTES.contains(&k.as_str()) {
            return Err(errors::invalid(format!("Attributes Reason: Invalid attribute name: {k}")));
        }
        if k == "Enabled" && !matches!(v.as_str(), "true" | "false") {
            return Err(errors::invalid("Attributes Reason: Enabled must be true or false"));
        }
        if k == "Token" && v.is_empty() {
            return Err(errors::invalid("Attributes Reason: Token must not be empty"));
        }
        if k == "CustomUserData" && v.len() > 2048 {
            return Err(errors::invalid("Attributes Reason: CustomUserData must be at most 2048 bytes"));
        }
    }
    Ok(())
}

impl Sns {
    fn application<'a>(st: &'a crate::state::State, arn: &str) -> Result<&'a PlatformApplication, ServiceError> {
        st.applications.get(arn).ok_or_else(errors::application_not_found)
    }

    pub(crate) fn create_platform_application_impl(
        &self,
        ctx: &RequestContext,
        input: types::CreatePlatformApplicationInput,
    ) -> Result<types::CreatePlatformApplicationResponse, ServiceError> {
        let account = account_of(ctx);
        let arn = format!("arn:{}:sns:{}:{account}:app/{}/{}", ctx.partition, ctx.region, input.platform, input.name);
        ctx.authorize("sns:CreatePlatformApplication", &arn, ConditionContext::new())?;
        if !names::valid_application_name(&input.name) {
            return Err(errors::invalid("Invalid platform application name"));
        }
        if !PLATFORMS.contains(&input.platform.as_str()) {
            return Err(errors::invalid("Platform"));
        }
        check_app_attributes(&input.attributes)?;
        if input.attributes.get("PlatformCredential").is_none_or(|c| c.is_empty()) {
            return Err(errors::invalid("Attributes Reason: PlatformCredential attribute is required"));
        }
        let needs_principal =
            input.platform.starts_with("APNS") || input.platform.starts_with("MACOS") || input.platform == "BAIDU";
        if needs_principal && input.attributes.get("PlatformPrincipal").is_none_or(|c| c.is_empty()) {
            return Err(errors::invalid("Attributes Reason: PlatformPrincipal attribute is required"));
        }
        let mut st = self.lock();
        if let Some(existing) = st.applications.get(&arn) {
            if existing.attributes != input.attributes {
                return Err(errors::invalid(
                    "Name Reason: An application with the same name but different properties already exists",
                ));
            }
            return Ok(types::CreatePlatformApplicationResponse { platform_application_arn: Some(arn) });
        }
        st.applications.insert(
            arn.clone(),
            PlatformApplication {
                arn: arn.clone(),
                name: input.name,
                platform: input.platform,
                attributes: input.attributes,
            },
        );
        Ok(types::CreatePlatformApplicationResponse { platform_application_arn: Some(arn) })
    }

    fn app_attributes(app: &PlatformApplication) -> BTreeMap<String, String> {
        let mut out: BTreeMap<String, String> = app
            .attributes
            .iter()
            .filter(|(k, _)| !SECRET_ATTRIBUTES.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        out.entry("Enabled".into()).or_insert_with(|| "true".into());
        if app.platform.starts_with("APNS") && app.attributes.contains_key("ApplePlatformTeamID") {
            out.insert("AuthenticationMethod".into(), "Token".into());
        }
        out
    }

    pub(crate) fn get_platform_application_attributes_impl(
        &self,
        ctx: &RequestContext,
        input: types::GetPlatformApplicationAttributesInput,
    ) -> Result<types::GetPlatformApplicationAttributesResponse, ServiceError> {
        ctx.authorize(
            "sns:GetPlatformApplicationAttributes",
            &input.platform_application_arn,
            ConditionContext::new(),
        )?;
        let st = self.lock();
        let app = Self::application(&st, &input.platform_application_arn)?;
        Ok(types::GetPlatformApplicationAttributesResponse { attributes: Some(Self::app_attributes(app)) })
    }

    pub(crate) fn set_platform_application_attributes_impl(
        &self,
        ctx: &RequestContext,
        input: types::SetPlatformApplicationAttributesInput,
    ) -> Result<(), ServiceError> {
        ctx.authorize(
            "sns:SetPlatformApplicationAttributes",
            &input.platform_application_arn,
            ConditionContext::new(),
        )?;
        check_app_attributes(&input.attributes)?;
        let mut st = self.lock();
        let app = st.applications.get_mut(&input.platform_application_arn).ok_or_else(errors::application_not_found)?;
        for (k, v) in input.attributes {
            if v.is_empty() && k != "PlatformCredential" {
                app.attributes.remove(&k);
            } else {
                app.attributes.insert(k, v);
            }
        }
        Ok(())
    }

    pub(crate) fn delete_platform_application_impl(
        &self,
        ctx: &RequestContext,
        input: types::DeletePlatformApplicationInput,
    ) -> Result<(), ServiceError> {
        ctx.authorize("sns:DeletePlatformApplication", &input.platform_application_arn, ConditionContext::new())?;
        let mut st = self.lock();
        if st.applications.remove(&input.platform_application_arn).is_some() {
            st.endpoints.retain(|_, e| e.application_arn != input.platform_application_arn);
        }
        Ok(())
    }

    pub(crate) fn list_platform_applications_impl(
        &self,
        ctx: &RequestContext,
        input: types::ListPlatformApplicationsInput,
    ) -> Result<types::ListPlatformApplicationsResponse, ServiceError> {
        let account = account_of(ctx);
        ctx.authorize("sns:ListPlatformApplications", "*", ConditionContext::new())?;
        let st = self.lock();
        let arns: Vec<&str> = st
            .applications
            .keys()
            .filter(|a| names::parse_sns_arn(a).is_some_and(|p| p.account == account && p.region == ctx.region))
            .map(String::as_str)
            .collect();
        let (page, next) = paginate(&arns, input.next_token.as_deref(), APP_PAGE)?;
        let apps = page
            .iter()
            .filter_map(|a| st.applications.get(*a))
            .map(|a| types::PlatformApplication {
                platform_application_arn: Some(a.arn.clone()),
                attributes: Some(Self::app_attributes(a)),
            })
            .collect();
        Ok(types::ListPlatformApplicationsResponse { platform_applications: Some(apps), next_token: next })
    }

    pub(crate) fn create_platform_endpoint_impl(
        &self,
        ctx: &RequestContext,
        input: types::CreatePlatformEndpointInput,
    ) -> Result<types::CreateEndpointResponse, ServiceError> {
        ctx.authorize("sns:CreatePlatformEndpoint", &input.platform_application_arn, ConditionContext::new())?;
        if input.token.is_empty() {
            return Err(errors::invalid("Token"));
        }
        let mut attributes = input.attributes.unwrap_or_default();
        check_endpoint_attributes(&attributes)?;
        if let Some(data) = input.custom_user_data {
            attributes.insert("CustomUserData".into(), data);
        }
        attributes.insert("Token".into(), input.token.clone());
        attributes.entry("Enabled".into()).or_insert_with(|| "true".into());
        let mut st = self.lock();
        let app = Self::application(&st, &input.platform_application_arn)?.clone();
        let existing = st
            .endpoints
            .values()
            .find(|e| e.application_arn == app.arn && e.attributes.get("Token") == Some(&input.token));
        if let Some(e) = existing {
            if e.attributes != attributes {
                return Err(errors::invalid(format!(
                    "Token Reason: Endpoint {} already exists with the same Token, but different attributes.",
                    e.arn
                )));
            }
            return Ok(types::CreateEndpointResponse { endpoint_arn: Some(e.arn.clone()) });
        }
        let parsed = names::parse_sns_arn(&app.arn).ok_or_else(errors::application_not_found)?;
        let arn = format!(
            "arn:{}:sns:{}:{}:endpoint/{}/{}/{}",
            parsed.partition,
            parsed.region,
            parsed.account,
            app.platform,
            app.name,
            uuid::Uuid::new_v4()
        );
        st.endpoints.insert(arn.clone(), PlatformEndpoint { arn: arn.clone(), application_arn: app.arn, attributes });
        Ok(types::CreateEndpointResponse { endpoint_arn: Some(arn) })
    }

    pub(crate) fn get_endpoint_attributes_impl(
        &self,
        ctx: &RequestContext,
        input: types::GetEndpointAttributesInput,
    ) -> Result<types::GetEndpointAttributesResponse, ServiceError> {
        ctx.authorize("sns:GetEndpointAttributes", &input.endpoint_arn, ConditionContext::new())?;
        let st = self.lock();
        let e = st.endpoints.get(&input.endpoint_arn).ok_or_else(errors::endpoint_not_found)?;
        Ok(types::GetEndpointAttributesResponse { attributes: Some(e.attributes.clone()) })
    }

    pub(crate) fn set_endpoint_attributes_impl(
        &self,
        ctx: &RequestContext,
        input: types::SetEndpointAttributesInput,
    ) -> Result<(), ServiceError> {
        ctx.authorize("sns:SetEndpointAttributes", &input.endpoint_arn, ConditionContext::new())?;
        check_endpoint_attributes(&input.attributes)?;
        let mut st = self.lock();
        let e = st.endpoints.get_mut(&input.endpoint_arn).ok_or_else(errors::endpoint_not_found)?;
        for (k, v) in input.attributes {
            e.attributes.insert(k, v);
        }
        Ok(())
    }

    pub(crate) fn delete_endpoint_impl(
        &self,
        ctx: &RequestContext,
        input: types::DeleteEndpointInput,
    ) -> Result<(), ServiceError> {
        ctx.authorize("sns:DeleteEndpoint", &input.endpoint_arn, ConditionContext::new())?;
        self.lock().endpoints.remove(&input.endpoint_arn);
        Ok(())
    }

    pub(crate) fn list_endpoints_by_platform_application_impl(
        &self,
        ctx: &RequestContext,
        input: types::ListEndpointsByPlatformApplicationInput,
    ) -> Result<types::ListEndpointsByPlatformApplicationResponse, ServiceError> {
        ctx.authorize(
            "sns:ListEndpointsByPlatformApplication",
            &input.platform_application_arn,
            ConditionContext::new(),
        )?;
        let st = self.lock();
        Self::application(&st, &input.platform_application_arn)?;
        let arns: Vec<&str> = st
            .endpoints
            .values()
            .filter(|e| e.application_arn == input.platform_application_arn)
            .map(|e| e.arn.as_str())
            .collect();
        let (page, next) = paginate(&arns, input.next_token.as_deref(), ENDPOINT_PAGE)?;
        let endpoints = page
            .iter()
            .filter_map(|a| st.endpoints.get(*a))
            .map(|e| types::Endpoint { endpoint_arn: Some(e.arn.clone()), attributes: Some(e.attributes.clone()) })
            .collect();
        Ok(types::ListEndpointsByPlatformApplicationResponse { endpoints: Some(endpoints), next_token: next })
    }
}
