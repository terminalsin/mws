//! Wires the generated `Handler` trait to the synchronous operations. The
//! operations not listed answer `NotImplemented`.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::Ssm;

macro_rules! delegate {
    ($($name:ident($input:ty) -> $output:ty;)*) => {
        $(
            fn $name<'life0, 'life1, 'async_trait>(
                &'life0 self,
                ctx: &'life1 RequestContext,
                input: $input,
            ) -> ::std::pin::Pin<Box<dyn ::std::future::Future<Output = Result<$output, ServiceError>> + Send + 'async_trait>>
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                Self: 'async_trait,
            {
                let result = Ssm::$name(self, ctx, input);
                Box::pin(async move { result })
            }
        )*
    };
}

impl Handler for Ssm {
    delegate! {
        add_tags_to_resource(types::AddTagsToResourceRequest) -> types::AddTagsToResourceResult;
        delete_parameter(types::DeleteParameterRequest) -> types::DeleteParameterResult;
        delete_parameters(types::DeleteParametersRequest) -> types::DeleteParametersResult;
        delete_resource_policy(types::DeleteResourcePolicyRequest) -> types::DeleteResourcePolicyResponse;
        describe_parameters(types::DescribeParametersRequest) -> types::DescribeParametersResult;
        get_parameter(types::GetParameterRequest) -> types::GetParameterResult;
        get_parameter_history(types::GetParameterHistoryRequest) -> types::GetParameterHistoryResult;
        get_parameters(types::GetParametersRequest) -> types::GetParametersResult;
        get_parameters_by_path(types::GetParametersByPathRequest) -> types::GetParametersByPathResult;
        get_resource_policies(types::GetResourcePoliciesRequest) -> types::GetResourcePoliciesResponse;
        get_service_setting(types::GetServiceSettingRequest) -> types::GetServiceSettingResult;
        label_parameter_version(types::LabelParameterVersionRequest) -> types::LabelParameterVersionResult;
        list_tags_for_resource(types::ListTagsForResourceRequest) -> types::ListTagsForResourceResult;
        put_parameter(types::PutParameterRequest) -> types::PutParameterResult;
        put_resource_policy(types::PutResourcePolicyRequest) -> types::PutResourcePolicyResponse;
        remove_tags_from_resource(types::RemoveTagsFromResourceRequest) -> types::RemoveTagsFromResourceResult;
        reset_service_setting(types::ResetServiceSettingRequest) -> types::ResetServiceSettingResult;
        unlabel_parameter_version(types::UnlabelParameterVersionRequest) -> types::UnlabelParameterVersionResult;
        update_service_setting(types::UpdateServiceSettingRequest) -> types::UpdateServiceSettingResult;
    }
}
