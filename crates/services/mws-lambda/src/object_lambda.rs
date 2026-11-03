//! Running S3 Object Lambda functions: S3 calls in through
//! [`mws_s3::ObjectLambdaInvoker`] with the caller's context, and the call
//! is authorized and run like a synchronous `Invoke` by that caller.

use mws_core::{RequestContext, ServiceError};

use crate::generated::types;
use crate::Lambda;

#[async_trait::async_trait]
impl mws_s3::ObjectLambdaInvoker for Lambda {
    async fn invoke(
        &self,
        ctx: &RequestContext,
        function_arn: &str,
        event: Vec<u8>,
    ) -> Result<mws_s3::LambdaInvocation, ServiceError> {
        let input = types::InvocationRequest {
            function_name: function_arn.to_string(),
            payload: Some(event),
            ..Default::default()
        };
        let out = Lambda::invoke(self, ctx, input).await?;
        Ok(mws_s3::LambdaInvocation { payload: out.payload.unwrap_or_default(), function_error: out.function_error })
    }
}
