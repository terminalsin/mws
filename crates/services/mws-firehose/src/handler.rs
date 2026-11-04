//! Wires the generated `Handler` trait to the operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::Firehose;

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
                let result = Firehose::$name(self, ctx, input);
                Box::pin(async move { result })
            }
        )*
    };
}

impl Handler for Firehose {
    delegate! {
        create_delivery_stream(types::CreateDeliveryStreamInput) -> types::CreateDeliveryStreamOutput;
        delete_delivery_stream(types::DeleteDeliveryStreamInput) -> types::DeleteDeliveryStreamOutput;
        describe_delivery_stream(types::DescribeDeliveryStreamInput) -> types::DescribeDeliveryStreamOutput;
        list_delivery_streams(types::ListDeliveryStreamsInput) -> types::ListDeliveryStreamsOutput;
        list_tags_for_delivery_stream(types::ListTagsForDeliveryStreamInput) -> types::ListTagsForDeliveryStreamOutput;
        put_record(types::PutRecordInput) -> types::PutRecordOutput;
        put_record_batch(types::PutRecordBatchInput) -> types::PutRecordBatchOutput;
        start_delivery_stream_encryption(types::StartDeliveryStreamEncryptionInput) -> types::StartDeliveryStreamEncryptionOutput;
        stop_delivery_stream_encryption(types::StopDeliveryStreamEncryptionInput) -> types::StopDeliveryStreamEncryptionOutput;
        tag_delivery_stream(types::TagDeliveryStreamInput) -> types::TagDeliveryStreamOutput;
        untag_delivery_stream(types::UntagDeliveryStreamInput) -> types::UntagDeliveryStreamOutput;
        update_destination(types::UpdateDestinationInput) -> types::UpdateDestinationOutput;
    }
}
