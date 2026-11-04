//! Wires the generated `Handler` trait to the operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::Kinesis;

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
                let result = Kinesis::$name(self, ctx, input);
                Box::pin(async move { result })
            }
        )*
    };
}

impl Handler for Kinesis {
    delegate! {
        add_tags_to_stream(types::AddTagsToStreamInput) -> ();
        create_channel(types::CreateChannelInput) -> types::CreateChannelOutput;
        create_stream(types::CreateStreamInput) -> ();
        decrease_stream_retention_period(types::DecreaseStreamRetentionPeriodInput) -> ();
        delete_channel(types::DeleteChannelInput) -> ();
        delete_resource_policy(types::DeleteResourcePolicyInput) -> ();
        delete_stream(types::DeleteStreamInput) -> ();
        deregister_stream_consumer(types::DeregisterStreamConsumerInput) -> ();
        describe_account_settings(types::DescribeAccountSettingsInput) -> types::DescribeAccountSettingsOutput;
        describe_channel(types::DescribeChannelInput) -> types::DescribeChannelOutput;
        describe_limits(types::DescribeLimitsInput) -> types::DescribeLimitsOutput;
        describe_stream(types::DescribeStreamInput) -> types::DescribeStreamOutput;
        describe_stream_consumer(types::DescribeStreamConsumerInput) -> types::DescribeStreamConsumerOutput;
        describe_stream_summary(types::DescribeStreamSummaryInput) -> types::DescribeStreamSummaryOutput;
        disable_enhanced_monitoring(types::DisableEnhancedMonitoringInput) -> types::EnhancedMonitoringOutput;
        enable_enhanced_monitoring(types::EnableEnhancedMonitoringInput) -> types::EnhancedMonitoringOutput;
        get_records(types::GetRecordsInput) -> types::GetRecordsOutput;
        get_resource_policy(types::GetResourcePolicyInput) -> types::GetResourcePolicyOutput;
        get_shard_iterator(types::GetShardIteratorInput) -> types::GetShardIteratorOutput;
        increase_stream_retention_period(types::IncreaseStreamRetentionPeriodInput) -> ();
        list_channels(types::ListChannelsInput) -> types::ListChannelsOutput;
        list_shards(types::ListShardsInput) -> types::ListShardsOutput;
        list_stream_consumers(types::ListStreamConsumersInput) -> types::ListStreamConsumersOutput;
        list_streams(types::ListStreamsInput) -> types::ListStreamsOutput;
        list_tags_for_resource(types::ListTagsForResourceInput) -> types::ListTagsForResourceOutput;
        list_tags_for_stream(types::ListTagsForStreamInput) -> types::ListTagsForStreamOutput;
        merge_shards(types::MergeShardsInput) -> ();
        put_record(types::PutRecordInput) -> types::PutRecordOutput;
        put_records(types::PutRecordsInput) -> types::PutRecordsOutput;
        put_resource_policy(types::PutResourcePolicyInput) -> ();
        register_stream_consumer(types::RegisterStreamConsumerInput) -> types::RegisterStreamConsumerOutput;
        remove_tags_from_stream(types::RemoveTagsFromStreamInput) -> ();
        split_shard(types::SplitShardInput) -> ();
        start_stream_encryption(types::StartStreamEncryptionInput) -> ();
        stop_stream_encryption(types::StopStreamEncryptionInput) -> ();
        subscribe_to_shard(types::SubscribeToShardInput) -> types::SubscribeToShardOutput;
        tag_resource(types::TagResourceInput) -> ();
        untag_resource(types::UntagResourceInput) -> ();
        update_account_settings(types::UpdateAccountSettingsInput) -> types::UpdateAccountSettingsOutput;
        update_channel(types::UpdateChannelInput) -> types::UpdateChannelOutput;
        update_max_record_size(types::UpdateMaxRecordSizeInput) -> ();
        update_shard_count(types::UpdateShardCountInput) -> types::UpdateShardCountOutput;
        update_stream_mode(types::UpdateStreamModeInput) -> ();
        update_stream_record_distribution_strategy(types::UpdateStreamRecordDistributionStrategyInput) -> ();
        update_stream_warm_throughput(types::UpdateStreamWarmThroughputInput) -> types::UpdateStreamWarmThroughputOutput;
    }
}
