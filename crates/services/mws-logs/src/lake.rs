//! Where import tasks read from: CloudTrail Lake event data stores,
//! reached through the [`LakeSource`] the `mws` crate registers (Logs
//! cannot depend on CloudTrail, which writes to Logs).

/// One stored CloudTrail event.
#[derive(Debug, Clone)]
pub struct LakeEvent {
    /// `eventTime`, in epoch milliseconds.
    pub event_time: i64,
    /// The event record, as JSON.
    pub json: String,
    /// `recipientAccountId` and `awsRegion`, which name the log stream.
    pub account: String,
    pub region: String,
}

/// An event data store as an import sees it.
#[derive(Debug, Clone, Default)]
pub struct LakeData {
    /// `ENABLED`, `STOPPED_INGESTION`, `PENDING_DELETION`, ...
    pub status: String,
    pub kms_key_id: Option<String>,
    /// Oldest first.
    pub events: Vec<LakeEvent>,
}

/// Read access to CloudTrail Lake event data stores.
pub trait LakeSource: Send + Sync {
    /// The event data store with this ARN, or `None` when there is none.
    fn read(&self, event_data_store_arn: &str) -> Option<LakeData>;
}
