//! CloudWatch Logs import tasks reading CloudTrail Lake event data stores.

/// CloudTrail Lake as the source of CloudWatch Logs import tasks.
pub(crate) struct CloudTrailLake(pub mws_cloudtrail::CloudTrail);

impl mws_logs::LakeSource for CloudTrailLake {
    fn read(&self, arn: &str) -> Option<mws_logs::LakeData> {
        let data = self.0.event_data_store_data(arn)?;
        let events = data
            .events
            .iter()
            .filter_map(|e| {
                let time = e.get("eventTime").and_then(|t| t.as_str())?;
                let event_time = chrono::DateTime::parse_from_rfc3339(time).ok()?.timestamp_millis();
                let field = |k: &str| e.get(k).and_then(|v| v.as_str()).unwrap_or_default().to_string();
                Some(mws_logs::LakeEvent {
                    event_time,
                    json: e.to_string(),
                    account: field("recipientAccountId"),
                    region: field("awsRegion"),
                })
            })
            .collect();
        Some(mws_logs::LakeData { status: data.status, kms_key_id: data.kms_key_id, events })
    }
}
