//! OpsItems that other services create on the account's behalf, such as
//! CloudWatch alarm actions (`arn:aws:ssm:<region>:<account>:opsitem:<severity>`).

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use mws_core::ErrorValue;

use crate::generated::types;
use crate::Ssm;

/// An OpsItem a service creates.
#[derive(Debug, Clone, Default)]
pub struct ServiceOpsItem {
    pub title: String,
    pub description: String,
    pub source: String,
    pub severity: Option<String>,
    pub category: Option<String>,
    /// `SearchableString` operational data by key (`/aws/dedup`,
    /// `/aws/resources`, ...).
    pub operational_data: BTreeMap<String, String>,
    /// The service principal's role (shown as `CreatedBy`).
    pub created_by: String,
    pub at: Option<DateTime<Utc>>,
}

impl Ssm {
    /// Create an OpsItem for a service. When an open OpsItem has the same
    /// `/aws/dedup` string, no new one is created and its id is returned.
    pub fn create_ops_item_as_service(
        &self,
        partition: &str,
        account: &str,
        region: &str,
        item: ServiceOpsItem,
    ) -> Result<String, String> {
        let at = item.at.unwrap_or_else(|| self.clock_now());
        let data: BTreeMap<String, types::OpsItemDataValue> = item
            .operational_data
            .into_iter()
            .map(|(k, v)| (k, types::OpsItemDataValue { value: Some(v), r#type: Some("SearchableString".into()) }))
            .collect();
        let ops = types::OpsItem {
            created_by: Some(item.created_by.clone()),
            ops_item_type: Some("/aws/issues".into()),
            created_time: Some(at),
            description: Some(item.description.chars().take(2048).collect()),
            last_modified_by: Some(item.created_by),
            last_modified_time: Some(at),
            status: Some("Open".into()),
            title: Some(item.title.chars().take(1024).collect()),
            source: Some(item.source),
            operational_data: (!data.is_empty()).then_some(data),
            severity: item.severity,
            category: item.category,
            ..Default::default()
        };
        match self.insert_ops_item(partition, account, region, ops, BTreeMap::new()) {
            Ok((id, _)) => Ok(id),
            Err(e) => match e.fields.iter().find(|f| f.name == "OpsItemId").map(|f| f.value.clone()) {
                Some(ErrorValue::String(id)) => Ok(id),
                _ => Err(e.message),
            },
        }
    }
}
