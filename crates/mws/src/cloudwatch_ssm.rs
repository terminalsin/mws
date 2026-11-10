//! CloudWatch alarm actions that create Systems Manager OpsItems
//! (`arn:aws:ssm:<region>:<account>:opsitem:<severity>[#CATEGORY=...]`).

use std::sync::Arc;

use mws_cloudwatch::{AlarmOpsItem, CloudWatch, OpsItemSink};
use mws_ssm::{ServiceOpsItem, Ssm};

struct AlarmOpsItems(Ssm);

impl OpsItemSink for AlarmOpsItems {
    fn create(&self, item: AlarmOpsItem) -> Result<String, String> {
        self.0.create_ops_item_as_service(
            &item.partition,
            &item.account,
            &item.region,
            ServiceOpsItem {
                title: item.title,
                description: item.description,
                source: item.source,
                severity: Some(item.severity),
                category: item.category,
                operational_data: item.operational_data,
                created_by: item.created_by,
                at: Some(item.at),
            },
        )
    }
}

pub(crate) fn wire(cloudwatch: &CloudWatch, ssm: &Ssm) {
    cloudwatch.set_ops_items(Arc::new(AlarmOpsItems(ssm.clone())));
}
