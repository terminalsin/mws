//! The fixed catalogues and account settings.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types as t;
use crate::util::{authorize, paginate, validation, METRICS, PROCESSES, TERMINATION_POLICIES};
use crate::AutoScaling;

impl AutoScaling {
    pub(crate) fn describe_adjustment_types_op(
        &self,
        ctx: &RequestContext,
    ) -> Result<t::DescribeAdjustmentTypesAnswer, ServiceError> {
        authorize(ctx, "DescribeAdjustmentTypes", "*", None, ConditionContext::new())?;
        Ok(t::DescribeAdjustmentTypesAnswer {
            adjustment_types: Some(
                ["ChangeInCapacity", "ExactCapacity", "PercentChangeInCapacity"]
                    .iter()
                    .map(|a| t::AdjustmentType { adjustment_type: Some(a.to_string()) })
                    .collect(),
            ),
        })
    }

    pub(crate) fn describe_scaling_process_types_op(
        &self,
        ctx: &RequestContext,
    ) -> Result<t::ProcessesType, ServiceError> {
        authorize(ctx, "DescribeScalingProcessTypes", "*", None, ConditionContext::new())?;
        let mut names: Vec<&str> = PROCESSES.to_vec();
        names.sort();
        Ok(t::ProcessesType {
            processes: Some(names.into_iter().map(|p| t::ProcessType { process_name: p.to_string() }).collect()),
        })
    }

    pub(crate) fn describe_metric_collection_types_op(
        &self,
        ctx: &RequestContext,
    ) -> Result<t::DescribeMetricCollectionTypesAnswer, ServiceError> {
        authorize(ctx, "DescribeMetricCollectionTypes", "*", None, ConditionContext::new())?;
        Ok(t::DescribeMetricCollectionTypesAnswer {
            metrics: Some(METRICS.iter().map(|m| t::MetricCollectionType { metric: Some(m.to_string()) }).collect()),
            granularities: Some(vec![t::MetricGranularityType { granularity: Some("1Minute".into()) }]),
        })
    }

    pub(crate) fn describe_termination_policy_types_op(
        &self,
        ctx: &RequestContext,
    ) -> Result<t::DescribeTerminationPolicyTypesAnswer, ServiceError> {
        authorize(ctx, "DescribeTerminationPolicyTypes", "*", None, ConditionContext::new())?;
        Ok(t::DescribeTerminationPolicyTypesAnswer {
            termination_policy_types: Some(TERMINATION_POLICIES.iter().map(|p| p.to_string()).collect()),
        })
    }

    pub(crate) fn put_account_setting_op(
        &self,
        ctx: &RequestContext,
        input: t::PutAccountSettingType,
    ) -> Result<t::PutAccountSettingAnswer, ServiceError> {
        authorize(ctx, "PutAccountSetting", "*", None, ConditionContext::new())?;
        if input.name.is_empty() || input.value.is_empty() {
            return Err(validation("Name and Value must not be empty."));
        }
        self.with_region(ctx, |r| {
            r.account_settings.insert(input.name.clone(), input.value.clone());
        });
        Ok(Default::default())
    }

    pub(crate) fn describe_account_settings_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeAccountSettingsType,
    ) -> Result<t::DescribeAccountSettingsAnswer, ServiceError> {
        authorize(ctx, "DescribeAccountSettings", "*", None, ConditionContext::new())?;
        let list: Vec<t::AccountSetting> = self.with_region(ctx, |r| {
            r.account_settings
                .iter()
                .filter(|(k, _)| input.name.as_ref().is_none_or(|n| n == *k))
                .map(|(k, v)| t::AccountSetting {
                    name: Some(k.clone()),
                    value: Some(v.clone()),
                    enforcement_type: Some("Optional".into()),
                    default_value: None,
                    ..Default::default()
                })
                .collect()
        });
        let (page, next_token) = paginate(list, input.max_records, &input.next_token, 100)?;
        Ok(t::DescribeAccountSettingsAnswer { settings: Some(page), next_token })
    }
}
