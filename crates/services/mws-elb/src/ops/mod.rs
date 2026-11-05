//! The ELBv2 operations. Each lives in a module by resource; this file
//! forwards the generated [`Handler`] to them.

mod actions;
mod lb;
mod listener;
mod misc;
mod rule;
mod targets;
mod tg;
mod trust;

pub(crate) use actions::forwarded_target_groups;
pub(crate) use rule::rules_of;
pub(crate) use tg::load_balancers_of as tg_load_balancers;

use mws_core::{RequestContext, ServiceError};

use crate::v2::{types, Handler};
use crate::Elb;

#[async_trait::async_trait]
impl Handler for Elb {
    async fn add_listener_certificates(
        &self,
        ctx: &RequestContext,
        input: types::AddListenerCertificatesInput,
    ) -> Result<types::AddListenerCertificatesOutput, ServiceError> {
        self.add_listener_certificates_op(ctx, input)
    }
    async fn add_tags(
        &self,
        ctx: &RequestContext,
        input: types::AddTagsInput,
    ) -> Result<types::AddTagsOutput, ServiceError> {
        self.add_tags_op(ctx, input)
    }
    async fn add_trust_store_revocations(
        &self,
        ctx: &RequestContext,
        input: types::AddTrustStoreRevocationsInput,
    ) -> Result<types::AddTrustStoreRevocationsOutput, ServiceError> {
        self.add_trust_store_revocations_op(ctx, input)
    }
    async fn create_listener(
        &self,
        ctx: &RequestContext,
        input: types::CreateListenerInput,
    ) -> Result<types::CreateListenerOutput, ServiceError> {
        self.create_listener_op(ctx, input)
    }
    async fn create_load_balancer(
        &self,
        ctx: &RequestContext,
        input: types::CreateLoadBalancerInput,
    ) -> Result<types::CreateLoadBalancerOutput, ServiceError> {
        self.create_load_balancer_op(ctx, input)
    }
    async fn create_rule(
        &self,
        ctx: &RequestContext,
        input: types::CreateRuleInput,
    ) -> Result<types::CreateRuleOutput, ServiceError> {
        self.create_rule_op(ctx, input)
    }
    async fn create_target_group(
        &self,
        ctx: &RequestContext,
        input: types::CreateTargetGroupInput,
    ) -> Result<types::CreateTargetGroupOutput, ServiceError> {
        self.create_target_group_op(ctx, input)
    }
    async fn create_trust_store(
        &self,
        ctx: &RequestContext,
        input: types::CreateTrustStoreInput,
    ) -> Result<types::CreateTrustStoreOutput, ServiceError> {
        self.create_trust_store_op(ctx, input)
    }
    async fn delete_listener(
        &self,
        ctx: &RequestContext,
        input: types::DeleteListenerInput,
    ) -> Result<types::DeleteListenerOutput, ServiceError> {
        self.delete_listener_op(ctx, input)
    }
    async fn delete_load_balancer(
        &self,
        ctx: &RequestContext,
        input: types::DeleteLoadBalancerInput,
    ) -> Result<types::DeleteLoadBalancerOutput, ServiceError> {
        self.delete_load_balancer_op(ctx, input)
    }
    async fn delete_rule(
        &self,
        ctx: &RequestContext,
        input: types::DeleteRuleInput,
    ) -> Result<types::DeleteRuleOutput, ServiceError> {
        self.delete_rule_op(ctx, input)
    }
    async fn delete_shared_trust_store_association(
        &self,
        ctx: &RequestContext,
        input: types::DeleteSharedTrustStoreAssociationInput,
    ) -> Result<types::DeleteSharedTrustStoreAssociationOutput, ServiceError> {
        self.delete_shared_trust_store_association_op(ctx, input)
    }
    async fn delete_target_group(
        &self,
        ctx: &RequestContext,
        input: types::DeleteTargetGroupInput,
    ) -> Result<types::DeleteTargetGroupOutput, ServiceError> {
        self.delete_target_group_op(ctx, input)
    }
    async fn delete_trust_store(
        &self,
        ctx: &RequestContext,
        input: types::DeleteTrustStoreInput,
    ) -> Result<types::DeleteTrustStoreOutput, ServiceError> {
        self.delete_trust_store_op(ctx, input)
    }
    async fn deregister_targets(
        &self,
        ctx: &RequestContext,
        input: types::DeregisterTargetsInput,
    ) -> Result<types::DeregisterTargetsOutput, ServiceError> {
        self.deregister_targets_op(ctx, input)
    }
    async fn describe_account_limits(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAccountLimitsInput,
    ) -> Result<types::DescribeAccountLimitsOutput, ServiceError> {
        self.describe_account_limits_op(ctx, input)
    }
    async fn describe_capacity_reservation(
        &self,
        ctx: &RequestContext,
        input: types::DescribeCapacityReservationInput,
    ) -> Result<types::DescribeCapacityReservationOutput, ServiceError> {
        self.describe_capacity_reservation_op(ctx, input)
    }
    async fn describe_listener_attributes(
        &self,
        ctx: &RequestContext,
        input: types::DescribeListenerAttributesInput,
    ) -> Result<types::DescribeListenerAttributesOutput, ServiceError> {
        self.describe_listener_attributes_op(ctx, input)
    }
    async fn describe_listener_certificates(
        &self,
        ctx: &RequestContext,
        input: types::DescribeListenerCertificatesInput,
    ) -> Result<types::DescribeListenerCertificatesOutput, ServiceError> {
        self.describe_listener_certificates_op(ctx, input)
    }
    async fn describe_listeners(
        &self,
        ctx: &RequestContext,
        input: types::DescribeListenersInput,
    ) -> Result<types::DescribeListenersOutput, ServiceError> {
        self.describe_listeners_op(ctx, input)
    }
    async fn describe_load_balancer_attributes(
        &self,
        ctx: &RequestContext,
        input: types::DescribeLoadBalancerAttributesInput,
    ) -> Result<types::DescribeLoadBalancerAttributesOutput, ServiceError> {
        self.describe_load_balancer_attributes_op(ctx, input)
    }
    async fn describe_load_balancers(
        &self,
        ctx: &RequestContext,
        input: types::DescribeLoadBalancersInput,
    ) -> Result<types::DescribeLoadBalancersOutput, ServiceError> {
        self.describe_load_balancers_op(ctx, input)
    }
    async fn describe_rules(
        &self,
        ctx: &RequestContext,
        input: types::DescribeRulesInput,
    ) -> Result<types::DescribeRulesOutput, ServiceError> {
        self.describe_rules_op(ctx, input)
    }
    async fn describe_ssl_policies(
        &self,
        ctx: &RequestContext,
        input: types::DescribeSSLPoliciesInput,
    ) -> Result<types::DescribeSSLPoliciesOutput, ServiceError> {
        self.describe_ssl_policies_op(ctx, input)
    }
    async fn describe_tags(
        &self,
        ctx: &RequestContext,
        input: types::DescribeTagsInput,
    ) -> Result<types::DescribeTagsOutput, ServiceError> {
        self.describe_tags_op(ctx, input)
    }
    async fn describe_target_group_attributes(
        &self,
        ctx: &RequestContext,
        input: types::DescribeTargetGroupAttributesInput,
    ) -> Result<types::DescribeTargetGroupAttributesOutput, ServiceError> {
        self.describe_target_group_attributes_op(ctx, input)
    }
    async fn describe_target_groups(
        &self,
        ctx: &RequestContext,
        input: types::DescribeTargetGroupsInput,
    ) -> Result<types::DescribeTargetGroupsOutput, ServiceError> {
        self.describe_target_groups_op(ctx, input)
    }
    async fn describe_target_health(
        &self,
        ctx: &RequestContext,
        input: types::DescribeTargetHealthInput,
    ) -> Result<types::DescribeTargetHealthOutput, ServiceError> {
        self.describe_target_health_op(ctx, input)
    }
    async fn describe_trust_store_associations(
        &self,
        ctx: &RequestContext,
        input: types::DescribeTrustStoreAssociationsInput,
    ) -> Result<types::DescribeTrustStoreAssociationsOutput, ServiceError> {
        self.describe_trust_store_associations_op(ctx, input)
    }
    async fn describe_trust_store_revocations(
        &self,
        ctx: &RequestContext,
        input: types::DescribeTrustStoreRevocationsInput,
    ) -> Result<types::DescribeTrustStoreRevocationsOutput, ServiceError> {
        self.describe_trust_store_revocations_op(ctx, input)
    }
    async fn describe_trust_stores(
        &self,
        ctx: &RequestContext,
        input: types::DescribeTrustStoresInput,
    ) -> Result<types::DescribeTrustStoresOutput, ServiceError> {
        self.describe_trust_stores_op(ctx, input)
    }
    async fn get_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetResourcePolicyInput,
    ) -> Result<types::GetResourcePolicyOutput, ServiceError> {
        self.get_resource_policy_op(ctx, input)
    }
    async fn get_trust_store_ca_certificates_bundle(
        &self,
        ctx: &RequestContext,
        input: types::GetTrustStoreCaCertificatesBundleInput,
    ) -> Result<types::GetTrustStoreCaCertificatesBundleOutput, ServiceError> {
        self.get_trust_store_ca_certificates_bundle_op(ctx, input)
    }
    async fn get_trust_store_revocation_content(
        &self,
        ctx: &RequestContext,
        input: types::GetTrustStoreRevocationContentInput,
    ) -> Result<types::GetTrustStoreRevocationContentOutput, ServiceError> {
        self.get_trust_store_revocation_content_op(ctx, input)
    }
    async fn modify_capacity_reservation(
        &self,
        ctx: &RequestContext,
        input: types::ModifyCapacityReservationInput,
    ) -> Result<types::ModifyCapacityReservationOutput, ServiceError> {
        self.modify_capacity_reservation_op(ctx, input)
    }
    async fn modify_ip_pools(
        &self,
        ctx: &RequestContext,
        input: types::ModifyIpPoolsInput,
    ) -> Result<types::ModifyIpPoolsOutput, ServiceError> {
        self.modify_ip_pools_op(ctx, input)
    }
    async fn modify_listener(
        &self,
        ctx: &RequestContext,
        input: types::ModifyListenerInput,
    ) -> Result<types::ModifyListenerOutput, ServiceError> {
        self.modify_listener_op(ctx, input)
    }
    async fn modify_listener_attributes(
        &self,
        ctx: &RequestContext,
        input: types::ModifyListenerAttributesInput,
    ) -> Result<types::ModifyListenerAttributesOutput, ServiceError> {
        self.modify_listener_attributes_op(ctx, input)
    }
    async fn modify_load_balancer_attributes(
        &self,
        ctx: &RequestContext,
        input: types::ModifyLoadBalancerAttributesInput,
    ) -> Result<types::ModifyLoadBalancerAttributesOutput, ServiceError> {
        self.modify_load_balancer_attributes_op(ctx, input)
    }
    async fn modify_rule(
        &self,
        ctx: &RequestContext,
        input: types::ModifyRuleInput,
    ) -> Result<types::ModifyRuleOutput, ServiceError> {
        self.modify_rule_op(ctx, input)
    }
    async fn modify_target_group(
        &self,
        ctx: &RequestContext,
        input: types::ModifyTargetGroupInput,
    ) -> Result<types::ModifyTargetGroupOutput, ServiceError> {
        self.modify_target_group_op(ctx, input)
    }
    async fn modify_target_group_attributes(
        &self,
        ctx: &RequestContext,
        input: types::ModifyTargetGroupAttributesInput,
    ) -> Result<types::ModifyTargetGroupAttributesOutput, ServiceError> {
        self.modify_target_group_attributes_op(ctx, input)
    }
    async fn modify_trust_store(
        &self,
        ctx: &RequestContext,
        input: types::ModifyTrustStoreInput,
    ) -> Result<types::ModifyTrustStoreOutput, ServiceError> {
        self.modify_trust_store_op(ctx, input)
    }
    async fn register_targets(
        &self,
        ctx: &RequestContext,
        input: types::RegisterTargetsInput,
    ) -> Result<types::RegisterTargetsOutput, ServiceError> {
        self.register_targets_op(ctx, input)
    }
    async fn remove_listener_certificates(
        &self,
        ctx: &RequestContext,
        input: types::RemoveListenerCertificatesInput,
    ) -> Result<types::RemoveListenerCertificatesOutput, ServiceError> {
        self.remove_listener_certificates_op(ctx, input)
    }
    async fn remove_tags(
        &self,
        ctx: &RequestContext,
        input: types::RemoveTagsInput,
    ) -> Result<types::RemoveTagsOutput, ServiceError> {
        self.remove_tags_op(ctx, input)
    }
    async fn remove_trust_store_revocations(
        &self,
        ctx: &RequestContext,
        input: types::RemoveTrustStoreRevocationsInput,
    ) -> Result<types::RemoveTrustStoreRevocationsOutput, ServiceError> {
        self.remove_trust_store_revocations_op(ctx, input)
    }
    async fn set_ip_address_type(
        &self,
        ctx: &RequestContext,
        input: types::SetIpAddressTypeInput,
    ) -> Result<types::SetIpAddressTypeOutput, ServiceError> {
        self.set_ip_address_type_op(ctx, input)
    }
    async fn set_rule_priorities(
        &self,
        ctx: &RequestContext,
        input: types::SetRulePrioritiesInput,
    ) -> Result<types::SetRulePrioritiesOutput, ServiceError> {
        self.set_rule_priorities_op(ctx, input)
    }
    async fn set_security_groups(
        &self,
        ctx: &RequestContext,
        input: types::SetSecurityGroupsInput,
    ) -> Result<types::SetSecurityGroupsOutput, ServiceError> {
        self.set_security_groups_op(ctx, input)
    }
    async fn set_subnets(
        &self,
        ctx: &RequestContext,
        input: types::SetSubnetsInput,
    ) -> Result<types::SetSubnetsOutput, ServiceError> {
        self.set_subnets_op(ctx, input)
    }
}

impl Elb {
    /// Run `f` on the caller's account and Region.
    pub(crate) fn with_region<R>(
        &self,
        ctx: &RequestContext,
        f: impl FnOnce(&mut crate::state::RegionState) -> R,
    ) -> R {
        let account = crate::account_of(ctx);
        let mut st = self.lock();
        let r = st.regions.entry(crate::state::State::key(&account, &ctx.region)).or_default();
        f(r)
    }

    /// The tags on an ELBv2 resource.
    pub(crate) fn tags_of(&self, ctx: &RequestContext, arn: &str) -> Vec<types::Tag> {
        self.with_region(ctx, |r| r.tags.get(arn).cloned().unwrap_or_default())
    }

    /// Authorize `action` on an existing resource, with its tags.
    pub(crate) fn authorize_on(&self, ctx: &RequestContext, action: &str, arn: &str) -> Result<(), ServiceError> {
        let tags = self.tags_of(ctx, arn);
        crate::names::authorize(ctx, action, arn, crate::names::resource_tag_context(&tags))
    }

    /// Authorize a create call (and the `AddTags` it implies when it
    /// carries tags, with `elasticloadbalancing:CreateAction`).
    pub(crate) fn authorize_create(
        &self,
        ctx: &RequestContext,
        action: &str,
        arn: &str,
        tags: &[types::Tag],
    ) -> Result<(), ServiceError> {
        crate::names::authorize(ctx, action, arn, crate::names::request_tag_context(tags))?;
        if !tags.is_empty() {
            let mut c = crate::names::request_tag_context(tags);
            c.insert("elasticloadbalancing:CreateAction".into(), vec![action.to_string()]);
            crate::names::authorize(ctx, "AddTags", arn, c)?;
        }
        Ok(())
    }
}
