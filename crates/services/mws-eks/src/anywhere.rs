//! EKS Anywhere subscriptions: support licenses for on-premises clusters.

use chrono::{Duration, Months};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::util::{self, text};
use crate::Eks;

fn not_found(id: &str) -> ServiceError {
    errors::resource_not_found(format!("No EKS Anywhere subscription found with id: {id}"))
        .with_field("subscriptionId", text(id))
}

impl Eks {
    pub(crate) async fn create_eks_anywhere_subscription(
        &self,
        ctx: &RequestContext,
        input: types::CreateEksAnywhereSubscriptionRequest,
    ) -> Result<types::CreateEksAnywhereSubscriptionResponse, ServiceError> {
        util::authorize(
            ctx,
            "CreateEksAnywhereSubscription",
            &util::arn(ctx, "eks-anywhere-subscription/*"),
            None,
            input.tags.as_ref(),
            ConditionContext::new(),
        )?;
        util::check_create_tags(input.tags.as_ref())?;
        let term = &input.term;
        if term.unit.as_deref().unwrap_or("MONTHS") != "MONTHS" || !matches!(term.duration, 12 | 36) {
            return Err(errors::invalid_parameter("The subscription term must be 12 or 36 months."));
        }
        let quantity = if input.license_quantity == 0 { 1 } else { input.license_quantity };
        if !(1..=100).contains(&quantity) {
            return Err(errors::invalid_parameter("licenseQuantity must be between 1 and 100."));
        }
        let mut st = self.write();
        let region = util::region(&mut st, ctx);
        let id = util::uuid();
        let now = ctx.received_at;
        let account = util::account(ctx).to_string();
        let licenses: Vec<types::License> = (0..quantity)
            .map(|_| types::License {
                id: Some(format!("l-{}", util::random(b"0123456789abcdef", 32))),
                token: Some(util::random(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 64)),
            })
            .collect();
        let sub = types::EksAnywhereSubscription {
            id: Some(id.clone()),
            arn: Some(util::arn(ctx, &format!("eks-anywhere-subscription/{id}"))),
            created_at: Some(now),
            effective_date: Some(now),
            expiration_date: Some(now + Months::new(term.duration as u32)),
            license_quantity: quantity,
            license_type: Some(input.license_type.clone().unwrap_or_else(|| "Cluster".into())),
            term: Some(types::EksAnywhereSubscriptionTerm { duration: term.duration, unit: Some("MONTHS".into()) }),
            status: Some("CREATING".into()),
            auto_renew: input.auto_renew,
            license_arns: Some(
                licenses
                    .iter()
                    .map(|l| {
                        format!(
                            "arn:{}:license-manager::{account}:license:{}",
                            ctx.partition,
                            l.id.as_deref().unwrap_or_default()
                        )
                    })
                    .collect(),
            ),
            licenses: Some(licenses),
            tags: Some(input.tags.clone().unwrap_or_default()),
        };
        region.subscriptions.insert(id, sub.clone());
        Ok(types::CreateEksAnywhereSubscriptionResponse { subscription: Some(sub) })
    }

    pub(crate) async fn describe_eks_anywhere_subscription(
        &self,
        ctx: &RequestContext,
        input: types::DescribeEksAnywhereSubscriptionRequest,
    ) -> Result<types::DescribeEksAnywhereSubscriptionResponse, ServiceError> {
        let mut st = self.write();
        let s = util::region(&mut st, ctx).subscriptions.get(&input.id).ok_or_else(|| not_found(&input.id))?;
        util::authorize(
            ctx,
            "DescribeEksAnywhereSubscription",
            s.arn.as_deref().unwrap_or_default(),
            s.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        Ok(types::DescribeEksAnywhereSubscriptionResponse { subscription: Some(s.clone()) })
    }

    pub(crate) async fn list_eks_anywhere_subscriptions(
        &self,
        ctx: &RequestContext,
        input: types::ListEksAnywhereSubscriptionsRequest,
    ) -> Result<types::ListEksAnywhereSubscriptionsResponse, ServiceError> {
        util::authorize(
            ctx,
            "ListEksAnywhereSubscriptions",
            &util::arn(ctx, "eks-anywhere-subscription/*"),
            None,
            None,
            ConditionContext::new(),
        )?;
        let statuses = input.include_status.clone().unwrap_or_default();
        let mut st = self.write();
        let now = ctx.received_at;
        let mut all: Vec<types::EksAnywhereSubscription> = util::region(&mut st, ctx)
            .subscriptions
            .values()
            .map(|s| {
                let mut s = s.clone();
                if s.status.as_deref() == Some("ACTIVE") {
                    if s.expiration_date.is_some_and(|e| e <= now) {
                        s.status = Some("EXPIRED".into());
                    } else if s.expiration_date.is_some_and(|e| e - now <= Duration::days(30)) {
                        s.status = Some("EXPIRING".into());
                    }
                }
                s
            })
            .filter(|s| statuses.is_empty() || statuses.iter().any(|x| s.status.as_ref() == Some(x)))
            .collect();
        all.sort_by_key(|s| s.created_at);
        let (items, next) = util::page(&all, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListEksAnywhereSubscriptionsResponse { subscriptions: Some(items), next_token: next })
    }

    pub(crate) async fn update_eks_anywhere_subscription(
        &self,
        ctx: &RequestContext,
        input: types::UpdateEksAnywhereSubscriptionRequest,
    ) -> Result<types::UpdateEksAnywhereSubscriptionResponse, ServiceError> {
        let mut st = self.write();
        let s = util::region(&mut st, ctx).subscriptions.get_mut(&input.id).ok_or_else(|| not_found(&input.id))?;
        util::authorize(
            ctx,
            "UpdateEksAnywhereSubscription",
            s.arn.as_deref().unwrap_or_default(),
            s.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        s.auto_renew = input.auto_renew;
        Ok(types::UpdateEksAnywhereSubscriptionResponse { subscription: Some(s.clone()) })
    }

    pub(crate) async fn delete_eks_anywhere_subscription(
        &self,
        ctx: &RequestContext,
        input: types::DeleteEksAnywhereSubscriptionRequest,
    ) -> Result<types::DeleteEksAnywhereSubscriptionResponse, ServiceError> {
        let now = ctx.received_at;
        let mut st = self.write();
        let s = util::region(&mut st, ctx).subscriptions.get_mut(&input.id).ok_or_else(|| not_found(&input.id))?;
        util::authorize(
            ctx,
            "DeleteEksAnywhereSubscription",
            s.arn.as_deref().unwrap_or_default(),
            s.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        if s.created_at.is_some_and(|c| now - c > Duration::days(7)) {
            return Err(errors::invalid_request(
                "An EKS Anywhere subscription can only be deleted within 7 days of its creation.",
            )
            .with_field("subscriptionId", text(&input.id)));
        }
        s.status = Some("DELETING".into());
        Ok(types::DeleteEksAnywhereSubscriptionResponse { subscription: Some(s.clone()) })
    }
}
