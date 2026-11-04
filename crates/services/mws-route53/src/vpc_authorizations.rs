//! Authorizations that let another account associate its VPC with a
//! private hosted zone.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::{arn, max_items, strip_id, Route53};

const MAX_AUTHORIZATIONS: usize = 100;

fn same_vpc(a: &types::VPC, b: &types::VPC) -> bool {
    a.vpc_id == b.vpc_id && a.vpc_region == b.vpc_region
}

impl Route53 {
    pub(crate) fn create_vpc_association_authorization(
        &self,
        ctx: &RequestContext,
        input: types::CreateVPCAssociationAuthorizationRequest,
    ) -> Result<types::CreateVPCAssociationAuthorizationResponse, ServiceError> {
        let id = strip_id(&input.hosted_zone_id).to_string();
        self.authorize(ctx, "CreateVPCAssociationAuthorization", &arn(ctx, "hostedzone", &id))?;
        crate::zones::check_vpc(&input.vpc)?;
        let mut st = self.lock(ctx);
        let zone = st.zone_mut(&id)?;
        if !zone.private {
            return Err(errors::invalid_input(
                "Invalid input: VPC association authorizations are only supported for private hosted zones.",
            ));
        }
        if !zone.vpc_authorizations.iter().any(|v| same_vpc(v, &input.vpc)) {
            if zone.vpc_authorizations.len() >= MAX_AUTHORIZATIONS {
                return Err(errors::too_many_vpc_association_authorizations(
                    "You've created the maximum number of authorizations that can be created for the specified hosted zone.",
                ));
            }
            zone.vpc_authorizations.push(input.vpc.clone());
        }
        Ok(types::CreateVPCAssociationAuthorizationResponse { hosted_zone_id: id, vpc: input.vpc })
    }

    pub(crate) fn delete_vpc_association_authorization(
        &self,
        ctx: &RequestContext,
        input: types::DeleteVPCAssociationAuthorizationRequest,
    ) -> Result<types::DeleteVPCAssociationAuthorizationResponse, ServiceError> {
        let id = strip_id(&input.hosted_zone_id).to_string();
        self.authorize(ctx, "DeleteVPCAssociationAuthorization", &arn(ctx, "hostedzone", &id))?;
        let mut st = self.lock(ctx);
        let zone = st.zone_mut(&id)?;
        let Some(pos) = zone.vpc_authorizations.iter().position(|v| same_vpc(v, &input.vpc)) else {
            return Err(errors::vpc_association_authorization_not_found(format!(
                "The VPC {} has not been authorized to be associated with hosted zone {id}.",
                input.vpc.vpc_id.as_deref().unwrap_or_default()
            )));
        };
        zone.vpc_authorizations.remove(pos);
        Ok(types::DeleteVPCAssociationAuthorizationResponse {})
    }

    pub(crate) fn list_vpc_association_authorizations(
        &self,
        ctx: &RequestContext,
        input: types::ListVPCAssociationAuthorizationsRequest,
    ) -> Result<types::ListVPCAssociationAuthorizationsResponse, ServiceError> {
        let id = strip_id(&input.hosted_zone_id).to_string();
        self.authorize(ctx, "ListVPCAssociationAuthorizations", &arn(ctx, "hostedzone", &id))?;
        let limit = max_items(input.max_results, 50, 50);
        let start = match &input.next_token {
            Some(t) => t
                .parse::<usize>()
                .map_err(|_| errors::invalid_pagination_token("The pagination token is not valid."))?,
            None => 0,
        };
        let st = self.lock(ctx);
        let zone = st.zone(&id)?;
        let all = &zone.vpc_authorizations;
        Ok(types::ListVPCAssociationAuthorizationsResponse {
            hosted_zone_id: id,
            vp_cs: all.iter().skip(start).take(limit).cloned().collect(),
            next_token: (start + limit < all.len()).then(|| (start + limit).to_string()),
        })
    }
}
