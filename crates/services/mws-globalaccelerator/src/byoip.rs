//! Bring your own IP addresses: address ranges move through provisioning,
//! advertising, withdrawing and deprovisioning on the emulated clock.

use std::net::Ipv4Addr;

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::ips::Cidr;
use crate::names::{account, authorize, invalid, now_ms, page, time};
use crate::state::{transition_ms, ByoipCidr, State};
use crate::GlobalAccelerator;

fn describe(c: &ByoipCidr) -> types::ByoipCidr {
    types::ByoipCidr {
        cidr: Some(c.cidr.clone()),
        state: Some(c.state.clone()),
        events: Some(
            c.events
                .iter()
                .map(|e| types::ByoipCidrEvent { message: Some(e.message.clone()), timestamp: Some(time(e.timestamp)) })
                .collect(),
        ),
    }
}

fn key(account: &str, cidr: &str) -> String {
    format!("{account}/{cidr}")
}

fn not_found(cidr: &str) -> ServiceError {
    errors::byoip_cidr_not_found(format!("The address range {cidr} was not found."))
}

fn wrong_state(cidr: &str, state: &str) -> ServiceError {
    errors::incorrect_cidr_state(format!(
        "The address range {cidr} is in the {state} state, which doesn't allow this action."
    ))
}

fn in_use(st: &State, cidr: &Cidr) -> bool {
    st.accelerators
        .values()
        .flat_map(|a| a.byoip_ips.iter())
        .any(|ip| ip.parse::<Ipv4Addr>().is_ok_and(|ip| cidr.contains(ip)))
}

impl GlobalAccelerator {
    fn transition(
        &self,
        ctx: &RequestContext,
        op: &str,
        cidr: &str,
        from: &str,
        pending: &str,
        to: &str,
    ) -> Result<types::ByoipCidr, ServiceError> {
        authorize(ctx, op, "*", ConditionContext::new())?;
        let now = now_ms(ctx);
        let mut st = self.settled(ctx);
        let k = key(&account(ctx), cidr);
        let c = st.byoip.get(&k).ok_or_else(|| not_found(cidr))?;
        if c.state != from {
            return Err(wrong_state(cidr, &c.state));
        }
        if op == "DeprovisionByoipCidr" && Cidr::parse(cidr).is_some_and(|r| in_use(&st, &r)) {
            return Err(errors::incorrect_cidr_state(format!(
                "Addresses in {cidr} are used by an accelerator. Remove them from the accelerator before deprovisioning the range."
            )));
        }
        let c = st.byoip.get_mut(&k).expect("range present");
        c.state = pending.into();
        c.pending = Some(to.into());
        c.settles_at = now + transition_ms();
        Ok(describe(c))
    }

    pub fn provision_byoip_cidr(
        &self,
        ctx: &RequestContext,
        input: types::ProvisionByoipCidrRequest,
    ) -> Result<types::ProvisionByoipCidrResponse, ServiceError> {
        authorize(ctx, "ProvisionByoipCidr", "*", ConditionContext::new())?;
        let cidr = Cidr::parse(&input.cidr)
            .ok_or_else(|| invalid(format!("The address range {} is not a valid IPv4 CIDR block.", input.cidr)))?;
        if cidr.prefix > 24 || cidr.prefix < 8 {
            return Err(invalid("The address range must be from /8 to /24."));
        }
        let auth = &input.cidr_authorization_context;
        if auth.message.trim().is_empty() || auth.signature.trim().is_empty() {
            return Err(invalid("CidrAuthorizationContext must include the signed message and its signature."));
        }
        let now = now_ms(ctx);
        let caller = account(ctx);
        let mut st = self.settled(ctx);
        let k = key(&caller, &input.cidr);
        if let Some(c) = st.byoip.get(&k) {
            if c.state != "DEPROVISIONED" && !c.state.starts_with("FAILED") {
                return Err(wrong_state(&input.cidr, &c.state));
            }
        }
        let overlapping = st.byoip.values().any(|c| {
            c.state != "DEPROVISIONED"
                && c.cidr != input.cidr
                && Cidr::parse(&c.cidr).is_some_and(|other| other.overlaps(&cidr))
        });
        if overlapping {
            return Err(invalid(format!(
                "The address range {} overlaps a range that is already provisioned.",
                input.cidr
            )));
        }
        let seq = st.next_seq();
        let c = ByoipCidr {
            account: caller,
            cidr: input.cidr.clone(),
            seq,
            state: "PENDING_PROVISIONING".into(),
            pending: Some("READY".into()),
            settles_at: now + transition_ms(),
            events: Vec::new(),
        };
        let out = describe(&c);
        st.byoip.insert(k, c);
        Ok(types::ProvisionByoipCidrResponse { byoip_cidr: Some(out) })
    }

    pub fn advertise_byoip_cidr(
        &self,
        ctx: &RequestContext,
        input: types::AdvertiseByoipCidrRequest,
    ) -> Result<types::AdvertiseByoipCidrResponse, ServiceError> {
        let c =
            self.transition(ctx, "AdvertiseByoipCidr", &input.cidr, "READY", "PENDING_ADVERTISING", "ADVERTISING")?;
        Ok(types::AdvertiseByoipCidrResponse { byoip_cidr: Some(c) })
    }

    pub fn withdraw_byoip_cidr(
        &self,
        ctx: &RequestContext,
        input: types::WithdrawByoipCidrRequest,
    ) -> Result<types::WithdrawByoipCidrResponse, ServiceError> {
        let c =
            self.transition(ctx, "WithdrawByoipCidr", &input.cidr, "ADVERTISING", "PENDING_WITHDRAWING", "READY")?;
        Ok(types::WithdrawByoipCidrResponse { byoip_cidr: Some(c) })
    }

    pub fn deprovision_byoip_cidr(
        &self,
        ctx: &RequestContext,
        input: types::DeprovisionByoipCidrRequest,
    ) -> Result<types::DeprovisionByoipCidrResponse, ServiceError> {
        let c = self.transition(
            ctx,
            "DeprovisionByoipCidr",
            &input.cidr,
            "READY",
            "PENDING_DEPROVISIONING",
            "DEPROVISIONED",
        )?;
        Ok(types::DeprovisionByoipCidrResponse { byoip_cidr: Some(c) })
    }

    pub fn list_byoip_cidrs(
        &self,
        ctx: &RequestContext,
        input: types::ListByoipCidrsRequest,
    ) -> Result<types::ListByoipCidrsResponse, ServiceError> {
        authorize(ctx, "ListByoipCidrs", "*", ConditionContext::new())?;
        let st = self.settled(ctx);
        let mut items: Vec<&ByoipCidr> = st.byoip.values().filter(|c| c.account == ctx.caller.account_id).collect();
        items.sort_by_key(|c| c.seq);
        let (items, next_token) = page(items, input.max_results, input.next_token.as_deref(), 100)?;
        Ok(types::ListByoipCidrsResponse { byoip_cidrs: Some(items.into_iter().map(describe).collect()), next_token })
    }
}
