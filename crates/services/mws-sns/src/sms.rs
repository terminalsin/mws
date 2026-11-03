//! SMS settings, opt-outs, the SMS sandbox and origination numbers.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types;
use crate::names::{self, account_of};
use crate::outbox::SmsMessage;
use crate::state::SandboxNumber;
use crate::topics::paginate;
use crate::{errors, Sns};

const SMS_ATTRIBUTES: &[&str] = &[
    "MonthlySpendLimit",
    "DeliveryStatusIAMRole",
    "DeliveryStatusSuccessSamplingRate",
    "DefaultSenderID",
    "DefaultSMSType",
    "UsageReportS3Bucket",
];
const OPTED_OUT_PAGE: usize = 100;

fn check_number(n: &str) -> Result<(), ServiceError> {
    if names::valid_phone_number(n) {
        Ok(())
    } else {
        Err(errors::invalid("PhoneNumber Reason: input incorrectly formatted"))
    }
}

fn check_sms_attribute(k: &str, v: &str) -> Result<(), ServiceError> {
    let ok = match k {
        "MonthlySpendLimit" => v.parse::<u64>().is_ok(),
        "DeliveryStatusIAMRole" => v.is_empty() || v.starts_with("arn:"),
        "DeliveryStatusSuccessSamplingRate" => v.parse::<u32>().is_ok_and(|r| r <= 100),
        "DefaultSenderID" => {
            (1..=11).contains(&v.len())
                && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && v.bytes().any(|b| b.is_ascii_alphabetic())
        }
        "DefaultSMSType" => matches!(v, "Promotional" | "Transactional"),
        "UsageReportS3Bucket" => !v.is_empty(),
        _ => return Err(errors::invalid(format!("Unknown SMS attribute: {k}"))),
    };
    if ok {
        Ok(())
    } else {
        Err(errors::invalid(k))
    }
}

impl Sns {
    pub(crate) fn set_sms_attributes_impl(
        &self,
        ctx: &RequestContext,
        input: types::SetSMSAttributesInput,
    ) -> Result<types::SetSMSAttributesResponse, ServiceError> {
        ctx.authorize("sns:SetSMSAttributes", "*", ConditionContext::new())?;
        for (k, v) in &input.attributes {
            check_sms_attribute(k, v)?;
        }
        let mut st = self.lock();
        let acct = st.sms.entry(account_of(ctx)).or_default();
        for (k, v) in input.attributes {
            acct.attributes.insert(k, v);
        }
        Ok(types::SetSMSAttributesResponse {})
    }

    pub(crate) fn get_sms_attributes_impl(
        &self,
        ctx: &RequestContext,
        input: types::GetSMSAttributesInput,
    ) -> Result<types::GetSMSAttributesResponse, ServiceError> {
        ctx.authorize("sns:GetSMSAttributes", "*", ConditionContext::new())?;
        let st = self.lock();
        let mut attrs = st.sms.get(&account_of(ctx)).map(|a| a.attributes.clone()).unwrap_or_default();
        if let Some(wanted) = input.attributes.filter(|w| !w.is_empty()) {
            for w in &wanted {
                if !SMS_ATTRIBUTES.contains(&w.as_str()) {
                    return Err(errors::invalid(format!("Unknown SMS attribute: {w}")));
                }
            }
            attrs.retain(|k, _| wanted.contains(k));
        }
        Ok(types::GetSMSAttributesResponse { attributes: Some(attrs) })
    }

    pub(crate) fn check_if_phone_number_is_opted_out_impl(
        &self,
        ctx: &RequestContext,
        input: types::CheckIfPhoneNumberIsOptedOutInput,
    ) -> Result<types::CheckIfPhoneNumberIsOptedOutResponse, ServiceError> {
        ctx.authorize("sns:CheckIfPhoneNumberIsOptedOut", "*", ConditionContext::new())?;
        check_number(&input.phone_number)?;
        let st = self.lock();
        Ok(types::CheckIfPhoneNumberIsOptedOutResponse { is_opted_out: st.opted_out.contains(&input.phone_number) })
    }

    pub(crate) fn list_phone_numbers_opted_out_impl(
        &self,
        ctx: &RequestContext,
        input: types::ListPhoneNumbersOptedOutInput,
    ) -> Result<types::ListPhoneNumbersOptedOutResponse, ServiceError> {
        ctx.authorize("sns:ListPhoneNumbersOptedOut", "*", ConditionContext::new())?;
        let st = self.lock();
        let numbers: Vec<&str> = st.opted_out.iter().map(String::as_str).collect();
        let (page, next) = paginate(&numbers, input.next_token.as_deref(), OPTED_OUT_PAGE)?;
        Ok(types::ListPhoneNumbersOptedOutResponse {
            phone_numbers: Some(page.into_iter().map(str::to_string).collect()),
            next_token: next,
        })
    }

    pub(crate) fn opt_in_phone_number_impl(
        &self,
        ctx: &RequestContext,
        input: types::OptInPhoneNumberInput,
    ) -> Result<types::OptInPhoneNumberResponse, ServiceError> {
        ctx.authorize("sns:OptInPhoneNumber", "*", ConditionContext::new())?;
        check_number(&input.phone_number)?;
        self.lock().opted_out.remove(&input.phone_number);
        Ok(types::OptInPhoneNumberResponse {})
    }

    pub(crate) fn get_sms_sandbox_account_status_impl(
        &self,
        ctx: &RequestContext,
    ) -> Result<types::GetSMSSandboxAccountStatusResult, ServiceError> {
        ctx.authorize("sns:GetSMSSandboxAccountStatus", "*", ConditionContext::new())?;
        // MWS accounts have production SMS access, so any number can be
        // sent to; the sandbox number list still works.
        Ok(types::GetSMSSandboxAccountStatusResult { is_in_sandbox: false })
    }

    pub(crate) fn create_sms_sandbox_phone_number_impl(
        &self,
        ctx: &RequestContext,
        input: types::CreateSMSSandboxPhoneNumberInput,
    ) -> Result<types::CreateSMSSandboxPhoneNumberResult, ServiceError> {
        ctx.authorize("sns:CreateSMSSandboxPhoneNumber", "*", ConditionContext::new())?;
        check_number(&input.phone_number)?;
        let account = account_of(ctx);
        let otp = format!("{:06}", rand::random::<u32>() % 1_000_000);
        let mut st = self.lock();
        let acct = st.sms.entry(account.clone()).or_default();
        if acct.sandbox_numbers.get(&input.phone_number).is_some_and(|n| n.status == "Verified") {
            return Err(errors::invalid("PhoneNumber Reason: The phone number is already verified"));
        }
        if acct.sandbox_numbers.len() >= 10 && !acct.sandbox_numbers.contains_key(&input.phone_number) {
            return Err(errors::user_error("You have reached the maximum number of sandbox phone numbers"));
        }
        acct.sandbox_numbers.insert(
            input.phone_number.clone(),
            SandboxNumber {
                status: "Pending".into(),
                one_time_password: otp.clone(),
                language_code: input.language_code,
            },
        );
        st.outbox.sms(SmsMessage {
            message_id: uuid::Uuid::new_v4().to_string(),
            phone_number: input.phone_number,
            message: format!("Your Amazon SNS verification code is: {otp}"),
            sms_type: Some("Transactional".into()),
            account_id: account,
            region: ctx.region.clone(),
            timestamp: crate::delivery::timestamp(&ctx.received_at),
            ..SmsMessage::default()
        });
        Ok(types::CreateSMSSandboxPhoneNumberResult {})
    }

    pub(crate) fn verify_sms_sandbox_phone_number_impl(
        &self,
        ctx: &RequestContext,
        input: types::VerifySMSSandboxPhoneNumberInput,
    ) -> Result<types::VerifySMSSandboxPhoneNumberResult, ServiceError> {
        ctx.authorize("sns:VerifySMSSandboxPhoneNumber", "*", ConditionContext::new())?;
        check_number(&input.phone_number)?;
        let mut st = self.lock();
        let n = st
            .sms
            .get_mut(&account_of(ctx))
            .and_then(|a| a.sandbox_numbers.get_mut(&input.phone_number))
            .ok_or_else(|| errors::resource_not_found("Phone number does not exist"))?;
        if n.one_time_password != input.one_time_password {
            return Err(errors::verification("Invalid one-time password"));
        }
        n.status = "Verified".into();
        Ok(types::VerifySMSSandboxPhoneNumberResult {})
    }

    pub(crate) fn delete_sms_sandbox_phone_number_impl(
        &self,
        ctx: &RequestContext,
        input: types::DeleteSMSSandboxPhoneNumberInput,
    ) -> Result<types::DeleteSMSSandboxPhoneNumberResult, ServiceError> {
        ctx.authorize("sns:DeleteSMSSandboxPhoneNumber", "*", ConditionContext::new())?;
        check_number(&input.phone_number)?;
        let mut st = self.lock();
        st.sms
            .get_mut(&account_of(ctx))
            .and_then(|a| a.sandbox_numbers.remove(&input.phone_number))
            .ok_or_else(|| errors::resource_not_found("Phone number does not exist"))?;
        Ok(types::DeleteSMSSandboxPhoneNumberResult {})
    }

    pub(crate) fn list_sms_sandbox_phone_numbers_impl(
        &self,
        ctx: &RequestContext,
        input: types::ListSMSSandboxPhoneNumbersInput,
    ) -> Result<types::ListSMSSandboxPhoneNumbersResult, ServiceError> {
        ctx.authorize("sns:ListSMSSandboxPhoneNumbers", "*", ConditionContext::new())?;
        let page = input.max_results.unwrap_or(100).clamp(1, 100) as usize;
        let st = self.lock();
        let empty = Default::default();
        let numbers = st.sms.get(&account_of(ctx)).map(|a| &a.sandbox_numbers).unwrap_or(&empty);
        let keys: Vec<&str> = numbers.keys().map(String::as_str).collect();
        let (items, next) = paginate(&keys, input.next_token.as_deref(), page)?;
        Ok(types::ListSMSSandboxPhoneNumbersResult {
            phone_numbers: items
                .into_iter()
                .map(|k| types::SMSSandboxPhoneNumber {
                    phone_number: Some(k.to_string()),
                    status: numbers.get(k).map(|n| n.status.clone()),
                })
                .collect(),
            next_token: next,
        })
    }

    pub(crate) fn list_origination_numbers_impl(
        &self,
        ctx: &RequestContext,
        input: types::ListOriginationNumbersRequest,
    ) -> Result<types::ListOriginationNumbersResult, ServiceError> {
        ctx.authorize("sns:ListOriginationNumbers", "*", ConditionContext::new())?;
        if let Some(m) = input.max_results {
            if !(1..=30).contains(&m) {
                return Err(errors::validation("1 validation error detected: Value at 'maxResults' failed to satisfy constraint: Member must have value less than or equal to 30"));
            }
        }
        // MWS accounts own no origination numbers.
        Ok(types::ListOriginationNumbersResult { next_token: None, phone_numbers: Some(Vec::new()) })
    }
}
