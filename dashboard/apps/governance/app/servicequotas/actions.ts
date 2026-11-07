"use server";

import { RequestServiceQuotaIncreaseCommand } from "@aws-sdk/client-service-quotas";
import { act, required, type ActionResult } from "@mws-dashboard/aws";

import { quotas } from "../../lib/clients";

export async function requestIncrease(service: string, quota: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const DesiredValue = Number(required(form, "value", "Value"));
    const out = await (await quotas()).send(new RequestServiceQuotaIncreaseCommand({ ServiceCode: service, QuotaCode: quota, DesiredValue }));
    return `Requested ${DesiredValue} (${out.RequestedQuota?.Status?.toLowerCase().replace(/_/g, " ")})`;
  }, "/servicequotas");
}
