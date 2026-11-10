"use server";

import { RequestServiceQuotaIncreaseCommand } from "@aws-sdk/client-service-quotas";
import { act, FieldError, required, type ActionResult } from "@mws-dashboard/aws";

import { quotas } from "../../lib/clients";

export async function requestIncrease(service: string, quota: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const DesiredValue = Number(required(form, "value", "Value"));
      try {
        const out = await (await quotas()).send(new RequestServiceQuotaIncreaseCommand({ ServiceCode: service, QuotaCode: quota, DesiredValue }));
        return `Requested ${DesiredValue} (${out.RequestedQuota?.Status?.toLowerCase().replace(/_/g, " ")})`;
      } catch (e) {
        if (!(e instanceof Error)) throw e;
        // The quota may have risen since the page loaded: the new floor
        // becomes the field's minimum, so its repair raises the value.
        const current = e.message.match(/less than or equal to the current value (-?[\d.]+)/)?.[1];
        if (e.name === "IllegalArgumentException" && current !== undefined) {
          const min = Math.floor(Number(current)) + 1;
          throw new FieldError("value", `Above ${current}`, "range", { min, type: "number" });
        }
        if (e.name === "ResourceAlreadyExistsException") throw new FieldError("value", "An increase is already pending");
        throw e;
      }
    },
    { revalidate: ["/servicequotas"], fields: { DesiredValue: "value" } },
  );
}
