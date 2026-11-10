"use server";

import {
  CreateSupportCaseCommand,
  ListTagsForResourceCommand,
  RequestServiceQuotaIncreaseCommand,
  StartAutoManagementCommand,
  StartQuotaUtilizationReportCommand,
  StopAutoManagementCommand,
  TagResourceCommand,
  UntagResourceCommand,
  UpdateAutoManagementCommand,
  type OptInType,
} from "@aws-sdk/client-service-quotas";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

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
    { revalidate: ["/servicequotas", `/servicequotas/quota`], fields: { DesiredValue: "value" } },
  );
}

/** Open a support case on a pending request (it moves to CASE_OPENED). */
export async function createSupportCase(request: string) {
  return act(async () => {
    await (await quotas()).send(new CreateSupportCaseCommand({ RequestId: request }));
    return "Support case opened";
  }, "/servicequotas/quota");
}

export async function saveQuotaTags(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Tags = text(form, "tags")
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l, i) => {
        const [Key, ...rest] = l.split("=");
        if (!rest.length || !Key.trim()) throw new FieldError("tags", `Line ${i + 1}: key=value`, "format");
        return { Key: Key.trim(), Value: rest.join("=").trim() };
      });
    const client = await quotas();
    const current = (await client.send(new ListTagsForResourceCommand({ ResourceARN: arn }))).Tags ?? [];
    const TagKeys = current.map((t) => t.Key!).filter((k) => !Tags.some((t) => t.Key === k));
    if (TagKeys.length) await client.send(new UntagResourceCommand({ ResourceARN: arn, TagKeys }));
    if (Tags.length) await client.send(new TagResourceCommand({ ResourceARN: arn, Tags }));
    return "Tags saved";
  }, { revalidate: ["/servicequotas/quota"], fields: { Tags: "tags", TagKeys: "tags", TagPolicyViolationException: "tags", TooManyTagsException: "tags" } });
}

export async function startUtilizationReport() {
  return act(async () => {
    const out = await (await quotas()).send(new StartQuotaUtilizationReportCommand({}));
    redirect(`/servicequotas?tab=utilization&report=${encodeURIComponent(out.ReportId!)}`);
  });
}

/** `service=QUOTA1,QUOTA2` lines (or a bare service code for all of it) as an exclusion list. */
function exclusions(form: FormData): Record<string, string[]> | undefined {
  const lines = text(form, "exclude")
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
  if (!lines.length) return undefined;
  return Object.fromEntries(
    lines.map((l) => {
      const [service, codes = ""] = l.split("=");
      return [service.trim(), codes.split(",").map((c) => c.trim()).filter(Boolean)];
    }),
  );
}

export async function saveAutoManagement(running: boolean, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const OptInType = (text(form, "type") || "NotifyOnly") as OptInType;
    const client = await quotas();
    if (running) await client.send(new UpdateAutoManagementCommand({ OptInType, ExclusionList: exclusions(form) ?? {} }));
    else await client.send(new StartAutoManagementCommand({ OptInLevel: "ACCOUNT", OptInType, ExclusionList: exclusions(form) }));
    return running ? "Automatic management updated" : "Automatic management started";
  }, { revalidate: ["/servicequotas/automatic"], fields: { OptInType: "type", ExclusionList: "exclude" } });
}

export async function stopAutoManagement() {
  return act(async () => {
    await (await quotas()).send(new StopAutoManagementCommand({}));
    return "Automatic management stopped";
  }, "/servicequotas/automatic");
}
