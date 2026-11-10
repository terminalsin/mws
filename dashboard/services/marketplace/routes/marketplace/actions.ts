"use server";

import { BatchMeterUsageCommand } from "@aws-sdk/client-marketplace-metering";
import { act, FieldError, mws, required, text, type ActionResult } from "@mws-dashboard/aws";
import { listItems } from "@mws-dashboard/ui/validation";
import { redirect } from "next/navigation";

import { metering } from "../../lib/clients";
import { type EntitlementValue, type Product } from "../../lib/marketplace";

/** The catalog control API answers plain messages that start with the
 * member they concern ("customerAWSAccountId must be ..."): land them on
 * the form field that fills it. */
async function control<T>(fields: Record<string, string>, run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (e) {
    const message = e instanceof Error ? e.message.replace(/^\S+ answered \d+: /, "") : "";
    const member = Object.keys(fields).find((m) => message.toLowerCase().startsWith(m.toLowerCase()));
    if (member) throw new FieldError(fields[member], message.charAt(0).toUpperCase() + message.slice(1));
    throw e;
  }
}

export async function createProduct(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const dimensions = listItems(text(form, "dimensions")).map((name) => ({ name }));
    if (dimensions.length === 0) throw new FieldError("dimensions", "Required", "required");
    const out = await control({ dimension: "dimensions", duplicate: "dimensions" }, () =>
      mws<Product>("/_aws/marketplace/products", {
        method: "POST",
        json: { title: required(form, "title", "Title"), productType: text(form, "type") || "SaaS", dimensions },
      }),
    );
    redirect(`/marketplace/product?code=${out.productCode}`);
  });
}

export async function deleteProduct(code: string) {
  return act(async () => {
    await mws(`/_aws/marketplace/products/${encodeURIComponent(code)}`, { method: "DELETE" });
    redirect("/marketplace");
  });
}

function parseValue(raw: string): EntitlementValue {
  if (/^-?\d+$/.test(raw)) return { integerValue: Number(raw) };
  if (/^-?\d*\.\d+$/.test(raw)) return { doubleValue: Number(raw) };
  if (raw === "true" || raw === "false") return { booleanValue: raw === "true" };
  return { stringValue: raw };
}

export async function subscribe(product: Product, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const entitlements = product.dimensions
      .map((d) => ({ dimension: d.name, raw: text(form, `dim:${d.name}`) }))
      .filter((e) => e.raw !== "")
      .map((e) => ({ dimension: e.dimension, value: parseValue(e.raw) }));
    const account = required(form, "account", "Buyer account");
    const out = await control({ customerAWSAccountId: "account" }, () =>
      mws<{ customerIdentifier: string; registrationToken: string }>("/_aws/marketplace/subscriptions", {
        method: "POST",
        json: { productCode: product.productCode, customerAWSAccountId: account, entitlements },
      }),
    );
    return { ok: true, message: `Subscribed ${out.customerIdentifier}`, detail: `x-amzn-marketplace-token: ${out.registrationToken}` };
  }, "/marketplace/product");
}

export async function unsubscribe(customer: string) {
  return act(async () => {
    await mws(`/_aws/marketplace/subscriptions/${encodeURIComponent(customer)}`, { method: "DELETE" });
    return "Unsubscribed";
  }, "/marketplace/product");
}

export async function newToken(customer: string) {
  return act(async () => {
    const out = await mws<{ registrationToken: string }>("/_aws/marketplace/registration-tokens", { method: "POST", json: { customerIdentifier: customer } });
    return { ok: true, message: "Registration token", detail: out.registrationToken };
  });
}

export async function meter(productCode: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await metering()).send(
      new BatchMeterUsageCommand({
        ProductCode: productCode,
        UsageRecords: [
          {
            CustomerIdentifier: required(form, "customer", "Customer"),
            Dimension: required(form, "dimension", "Dimension"),
            Quantity: Number(text(form, "quantity") || "1"),
            Timestamp: new Date(),
          },
        ],
      }),
    );
    const r = out.Results?.[0];
    if (!r) throw new Error(out.UnprocessedRecords?.length ? "Unprocessed" : "No result");
    return { ok: r.Status === "Success", message: r.Status ?? "", detail: r.MeteringRecordId };
  }, {
    revalidate: ["/marketplace/product"],
    fields: { "UsageRecords.Quantity": "quantity", "UsageRecords.Dimension": "dimension", "UsageRecords.CustomerIdentifier": "customer" },
  });
}

export async function clearRecords() {
  return act(async () => {
    await mws("/_aws/marketplace-metering/records", { method: "DELETE" });
    return "Cleared";
  }, "/marketplace");
}
