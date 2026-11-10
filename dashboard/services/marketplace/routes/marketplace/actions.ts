"use server";

import { BatchMeterUsageCommand, MeterUsageCommand, RegisterUsageCommand, ResolveCustomerCommand, type UsageRecord } from "@aws-sdk/client-marketplace-metering";
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
    const out = await control({ dimension: "dimensions", duplicate: "dimensions", productCode: "code", product: "code", sellerAccountId: "seller" }, () =>
      mws<Product>("/_aws/marketplace/products", {
        method: "POST",
        json: {
          title: required(form, "title", "Title"),
          productType: text(form, "type") || "SaaS",
          dimensions,
          productCode: text(form, "code") || undefined,
          sellerAccountId: text(form, "seller") || undefined,
        },
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

/** The entitlements of the subscribe / edit sheets: a value per dimension
 * (`dim:<name>`) and one expiry (`expires`, a local date-time) for all. */
function entitlementsFrom(product: Product, form: FormData) {
  const expires = text(form, "expires");
  const expirationDate = expires ? new Date(expires.length === 16 ? `${expires}:00Z` : expires).toISOString() : undefined;
  if (expires && Number.isNaN(new Date(expirationDate!).getTime())) throw new FieldError("expires", "Not a date", "format");
  return product.dimensions
    .map((d) => ({ dimension: d.name, raw: text(form, `dim:${d.name}`) }))
    .filter((e) => e.raw !== "")
    .map((e) => ({ dimension: e.dimension, value: parseValue(e.raw), ...(expirationDate ? { expirationDate } : {}) }));
}

export async function subscribe(product: Product, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const entitlements = entitlementsFrom(product, form);
    const account = required(form, "account", "Buyer account");
    const tokenTtl = text(form, "tokenTtl");
    const out = await control({ customerAWSAccountId: "account", customerIdentifier: "customer", licenseArn: "license", agreementId: "agreement", expirationDate: "expires", tokenExpiresInSeconds: "tokenTtl" }, () =>
      mws<{ customerIdentifier: string; registrationToken: string }>("/_aws/marketplace/subscriptions", {
        method: "POST",
        json: {
          productCode: product.productCode,
          customerAWSAccountId: account,
          entitlements,
          customerIdentifier: text(form, "customer") || undefined,
          licenseArn: text(form, "license") || undefined,
          agreementId: text(form, "agreement") || undefined,
          tokenExpiresInSeconds: tokenTtl ? Number(tokenTtl) : undefined,
        },
      }),
    );
    return { ok: true, message: `Subscribed ${out.customerIdentifier}`, detail: `x-amzn-marketplace-token: ${out.registrationToken}` };
  }, "/marketplace/product");
}

export async function updateEntitlements(product: Product, customer: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const entitlements = entitlementsFrom(product, form);
    await control({ expirationDate: "expires", dimension: "expires" }, () =>
      mws(`/_aws/marketplace/subscriptions/${encodeURIComponent(customer)}/entitlements`, { method: "PUT", json: { entitlements } }),
    );
    return entitlements.length ? `${entitlements.length} entitlement${entitlements.length > 1 ? "s" : ""} saved` : "Entitlements removed";
  }, "/marketplace/product");
}

export async function resolveCustomer(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const out = await (await metering()).send(new ResolveCustomerCommand({ RegistrationToken: required(form, "token", "Registration token").replace(/^x-amzn-marketplace-token:\s*/, "") }));
      return {
        ok: true,
        message: `Resolved ${out.CustomerIdentifier}`,
        detail: [
          `CustomerIdentifier: ${out.CustomerIdentifier}`,
          `CustomerAWSAccountId: ${out.CustomerAWSAccountId}`,
          `ProductCode: ${out.ProductCode}`,
          out.LicenseArn && `LicenseArn: ${out.LicenseArn}`,
          out.Metadata?.AgreementId && `AgreementId: ${out.Metadata.AgreementId}`,
        ]
          .filter(Boolean)
          .join("\n"),
      };
    },
    { fields: { RegistrationToken: "token", InvalidTokenException: "token", ExpiredTokenException: "token" } },
  );
}

/** A `datetime-local` value (UTC) as a Date, or now. */
function timestamp(form: FormData, field: string): Date {
  const v = text(form, field);
  if (!v) return new Date();
  const d = new Date(v.length === 16 ? `${v}:00Z` : v);
  if (Number.isNaN(d.getTime())) throw new FieldError(field, "Not a date", "format");
  return d;
}

export async function meterUsage(productCode: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const dryRun = text(form, "dryRun") === "on";
      const out = await (await metering()).send(
        new MeterUsageCommand({
          ProductCode: productCode,
          UsageDimension: required(form, "dimension", "Dimension"),
          UsageQuantity: Number(text(form, "quantity") || "1"),
          Timestamp: timestamp(form, "timestamp"),
          DryRun: dryRun || undefined,
        }),
      );
      return { ok: true, message: dryRun ? "Dry run passed" : "Recorded", detail: out.MeteringRecordId };
    },
    {
      revalidate: ["/marketplace/product"],
      fields: { UsageDimension: "dimension", UsageQuantity: "quantity", Timestamp: "timestamp", TimestampOutOfBoundsException: "timestamp", DuplicateRequestException: "quantity", InvalidUsageDimensionException: "dimension" },
    },
  );
}

export async function registerUsage(productCode: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const out = await (await metering()).send(new RegisterUsageCommand({ ProductCode: productCode, PublicKeyVersion: Number(text(form, "keyVersion") || "1"), Nonce: text(form, "nonce") || undefined }));
      let claims = "";
      try {
        claims = JSON.stringify(JSON.parse(Buffer.from(out.Signature!.split(".")[1], "base64url").toString()), null, 2);
      } catch {
        // not a JWT
      }
      return { ok: true, message: "Registered", detail: [claims, out.Signature].filter(Boolean).join("\n\n") };
    },
    { revalidate: ["/marketplace/product"], fields: { Nonce: "nonce", PublicKeyVersion: "keyVersion", InvalidPublicKeyVersionException: "keyVersion" } },
  );
}

export async function unsubscribe(customer: string) {
  return act(async () => {
    await mws(`/_aws/marketplace/subscriptions/${encodeURIComponent(customer)}`, { method: "DELETE" });
    return "Unsubscribed";
  }, "/marketplace/product");
}

export async function newToken(customer: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const ttl = text(form, "ttl");
    const out = await control({ expiresInSeconds: "ttl" }, () =>
      mws<{ registrationToken: string }>("/_aws/marketplace/registration-tokens", { method: "POST", json: { customerIdentifier: customer, expiresInSeconds: ttl ? Number(ttl) : undefined } }),
    );
    return { ok: true, message: "Registration token", detail: out.registrationToken };
  });
}

export async function meter(productCode: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const [kind, id] = required(form, "customer", "Customer").split("|");
    const record: UsageRecord =
      kind === "license"
        ? { CustomerAWSAccountId: id.split("@")[0], LicenseArn: id.split("@").slice(1).join("@"), Dimension: required(form, "dimension", "Dimension"), Quantity: Number(text(form, "quantity") || "1"), Timestamp: timestamp(form, "timestamp") }
        : { CustomerIdentifier: id, Dimension: required(form, "dimension", "Dimension"), Quantity: Number(text(form, "quantity") || "1"), Timestamp: timestamp(form, "timestamp") };
    const out = await (await metering()).send(new BatchMeterUsageCommand({ ProductCode: kind === "license" ? undefined : productCode, UsageRecords: [record] }));
    const r = out.Results?.[0];
    if (!r) throw new Error(out.UnprocessedRecords?.length ? "Unprocessed: MWS did not accept the record" : "No result");
    return { ok: r.Status === "Success", message: r.Status ?? "", detail: r.MeteringRecordId };
  }, {
    revalidate: ["/marketplace/product"],
    fields: {
      "UsageRecords.Quantity": "quantity",
      "UsageRecords.Dimension": "dimension",
      "UsageRecords.CustomerIdentifier": "customer",
      "UsageRecords.Timestamp": "timestamp",
      TimestampOutOfBoundsException: "timestamp",
      InvalidUsageDimensionException: "dimension",
      InvalidCustomerIdentifierException: "customer",
      InvalidLicenseException: "customer",
    },
  });
}

export async function clearRecords() {
  return act(async () => {
    await mws("/_aws/marketplace-metering/records", { method: "DELETE" });
    return "Cleared";
  }, "/marketplace");
}
