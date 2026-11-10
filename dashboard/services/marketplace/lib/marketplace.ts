import "server-only";

import { endpoint, mws } from "@mws-dashboard/aws";

// The Marketplace catalog has no SDK operations: MWS keeps it behind /_aws/marketplace.

export type EntitlementValue = { integerValue?: number; doubleValue?: number; booleanValue?: boolean; stringValue?: string };

export interface Product {
  productCode: string;
  sellerAccountId: string;
  title: string;
  productType: "SaaS" | "AMI" | "Container";
  dimensions: { name: string; description?: string | null }[];
  createdAt?: string | null;
}

export interface Subscription {
  customerIdentifier: string;
  customerAWSAccountId: string;
  productCode: string;
  licenseArn: string;
  agreementId: string;
  status: "Active" | "Unsubscribed";
  subscribedAt?: string | null;
  unsubscribedAt?: string | null;
  entitlements: { dimension: string; value: EntitlementValue; expirationDate?: string | null }[];
}

export interface MeteringRecord {
  meteringRecordId: string;
  operation: string;
  productCode: string;
  customerIdentifier?: string | null;
  customerAWSAccountId: string;
  dimension: string;
  quantity: number;
  timestamp: string;
  reportedBy: string;
  recordedAt: string;
}

export const products = async () => (await mws<{ products: Product[] }>("/_aws/marketplace/products")).products;
export const product = (code: string) => mws<Product>(`/_aws/marketplace/products/${encodeURIComponent(code)}`);
export const subscriptions = async (productCode?: string) =>
  (await mws<{ subscriptions: Subscription[] }>(`/_aws/marketplace/subscriptions${productCode ? `?productCode=${encodeURIComponent(productCode)}` : ""}`)).subscriptions;
export interface RecordFilter {
  productCode?: string;
  customerAWSAccountId?: string;
  customerIdentifier?: string;
  dimension?: string;
}

const query = (q: object) => {
  const s = new URLSearchParams(Object.entries(q).filter(([, v]) => v) as [string, string][]).toString();
  return s ? `?${s}` : "";
};

export const records = async (filter: string | RecordFilter = {}) =>
  (await mws<{ records: MeteringRecord[] }>(`/_aws/marketplace-metering/records${query(typeof filter === "string" ? { productCode: filter } : filter)}`)).records;

export interface Registration {
  productCode: string;
  customerAWSAccountId: string;
  customerIdentifier?: string | null;
  nonce?: string | null;
  registeredBy: string;
  registeredAt: string;
}

export const registrations = async (productCode?: string) =>
  (await mws<{ registrations: Registration[] }>(`/_aws/marketplace-metering/registrations${query({ productCode })}`)).registrations;

/** The PEM key RegisterUsage signatures verify against (MWS's, not AWS's). */
export async function publicKey(): Promise<string> {
  const r = await fetch(`${endpoint()}/_aws/marketplace-metering/public-key`, { cache: "no-store" });
  if (!r.ok) throw new Error(`public-key answered ${r.status}`);
  return r.text();
}

/** Has this entitlement expired (as GetEntitlements sees it)? */
export function expired(e: { expirationDate?: string | null }, now = Date.now()): boolean {
  return !!e.expirationDate && new Date(e.expirationDate).getTime() <= now;
}

export function valueText(v: EntitlementValue): string {
  if (v.integerValue !== undefined) return String(v.integerValue);
  if (v.doubleValue !== undefined) return String(v.doubleValue);
  if (v.booleanValue !== undefined) return v.booleanValue ? "✓" : "✗";
  return v.stringValue ?? "";
}

export const PRODUCT_ICONS: Record<string, string> = {
  SaaS: "service/AWSMarketplace",
  AMI: "resource/AmazonEC2AMI",
  Container: "service/AmazonElasticContainerService",
};
