import "server-only";

import { mws } from "@mws-dashboard/aws";

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
export const records = async (productCode?: string) =>
  (await mws<{ records: MeteringRecord[] }>(`/_aws/marketplace-metering/records${productCode ? `?productCode=${encodeURIComponent(productCode)}` : ""}`)).records;

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
