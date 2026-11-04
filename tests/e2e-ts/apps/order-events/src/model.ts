export interface Order {
  orderId: string;
  customerId: string;
  total: number;
  currency: string;
  billingCountry: string;
  shippingCountry: string;
}

export interface FraudCheckResult {
  orderId: string;
  riskScore: number;
  decision: "approve" | "review";
}

export const ORDER_SOURCE = "shop.orders";
export const FRAUD_SOURCE = "shop.fraud";
