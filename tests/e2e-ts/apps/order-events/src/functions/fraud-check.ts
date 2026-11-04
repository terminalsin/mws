// Lambda function: scores high-value orders and publishes the verdict back to
// the bus as a FraudCheckCompleted event. It is bundled with esbuild (SDK
// included), as you would for a real deployment.
import { EventBridgeClient, PutEventsCommand } from "@aws-sdk/client-eventbridge";
import { FRAUD_SOURCE, type FraudCheckResult, type Order } from "../model.js";

interface EventBridgeEvent<T> {
  id: string;
  "detail-type": string;
  source: string;
  detail: T;
}

// Created once per execution environment and reused across invocations.
// Inside Lambda the SDK picks up the role's credentials from the environment.
const client = new EventBridgeClient({});

export function score(order: Order): FraudCheckResult {
  let riskScore = Math.min(order.total / 100, 50);
  if (order.billingCountry !== order.shippingCountry) riskScore += 40;
  riskScore = Math.round(riskScore);
  return { orderId: order.orderId, riskScore, decision: riskScore >= 60 ? "review" : "approve" };
}

export async function handler(event: EventBridgeEvent<Order>): Promise<FraudCheckResult> {
  const result = score(event.detail);
  console.log(JSON.stringify({ message: "fraud check", eventId: event.id, ...result }));
  const response = await client.send(
    new PutEventsCommand({
      Entries: [
        {
          EventBusName: process.env.EVENT_BUS_NAME,
          Source: FRAUD_SOURCE,
          DetailType: "FraudCheckCompleted",
          Detail: JSON.stringify(result),
        },
      ],
    }),
  );
  if (response.FailedEntryCount) {
    throw new Error(`PutEvents failed: ${JSON.stringify(response.Entries)}`);
  }
  return result;
}
