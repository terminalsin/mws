import { FilterLogEventsCommand, ResourceNotFoundException } from "@aws-sdk/client-cloudwatch-logs";
import { TestEventPatternCommand } from "@aws-sdk/client-eventbridge";
import { InvokeCommand } from "@aws-sdk/client-lambda";
import { ReceiveMessageCommand } from "@aws-sdk/client-sqs";
import { randomBytes, randomUUID } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { events, lambda, logs, sqs } from "../src/clients.js";
import { HIGH_VALUE_PATTERN, provisionOrderFlow, type OrderFlow } from "../src/infrastructure.js";
import type { FraudCheckResult, Order } from "../src/model.js";
import { publishOrderPlaced } from "../src/orders.js";

let flow: OrderFlow;

beforeAll(async () => {
  flow = await provisionOrderFlow(`shop-${randomBytes(4).toString("hex")}`);
});

function order(overrides: Partial<Order> = {}): Order {
  return {
    orderId: randomUUID(),
    customerId: "c-42",
    total: 120,
    currency: "EUR",
    billingCountry: "NL",
    shippingCountry: "NL",
    ...overrides,
  };
}

/** Long-polls a queue until a message body satisfies the predicate. */
async function waitForMessage<T>(queueUrl: string, predicate: (body: T) => boolean): Promise<T> {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const { Messages = [] } = await sqs.send(
      new ReceiveMessageCommand({ QueueUrl: queueUrl, MaxNumberOfMessages: 10, WaitTimeSeconds: 1 }),
    );
    for (const message of Messages) {
      const body = JSON.parse(message.Body!) as T;
      if (predicate(body)) return body;
    }
  }
  throw new Error(`no matching message on ${queueUrl}`);
}

async function findLogEvents(logGroupName: string, filterPattern: string) {
  const deadline = Date.now() + 30_000;
  for (;;) {
    try {
      const { events: found = [] } = await logs.send(new FilterLogEventsCommand({ logGroupName, filterPattern }));
      if (found.length > 0) return found;
    } catch (err) {
      // The function creates its log group on first write.
      if (!(err instanceof ResourceNotFoundException)) throw err;
    }
    if (Date.now() > deadline) throw new Error(`no log events in ${logGroupName}`);
    await new Promise((r) => setTimeout(r, 250));
  }
}

describe("order events", () => {
  it("routes only high-value orders to the fraud check", async () => {
    const matches = async (total: number) => {
      const event = {
        id: randomUUID(),
        account: "123456789012",
        source: "shop.orders",
        "detail-type": "OrderPlaced",
        time: new Date().toISOString(),
        region: "us-east-1",
        resources: [],
        detail: order({ total }),
      };
      const { Result } = await events.send(
        new TestEventPatternCommand({ EventPattern: JSON.stringify(HIGH_VALUE_PATTERN), Event: JSON.stringify(event) }),
      );
      return Result;
    };
    expect(await matches(499.99)).toBe(false);
    expect(await matches(500)).toBe(true);
  });

  it("writes every order to the audit queue in the transformed shape", async () => {
    const placed = order({ total: 42.5 });
    await publishOrderPlaced(flow.eventBusName, placed);

    const audit = await waitForMessage<{ orderId: string; total: number; placedAt: string }>(
      flow.auditQueueUrl,
      (body) => body.orderId === placed.orderId,
    );
    expect(audit).toEqual({ orderId: placed.orderId, total: 42.5, placedAt: expect.stringMatching(/^\d{4}-\d\d-\d\dT/) });
  });

  it("runs the fraud-check Lambda for a high-value order and routes its verdict", async () => {
    const placed = order({ total: 2500, shippingCountry: "BE" });
    await publishOrderPlaced(flow.eventBusName, placed);

    const verdict = await waitForMessage<{ source: string; "detail-type": string; detail: FraudCheckResult }>(
      flow.resultsQueueUrl,
      (body) => body.detail.orderId === placed.orderId,
    );
    expect(verdict).toMatchObject({
      source: "shop.fraud",
      "detail-type": "FraudCheckCompleted",
      detail: { orderId: placed.orderId, riskScore: 65, decision: "review" },
    });

    // The function's console output lands in its CloudWatch Logs group.
    // Log delivery is asynchronous (in AWS too), so poll for it.
    const logEvents = await findLogEvents(`/aws/lambda/${flow.functionName}`, `"${placed.orderId}"`);
    expect(logEvents.length).toBeGreaterThan(0);
  });

  it("can be invoked directly with a hand-written event", async () => {
    const placed = order({ total: 800 });
    const response = await lambda.send(
      new InvokeCommand({
        FunctionName: flow.functionName,
        Payload: JSON.stringify({ id: "manual", source: "shop.orders", "detail-type": "OrderPlaced", detail: placed }),
      }),
    );
    expect(response.StatusCode).toBe(200);
    expect(response.FunctionError).toBeUndefined();
    const result = JSON.parse(Buffer.from(response.Payload!).toString()) as FraudCheckResult;
    expect(result).toEqual({ orderId: placed.orderId, riskScore: 8, decision: "approve" });
  });

  it("reports a handler error the way Lambda does", async () => {
    const response = await lambda.send(
      new InvokeCommand({ FunctionName: flow.functionName, Payload: JSON.stringify({ id: "broken" }) }),
    );
    expect(response.FunctionError).toBe("Unhandled");
    const error = JSON.parse(Buffer.from(response.Payload!).toString());
    expect(error).toMatchObject({ errorType: "TypeError" });
  });
});
