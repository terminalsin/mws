import { PutEventsCommand } from "@aws-sdk/client-eventbridge";
import { events } from "./clients.js";
import { ORDER_SOURCE, type Order } from "./model.js";

/** What the checkout service does when an order is placed. */
export async function publishOrderPlaced(eventBusName: string, order: Order): Promise<string> {
  const { Entries = [], FailedEntryCount } = await events.send(
    new PutEventsCommand({
      Entries: [
        {
          EventBusName: eventBusName,
          Source: ORDER_SOURCE,
          DetailType: "OrderPlaced",
          Detail: JSON.stringify(order),
        },
      ],
    }),
  );
  if (FailedEntryCount) throw new Error(`${Entries[0]?.ErrorCode}: ${Entries[0]?.ErrorMessage}`);
  return Entries[0]!.EventId!;
}
