"use server";

import { TestEventPatternCommand } from "@aws-sdk/client-eventbridge";
import { describeError } from "@mws-dashboard/aws";

import { events } from "./clients";

/** The pattern builder's live check: EventBridge's own TestEventPattern on
 * the sample event, so the answer is the service's, not the console's. */
export async function testPatternLive(pattern: string, event: string): Promise<{ match?: boolean; error?: string }> {
  try {
    const out = await (await events()).send(new TestEventPatternCommand({ EventPattern: pattern, Event: event }));
    return { match: !!out.Result };
  } catch (e) {
    return { error: describeError(e).replace(/^InvalidEventPatternException: Event pattern is not valid\. Reason: /, "") };
  }
}
