"use server";

import { CreateEventBusCommand, DisableRuleCommand, EnableRuleCommand, PutEventsCommand } from "@aws-sdk/client-eventbridge";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";

import { events } from "../../lib/clients";

export async function createBus(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await events()).send(new CreateEventBusCommand({ Name: required(form, "name", "Bus name") }));
    return `Created ${out.EventBusArn}`;
  }, "/events");
}

export async function putEvent(bus: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const detail = text(form, "detail") || "{}";
    try {
      JSON.parse(detail);
    } catch {
      throw new Error("Detail must be a JSON object");
    }
    const out = await (await events()).send(
      new PutEventsCommand({
        Entries: [
          {
            EventBusName: bus,
            Source: required(form, "source", "Source"),
            DetailType: required(form, "detailType", "Detail type"),
            Detail: detail,
          },
        ],
      }),
    );
    const entry = out.Entries?.[0];
    if (out.FailedEntryCount) return { ok: false, message: `${entry?.ErrorCode}: ${entry?.ErrorMessage}` };
    return `Put event ${entry?.EventId}`;
  }, "/events");
}

export async function setRuleState(bus: string, rule: string, enable: boolean) {
  return act(async () => {
    const client = await events();
    await client.send(enable ? new EnableRuleCommand({ Name: rule, EventBusName: bus }) : new DisableRuleCommand({ Name: rule, EventBusName: bus }));
    return enable ? "Enabled" : "Disabled";
  }, "/events");
}
