"use server";

import {
  CreateEventBusCommand,
  DeleteEventBusCommand,
  DeleteRuleCommand,
  DisableRuleCommand,
  EnableRuleCommand,
  ListTargetsByRuleCommand,
  PutEventsCommand,
  PutRuleCommand,
  PutTargetsCommand,
  RemoveTargetsCommand,
} from "@aws-sdk/client-eventbridge";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

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

export async function createRule(bus: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await events();
    const name = required(form, "name", "Rule name");
    const pattern = text(form, "pattern");
    const schedule = text(form, "schedule");
    if (!pattern && !schedule) throw new Error("Give an event pattern or a schedule");
    if (pattern) JSON.parse(pattern);
    await client.send(
      new PutRuleCommand({
        Name: name,
        EventBusName: bus,
        ...(pattern ? { EventPattern: pattern } : { ScheduleExpression: schedule }),
        State: "ENABLED",
      }),
    );
    const target = text(form, "target");
    if (target) await client.send(new PutTargetsCommand({ Rule: name, EventBusName: bus, Targets: [{ Id: "target-1", Arn: target }] }));
    return `Created ${name}`;
  }, "/events");
}

export async function deleteRule(bus: string, rule: string) {
  return act(async () => {
    const client = await events();
    const targets = (await client.send(new ListTargetsByRuleCommand({ Rule: rule, EventBusName: bus }))).Targets ?? [];
    if (targets.length) await client.send(new RemoveTargetsCommand({ Rule: rule, EventBusName: bus, Ids: targets.map((t) => t.Id!) }));
    await client.send(new DeleteRuleCommand({ Name: rule, EventBusName: bus }));
    return `Deleted ${rule}`;
  }, "/events");
}

export async function deleteBus(bus: string) {
  return act(async () => {
    await (await events()).send(new DeleteEventBusCommand({ Name: bus }));
    redirect("/events");
  });
}
