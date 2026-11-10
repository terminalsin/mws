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
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { events } from "../../lib/clients";

export async function createBus(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await events()).send(new CreateEventBusCommand({ Name: required(form, "name", "Bus name") }));
    return `Created ${out.EventBusArn}`;
  }, { revalidate: ["/events"], fields: { Name: "name" } });
}

/** The form field a failed PutEvents entry is about. */
function entryField(code = "", message = "") {
  if (code === "NotAuthorizedForSourceException") return "source";
  if (code === "MalformedDetail") return "detail";
  if (/DetailType/.test(message)) return "detailType";
  if (/Detail/.test(message)) return "detail";
  if (/Source/.test(message)) return "source";
  return null;
}

export async function putEvent(bus: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const detail = required(form, "detail", "Detail");
    let parsed: unknown;
    try {
      parsed = JSON.parse(detail);
    } catch {
      throw new FieldError("detail", "Invalid JSON", "format");
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new FieldError("detail", "Must be a JSON object", "format");
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
    if (out.FailedEntryCount) {
      const field = entryField(entry?.ErrorCode, entry?.ErrorMessage);
      const message = entry?.ErrorCode === "NotAuthorizedForSourceException" ? "aws. is reserved" : (entry?.ErrorMessage ?? entry?.ErrorCode ?? "Rejected");
      if (field) throw new FieldError(field, message);
      return { ok: false, message: `${entry?.ErrorCode}: ${entry?.ErrorMessage}` };
    }
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

/** Which field a PutRule rejection is about: AWS names the parameter in
 * the message rather than in a constraint. */
function ruleError(e: unknown): unknown {
  if (!(e instanceof Error)) return e;
  if (e.name === "InvalidEventPatternException") return new FieldError("pattern", e.message.replace(/^Event pattern is not valid\. Reason: /, ""));
  if (/ScheduleExpression/.test(e.message)) return new FieldError("schedule", /default event bus/.test(e.message) ? "Only on the default bus" : "Like rate(5 minutes) or cron(0 12 * * ? *)", "format");
  return e;
}

export async function createRule(bus: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const client = await events();
      const name = required(form, "name", "Rule name");
      const pattern = text(form, "pattern");
      const schedule = text(form, "schedule");
      if (!pattern && !schedule) throw new FieldError("pattern", bus === "default" ? "Give a pattern or a schedule" : "Required", "required");
      await client
        .send(
          new PutRuleCommand({
            Name: name,
            EventBusName: bus,
            ...(pattern ? { EventPattern: pattern } : {}),
            ...(schedule ? { ScheduleExpression: schedule } : {}),
            State: "ENABLED",
          }),
        )
        .catch((e) => {
          throw ruleError(e);
        });
      const target = text(form, "target");
      if (target) {
        // The rule exists by now; a rejected target lands on its field, and
        // submitting again updates the same rule.
        const out = await client.send(new PutTargetsCommand({ Rule: name, EventBusName: bus, Targets: [{ Id: "target-1", Arn: target }] })).catch((e) => {
          throw new FieldError("target", e instanceof Error ? e.message : String(e));
        });
        const failed = out.FailedEntries?.[0];
        if (failed) throw new FieldError("target", failed.ErrorMessage ?? failed.ErrorCode ?? "Rejected");
      }
      return `Created ${name}`;
    },
    { revalidate: ["/events"], fields: { Name: "name", EventPattern: "pattern", ScheduleExpression: "schedule", Arn: "target" } },
  );
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
