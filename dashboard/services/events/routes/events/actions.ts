"use server";

import {
  CancelReplayCommand,
  CreateApiDestinationCommand,
  CreateArchiveCommand,
  CreateConnectionCommand,
  CreateEventBusCommand,
  DeauthorizeConnectionCommand,
  DeleteApiDestinationCommand,
  DeleteArchiveCommand,
  DeleteConnectionCommand,
  DeleteEventBusCommand,
  DeleteRuleCommand,
  DescribeEventBusCommand,
  DescribeRuleCommand,
  DisableRuleCommand,
  EnableRuleCommand,
  ListRulesCommand,
  ListTargetsByRuleCommand,
  PutEventsCommand,
  PutPermissionCommand,
  PutRuleCommand,
  PutTargetsCommand,
  RemovePermissionCommand,
  RemoveTargetsCommand,
  StartReplayCommand,
  TestEventPatternCommand,
  UpdateApiDestinationCommand,
  UpdateArchiveCommand,
  UpdateEventBusCommand,
  type ApiDestinationHttpMethod,
  type ConnectionAuthorizationType,
  type CreateConnectionAuthRequestParameters,
  type RuleState,
  type Target,
} from "@aws-sdk/client-eventbridge";
import { act, all, checkFailures, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { events } from "../../lib/clients";
import { grantTarget } from "../../lib/grant";

function json(form: FormData, field: string, label = "JSON"): string {
  const value = text(form, field);
  if (!value) return "";
  try {
    JSON.parse(value);
  } catch {
    throw new FieldError(field, `Invalid ${label}`, "format");
  }
  return value;
}

export async function createBus(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const description = text(form, "description");
    const out = await (await events()).send(new CreateEventBusCommand({ Name: required(form, "name", "Bus name"), ...(description ? { Description: description } : {}) }));
    return `Created ${out.EventBusArn}`;
  }, { revalidate: ["/events"], fields: { Name: "name", Description: "description" } });
}

export async function updateBus(bus: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await events();
    const dlq = text(form, "dlq");
    await client.send(new UpdateEventBusCommand({ Name: bus, Description: text(form, "description"), DeadLetterConfig: dlq ? { Arn: dlq } : {} }));
    const policy = json(form, "policy", "policy");
    const had = text(form, "hadPolicy") === "1";
    if (policy) await client.send(new PutPermissionCommand({ EventBusName: bus, Policy: policy }));
    else if (had) await client.send(new RemovePermissionCommand({ EventBusName: bus, RemoveAllPermissions: true }));
    return "Saved";
  }, { revalidate: ["/events"], fields: { Description: "description", "DeadLetterConfig.Arn": "dlq", Policy: "policy", PolicyLengthExceededException: "policy" } });
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

/** Put one event on the bus, and say which of its rules it matched. */
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
    const client = await events();
    const source = required(form, "source", "Source");
    const detailType = required(form, "detailType", "Detail type");
    const out = await client.send(new PutEventsCommand({ Entries: [{ EventBusName: bus, Source: source, DetailType: detailType, Detail: detail }] }));
    const entry = out.Entries?.[0];
    if (out.FailedEntryCount) {
      const field = entryField(entry?.ErrorCode, entry?.ErrorMessage);
      const message = entry?.ErrorCode === "NotAuthorizedForSourceException" ? "aws. is reserved" : (entry?.ErrorMessage ?? entry?.ErrorCode ?? "Rejected");
      if (field) throw new FieldError(field, message);
      return { ok: false, message: `${entry?.ErrorCode}: ${entry?.ErrorMessage}` };
    }
    // Which rules it matched: the same event, tested against each pattern.
    const busArn = (await client.send(new DescribeEventBusCommand({ Name: bus }))).Arn ?? "";
    const [, , , region, account] = busArn.split(":");
    const event = JSON.stringify({ version: "0", id: entry?.EventId, "detail-type": detailType, source, account, time: new Date().toISOString(), region, resources: [], detail: parsed });
    const rules = await all((NextToken) => client.send(new ListRulesCommand({ EventBusName: bus, NextToken })), (r) => r.Rules, (r) => r.NextToken);
    const matched = (
      await Promise.all(
        rules
          .filter((r) => r.EventPattern && r.State !== "DISABLED")
          .map((r) => client.send(new TestEventPatternCommand({ EventPattern: r.EventPattern, Event: event })).then((t) => (t.Result ? r.Name! : null), () => null)),
      )
    ).filter((n): n is string => !!n);
    return { ok: true, message: `Put event ${entry?.EventId}`, detail: matched.length ? `Matched ${matched.join(", ")}` : "Matched no rules" };
  }, "/events");
}

export async function testPattern(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const EventPattern = json(form, "pattern", "pattern") || required(form, "pattern", "Pattern");
    const Event = json(form, "event", "event") || required(form, "event", "Event");
    const out = await (await events()).send(new TestEventPatternCommand({ EventPattern, Event })).catch((e) => {
      if (e instanceof Error && e.name === "InvalidEventPatternException") throw new FieldError("pattern", e.message.replace(/^Event pattern is not valid\. Reason: /, ""));
      if (e instanceof Error && /event/i.test(e.message)) throw new FieldError("event", e.message);
      throw e;
    });
    // A detail keeps the sheet open, so the next try starts from this one.
    return out.Result ? { ok: true, message: "The event matches the pattern", detail: "Result: true" } : { ok: false, message: "The event does not match the pattern" };
  }, { fields: { EventPattern: "pattern", Event: "event" } });
}

export async function setRuleState(bus: string, rule: string, enable: boolean) {
  return act(async () => {
    const client = await events();
    await client.send(enable ? new EnableRuleCommand({ Name: rule, EventBusName: bus }) : new DisableRuleCommand({ Name: rule, EventBusName: bus }));
    return enable ? "Enabled" : "Disabled";
  }, "/events", "/events/rule");
}

/** Which field a PutRule rejection is about: AWS names the parameter in
 * the message rather than in a constraint. */
function ruleError(e: unknown): unknown {
  if (!(e instanceof Error)) return e;
  if (e.name === "InvalidEventPatternException") return new FieldError("pattern", e.message.replace(/^Event pattern is not valid\. Reason: /, ""));
  if (/ScheduleExpression/.test(e.message)) return new FieldError("schedule", /default event bus/.test(e.message) ? "Only on the default bus" : "Like rate(5 minutes) or cron(0 12 * * ? *)", "format");
  return e;
}

const RULE_FIELDS = { Name: "name", EventPattern: "pattern", ScheduleExpression: "schedule", Description: "description", Arn: "target", RoleArn: "role" };

/** Put one target on a rule, granting it access first when asked. */
async function putTarget(bus: string, rule: string, target: Target, grant: boolean) {
  const client = await events();
  let granted: string | null = null;
  if (grant) {
    const ruleArn = (await client.send(new DescribeRuleCommand({ Name: rule, EventBusName: bus }))).Arn!;
    granted = await grantTarget(ruleArn, rule, target.Id!, target.Arn!).catch((e) => {
      throw new FieldError("target", `Couldn't grant access: ${e instanceof Error ? e.message : String(e)}`);
    });
  }
  const out = await client.send(new PutTargetsCommand({ Rule: rule, EventBusName: bus, Targets: [target] })).catch((e) => {
    throw new FieldError("target", e instanceof Error ? e.message : String(e));
  });
  const failed = out.FailedEntries?.[0];
  if (failed) throw new FieldError("target", failed.ErrorMessage ?? failed.ErrorCode ?? "Rejected");
  return granted;
}

export async function createRule(bus: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await events();
    const name = required(form, "name", "Rule name");
    const pattern = text(form, "pattern");
    const schedule = text(form, "schedule");
    const description = text(form, "description");
    if (!pattern && !schedule) throw new FieldError("pattern", bus === "default" ? "Give a pattern or a schedule" : "Required", "required");
    await client
      .send(
        new PutRuleCommand({
          Name: name,
          EventBusName: bus,
          ...(pattern ? { EventPattern: pattern } : {}),
          ...(schedule ? { ScheduleExpression: schedule } : {}),
          ...(description ? { Description: description } : {}),
          State: "ENABLED",
        }),
      )
      .catch((e) => {
        throw ruleError(e);
      });
    const target = text(form, "target");
    let granted: string | null = null;
    if (target) {
      // The rule exists by now; a rejected target lands on its field, and
      // submitting again updates the same rule.
      const role = text(form, "role");
      granted = await putTarget(bus, name, { Id: "target-1", Arn: target, ...(role ? { RoleArn: role } : {}) }, text(form, "grant") === "on");
    }
    return `Created ${name}${granted ? ` (and allowed it in the ${granted})` : ""}`;
  }, { revalidate: ["/events"], fields: RULE_FIELDS });
}

export async function updateRule(bus: string, name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await events();
    const current = await client.send(new DescribeRuleCommand({ Name: name, EventBusName: bus }));
    const pattern = text(form, "pattern");
    const schedule = text(form, "schedule");
    if (!pattern && !schedule) throw new FieldError("pattern", "Give a pattern or a schedule", "required");
    const role = text(form, "role");
    // PutRule replaces the rule: whatever it leaves out is cleared.
    await client
      .send(
        new PutRuleCommand({
          Name: name,
          EventBusName: bus,
          ...(pattern ? { EventPattern: pattern } : {}),
          ...(schedule ? { ScheduleExpression: schedule } : {}),
          Description: text(form, "description"),
          ...(role ? { RoleArn: role } : {}),
          State: (current.State ?? "ENABLED") as RuleState,
        }),
      )
      .catch((e) => {
        throw ruleError(e);
      });
    return "Saved";
  }, { revalidate: ["/events/rule", "/events"], fields: RULE_FIELDS });
}

/** A target from its form: input shaping, retries, dead-letter queue and
 * the parameters some targets take. */
function targetFrom(form: FormData): Target {
  const Arn = required(form, "target", "Target");
  const Id = required(form, "id", "Target ID");
  const input = text(form, "input");
  const target: Target = { Id, Arn };
  if (input === "constant") target.Input = json(form, "inputValue", "JSON") || required(form, "inputValue", "Input");
  if (input === "path") target.InputPath = required(form, "inputPath", "Input path");
  if (input === "transformer") {
    const map = json(form, "inputPaths", "JSON");
    target.InputTransformer = { InputPathsMap: map ? JSON.parse(map) : undefined, InputTemplate: required(form, "inputTemplate", "Template") };
  }
  const attempts = text(form, "retries");
  const age = text(form, "age");
  if (attempts || age) target.RetryPolicy = { ...(attempts ? { MaximumRetryAttempts: Number(attempts) } : {}), ...(age ? { MaximumEventAgeInSeconds: Number(age) } : {}) };
  const dlq = text(form, "dlq");
  if (dlq) target.DeadLetterConfig = { Arn: dlq };
  const role = text(form, "role");
  if (role) target.RoleArn = role;
  const group = text(form, "group");
  if (group) target.SqsParameters = { MessageGroupId: group };
  const partition = text(form, "partitionKey");
  if (partition) target.KinesisParameters = { PartitionKeyPath: partition };
  return target;
}

const TARGET_FIELDS = {
  Arn: "target",
  Id: "id",
  Input: "inputValue",
  InputPath: "inputPath",
  "InputTransformer.InputTemplate": "inputTemplate",
  "InputTransformer.InputPathsMap": "inputPaths",
  "RetryPolicy.MaximumRetryAttempts": "retries",
  "RetryPolicy.MaximumEventAgeInSeconds": "age",
  "DeadLetterConfig.Arn": "dlq",
  RoleArn: "role",
  "SqsParameters.MessageGroupId": "group",
};

export async function saveTarget(bus: string, rule: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const granted = await putTarget(bus, rule, targetFrom(form), text(form, "grant") === "on");
    return `Saved${granted ? ` (and allowed the rule in the ${granted})` : ""}`;
  }, { revalidate: ["/events/rule", "/events"], fields: TARGET_FIELDS });
}

export async function removeTarget(bus: string, rule: string, id: string) {
  return act(async () => {
    const out = await (await events()).send(new RemoveTargetsCommand({ Rule: rule, EventBusName: bus, Ids: [id] }));
    checkFailures(out.FailedEntries, (f) => `${f.TargetId}: ${f.ErrorMessage ?? f.ErrorCode}`);
    return "Target removed";
  }, "/events/rule", "/events");
}

export async function deleteRule(bus: string, rule: string, back?: boolean) {
  return act(async () => {
    const client = await events();
    const targets = await all((NextToken) => client.send(new ListTargetsByRuleCommand({ Rule: rule, EventBusName: bus, NextToken })), (r) => r.Targets, (r) => r.NextToken);
    if (targets.length) {
      const out = await client.send(new RemoveTargetsCommand({ Rule: rule, EventBusName: bus, Ids: targets.map((t) => t.Id!) }));
      checkFailures(out.FailedEntries, (f) => `${f.TargetId}: ${f.ErrorMessage ?? f.ErrorCode}`);
    }
    await client.send(new DeleteRuleCommand({ Name: rule, EventBusName: bus }));
    if (back) redirect(bus === "default" ? "/events" : `/events?bus=${encodeURIComponent(bus)}`);
    return `Deleted ${rule}`;
  }, "/events");
}

export async function deleteBus(bus: string) {
  return act(async () => {
    await (await events()).send(new DeleteEventBusCommand({ Name: bus }));
    redirect("/events");
  });
}

// Archives and replays ------------------------------------------------------

const ARCHIVE_FIELDS = { ArchiveName: "name", EventSourceArn: "source", Description: "description", EventPattern: "pattern", RetentionDays: "retention", ResourceAlreadyExistsException: "name" };

export async function createArchive(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const pattern = json(form, "pattern", "pattern");
    const retention = text(form, "retention");
    const description = text(form, "description");
    await (await events())
      .send(
        new CreateArchiveCommand({
          ArchiveName: required(form, "name", "Archive name"),
          EventSourceArn: required(form, "source", "Source bus"),
          ...(description ? { Description: description } : {}),
          ...(pattern ? { EventPattern: pattern } : {}),
          ...(retention ? { RetentionDays: Number(retention) } : {}),
        }),
      )
      .catch((e) => {
        if (e instanceof Error && e.name === "InvalidEventPatternException") throw new FieldError("pattern", e.message.replace(/^Event pattern is not valid\. Reason: /, ""));
        throw e;
      });
    return "Archive created";
  }, { revalidate: ["/events/archives"], fields: ARCHIVE_FIELDS });
}

export async function updateArchive(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const pattern = json(form, "pattern", "pattern");
    const retention = text(form, "retention");
    await (await events()).send(
      new UpdateArchiveCommand({ ArchiveName: name, Description: text(form, "description"), EventPattern: pattern, RetentionDays: retention ? Number(retention) : 0 }),
    );
    return "Saved";
  }, { revalidate: ["/events/archives"], fields: ARCHIVE_FIELDS });
}

export async function deleteArchive(name: string) {
  return act(async () => {
    await (await events()).send(new DeleteArchiveCommand({ ArchiveName: name }));
    return "Archive deleted";
  }, "/events/archives");
}

function time(form: FormData, field: string, label: string) {
  const v = required(form, field, label);
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) throw new FieldError(field, "Not a date and time", "format");
  return d;
}

export async function startReplay(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const start = time(form, "start", "Start");
    const end = time(form, "end", "End");
    if (end <= start) throw new FieldError("end", "Must be after the start", "range");
    const filters = form.getAll("rules").filter((v): v is string => typeof v === "string" && !!v);
    const description = text(form, "description");
    await (await events()).send(
      new StartReplayCommand({
        ReplayName: required(form, "name", "Replay name"),
        EventSourceArn: required(form, "archive", "Archive"),
        EventStartTime: start,
        EventEndTime: end,
        ...(description ? { Description: description } : {}),
        Destination: { Arn: required(form, "destination", "Destination bus"), ...(filters.length ? { FilterArns: filters } : {}) },
      }),
    );
    redirect("/events/replays");
  }, { fields: { ReplayName: "name", EventSourceArn: "archive", EventStartTime: "start", EventEndTime: "end", "Destination.Arn": "destination", ResourceAlreadyExistsException: "name" } });
}

export async function cancelReplay(name: string) {
  return act(async () => {
    const out = await (await events()).send(new CancelReplayCommand({ ReplayName: name }));
    return `Replay ${out.State?.toLowerCase() ?? "cancelling"}`;
  }, "/events/replays");
}

// Connections and API destinations ------------------------------------------

function authParameters(type: string, form: FormData): CreateConnectionAuthRequestParameters {
  if (type === "API_KEY") return { ApiKeyAuthParameters: { ApiKeyName: required(form, "keyName", "API key name"), ApiKeyValue: required(form, "keyValue", "Value") } };
  if (type === "BASIC") return { BasicAuthParameters: { Username: required(form, "username", "Username"), Password: required(form, "password", "Password") } };
  return {
    OAuthParameters: {
      AuthorizationEndpoint: required(form, "authEndpoint", "Authorization endpoint"),
      HttpMethod: (text(form, "authMethod") || "POST") as "POST" | "GET" | "PUT",
      ClientParameters: { ClientID: required(form, "clientId", "Client ID"), ClientSecret: required(form, "clientSecret", "Client secret") },
    },
  };
}

const CONNECTION_FIELDS = {
  Name: "name",
  Description: "description",
  "AuthParameters.ApiKeyAuthParameters.ApiKeyName": "keyName",
  "AuthParameters.ApiKeyAuthParameters.ApiKeyValue": "keyValue",
  "AuthParameters.BasicAuthParameters.Username": "username",
  "AuthParameters.BasicAuthParameters.Password": "password",
  "AuthParameters.OAuthParameters.AuthorizationEndpoint": "authEndpoint",
  "AuthParameters.OAuthParameters.ClientParameters.ClientID": "clientId",
  ResourceAlreadyExistsException: "name",
};

export async function createConnection(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const type = required(form, "auth", "Authorization type") as ConnectionAuthorizationType;
    const description = text(form, "description");
    await (await events()).send(
      new CreateConnectionCommand({ Name: required(form, "name", "Connection name"), AuthorizationType: type, AuthParameters: authParameters(type, form), ...(description ? { Description: description } : {}) }),
    );
    return "Connection created";
  }, { revalidate: ["/events/connections"], fields: CONNECTION_FIELDS });
}

export async function deauthorizeConnection(name: string) {
  return act(async () => {
    const out = await (await events()).send(new DeauthorizeConnectionCommand({ Name: name }));
    return `Connection ${out.ConnectionState?.toLowerCase() ?? "deauthorized"}`;
  }, "/events/connections");
}

export async function deleteConnection(name: string) {
  return act(async () => {
    await (await events()).send(new DeleteConnectionCommand({ Name: name }));
    return "Connection deleted";
  }, "/events/connections");
}

const DESTINATION_FIELDS = { Name: "name", ConnectionArn: "connection", InvocationEndpoint: "endpoint", HttpMethod: "method", InvocationRateLimitPerSecond: "rate", Description: "description", ResourceAlreadyExistsException: "name" };

export async function saveApiDestination(existing: string | null, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const rate = text(form, "rate");
    const fields = {
      ConnectionArn: required(form, "connection", "Connection"),
      InvocationEndpoint: required(form, "endpoint", "Endpoint"),
      HttpMethod: required(form, "method", "Method") as ApiDestinationHttpMethod,
      ...(text(form, "description") ? { Description: text(form, "description") } : {}),
      ...(rate ? { InvocationRateLimitPerSecond: Number(rate) } : {}),
    };
    const client = await events();
    if (existing) await client.send(new UpdateApiDestinationCommand({ Name: existing, ...fields }));
    else await client.send(new CreateApiDestinationCommand({ Name: required(form, "name", "Name"), ...fields }));
    return existing ? "Saved" : "API destination created";
  }, { revalidate: ["/events/api-destinations"], fields: DESTINATION_FIELDS });
}

export async function deleteApiDestination(name: string) {
  return act(async () => {
    await (await events()).send(new DeleteApiDestinationCommand({ Name: name }));
    return "API destination deleted";
  }, "/events/api-destinations");
}
