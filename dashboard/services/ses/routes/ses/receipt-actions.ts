"use server";

import {
  CloneReceiptRuleSetCommand,
  CreateReceiptFilterCommand,
  CreateReceiptRuleCommand,
  CreateReceiptRuleSetCommand,
  DeleteReceiptFilterCommand,
  DeleteReceiptRuleCommand,
  DeleteReceiptRuleSetCommand,
  SetActiveReceiptRuleSetCommand,
  SetReceiptRulePositionCommand,
  UpdateReceiptRuleCommand,
  type ReceiptAction,
  type ReceiptRule,
} from "@aws-sdk/client-ses";
import { act, FieldError, mws, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { ruleSetHref, sesV1 } from "../../lib/clients";

const SET_FIELDS = { RuleSetName: "name", AlreadyExists: "name", AlreadyExistsException: "name", OriginalRuleSetName: "from" };

export async function createRuleSet(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Name");
    const from = text(form, "from");
    const client = await sesV1();
    if (from) await client.send(new CloneReceiptRuleSetCommand({ RuleSetName: name, OriginalRuleSetName: from }));
    else await client.send(new CreateReceiptRuleSetCommand({ RuleSetName: name }));
    if (form.get("activate") === "on") await client.send(new SetActiveReceiptRuleSetCommand({ RuleSetName: name }));
    redirect(ruleSetHref(name));
  }, { fields: SET_FIELDS });
}

export async function deleteRuleSet(name: string, back?: boolean) {
  return act(async () => {
    await (await sesV1()).send(new DeleteReceiptRuleSetCommand({ RuleSetName: name }));
    if (back) redirect("/ses?tab=receiving");
    return `Deleted ${name}`;
  }, "/ses");
}

/** Make a rule set the active one, or (with none) turn receiving off. */
export async function setActiveRuleSet(name: string | null) {
  return act(async () => {
    await (await sesV1()).send(new SetActiveReceiptRuleSetCommand({ RuleSetName: name ?? undefined }));
    return name ? `${name} is active` : "No active rule set";
  }, "/ses", "/ses/ruleset");
}

/** The rule's actions, in the order SES runs them here. */
function actions(form: FormData): ReceiptAction[] {
  const on = (k: string) => form.get(`do:${k}`) === "on";
  const out: ReceiptAction[] = [];
  if (on("header")) out.push({ AddHeaderAction: { HeaderName: required(form, "headerName", "Header name"), HeaderValue: required(form, "headerValue", "Header value") } });
  if (on("s3"))
    out.push({
      S3Action: { BucketName: required(form, "bucket", "S3 bucket"), ObjectKeyPrefix: text(form, "prefix") || undefined, TopicArn: text(form, "s3Topic") || undefined },
    });
  if (on("sns")) out.push({ SNSAction: { TopicArn: required(form, "topic", "SNS topic"), Encoding: (text(form, "encoding") || "UTF-8") as "UTF-8" | "Base64" } });
  if (on("lambda"))
    out.push({ LambdaAction: { FunctionArn: required(form, "function", "Lambda function"), InvocationType: (text(form, "invocation") || "Event") as "Event" | "RequestResponse" } });
  if (on("bounce"))
    out.push({
      BounceAction: {
        SmtpReplyCode: required(form, "smtpCode", "SMTP reply code"),
        StatusCode: text(form, "statusCode") || undefined,
        Message: required(form, "bounceMessage", "Message"),
        Sender: required(form, "bounceSender", "Sender"),
      },
    });
  if (on("stop")) out.push({ StopAction: { Scope: "RuleSet" } });
  if (!out.length) throw new FieldError("do:s3", "Add at least one action", "required");
  return out;
}

function rule(form: FormData): ReceiptRule {
  return {
    Name: required(form, "ruleName", "Rule name"),
    Enabled: form.get("enabled") === "on",
    ScanEnabled: form.get("scan") === "on",
    TlsPolicy: (text(form, "tls") || "Optional") as "Optional" | "Require",
    Recipients: text(form, "recipients")
      .split(/[\s,]+/)
      .filter(Boolean),
    Actions: actions(form),
  };
}

const RULE_FIELDS = {
  Name: "ruleName",
  AlreadyExists: "ruleName",
  Recipients: "recipients",
  BucketName: "bucket",
  InvalidS3Configuration: "bucket",
  TopicArn: "topic",
  InvalidSnsTopic: "topic",
  FunctionArn: "function",
  InvalidLambdaFunction: "function",
  SmtpReplyCode: "smtpCode",
  StatusCode: "statusCode",
  Sender: "bounceSender",
  HeaderName: "headerName",
  HeaderValue: "headerValue",
  After: "after",
};

export async function createRule(ruleSet: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const r = rule(form);
    await (await sesV1()).send(new CreateReceiptRuleCommand({ RuleSetName: ruleSet, Rule: r, After: text(form, "after") || undefined }));
    return `Rule ${r.Name} created`;
  }, { revalidate: ["/ses/ruleset"], fields: RULE_FIELDS });
}

export async function updateRule(ruleSet: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const r = rule(form);
    await (await sesV1()).send(new UpdateReceiptRuleCommand({ RuleSetName: ruleSet, Rule: r }));
    return `Rule ${r.Name} saved`;
  }, { revalidate: ["/ses/ruleset"], fields: RULE_FIELDS });
}

export async function deleteRule(ruleSet: string, name: string) {
  return act(async () => {
    await (await sesV1()).send(new DeleteReceiptRuleCommand({ RuleSetName: ruleSet, RuleName: name }));
    return `Deleted ${name}`;
  }, "/ses/ruleset");
}

/** Put a rule after another (or first, with none). */
export async function moveRule(ruleSet: string, name: string, after: string | null) {
  return act(async () => {
    await (await sesV1()).send(new SetReceiptRulePositionCommand({ RuleSetName: ruleSet, RuleName: name, After: after ?? undefined }));
    return `Moved ${name}`;
  }, "/ses/ruleset");
}

export async function createFilter(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "filterName", "Name");
    await (await sesV1()).send(
      new CreateReceiptFilterCommand({ Filter: { Name: name, IpFilter: { Cidr: required(form, "cidr", "IP address or range"), Policy: (text(form, "policy") || "Block") as "Block" | "Allow" } } }),
    );
    return `Filter ${name} created`;
  }, { revalidate: ["/ses"], fields: { Name: "filterName", AlreadyExists: "filterName", Cidr: "cidr", InvalidParameterValue: "cidr" } });
}

export async function deleteFilter(name: string) {
  return act(async () => {
    await (await sesV1()).send(new DeleteReceiptFilterCommand({ FilterName: name }));
    return `Deleted ${name}`;
  }, "/ses");
}

/** Deliver a message to SES receiving, as if it arrived over SMTP (MWS's
 * side channel; the SMTP listener does the same). */
export async function receiveTest(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const from = required(form, "from", "From");
    const to = required(form, "to", "To");
    const subject = text(form, "subject") || "(no subject)";
    const raw = [`From: ${from}`, `To: ${to}`, `Subject: ${subject}`, `Date: ${new Date().toUTCString()}`, "MIME-Version: 1.0", "Content-Type: text/plain; charset=UTF-8", "", text(form, "body"), ""].join("\r\n");
    const q = new URLSearchParams({ from, to });
    const out = await mws<{ messageId?: string; accepted?: string[]; rejected?: string[] }>(`/_aws/ses/inbound?${q}`, { method: "POST", body: raw });
    if (!out.accepted?.length) throw new FieldError("to", `Rejected: ${(out.rejected ?? [to]).join(", ")}`, "server");
    return `Received ${out.messageId} for ${out.accepted.join(", ")}`;
  }, { revalidate: ["/ses"] });
}
