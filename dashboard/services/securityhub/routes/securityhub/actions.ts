"use server";

import {
  BatchDeleteAutomationRulesCommand,
  BatchEnableStandardsCommand,
  BatchUpdateFindingsCommand,
  CreateActionTargetCommand,
  CreateAutomationRuleCommand,
  CreateInsightCommand,
  DeleteActionTargetCommand,
  DeleteInsightCommand,
  EnableSecurityHubCommand,
  type SeverityLabel,
  type WorkflowStatus,
} from "@aws-sdk/client-securityhub";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";

import { securityhub } from "../../lib/clients";

export async function enableHub() {
  return act(async () => {
    await (await securityhub()).send(new EnableSecurityHubCommand({ EnableDefaultStandards: true }));
    return "Security Hub enabled";
  }, "/securityhub");
}

export async function enableStandard(arn: string) {
  return act(async () => {
    await (await securityhub()).send(new BatchEnableStandardsCommand({ StandardsSubscriptionRequests: [{ StandardsArn: arn }] }));
    return "Standard enabled";
  }, "/securityhub");
}

export async function setWorkflow(id: string, product: string, status: "RESOLVED" | "SUPPRESSED" | "NOTIFIED") {
  return act(async () => {
    await (await securityhub()).send(new BatchUpdateFindingsCommand({ FindingIdentifiers: [{ Id: id, ProductArn: product }], Workflow: { Status: status } }));
    return status === "RESOLVED" ? "Resolved" : status === "SUPPRESSED" ? "Suppressed" : "Notified";
  }, "/securityhub");
}

/** Security Hub answers InvalidInputException for every input it rejects,
 * naming the member in the message: land it on that member's field. */
function onField(e: unknown, members: Record<string, string>): never {
  if (e instanceof Error && e.name === "InvalidInputException") {
    const member = Object.keys(members).find((m) => new RegExp(`\\b${m}\\b`).test(e.message));
    if (member) throw new FieldError(members[member], e.message.replace(/\.$/, ""));
  }
  throw e;
}

export async function createInsight(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Name");
    const group = required(form, "group", "Group by");
    const label = text(form, "severity") as SeverityLabel | "";
    await (await securityhub())
      .send(
        new CreateInsightCommand({
          Name: name,
          GroupByAttribute: group,
          Filters: {
            RecordState: [{ Value: "ACTIVE", Comparison: "EQUALS" }],
            ...(label ? { SeverityLabel: [{ Value: label, Comparison: "EQUALS" }] } : {}),
          },
        }),
      )
      .catch((e) => onField(e, { GroupByAttribute: "group", Name: "name" }));
    return `Created insight ${name}`;
  }, { revalidate: ["/securityhub"], fields: { Name: "name", GroupByAttribute: "group" } });
}

export async function deleteInsight(arn: string) {
  return act(async () => {
    await (await securityhub()).send(new DeleteInsightCommand({ InsightArn: arn }));
    return "Insight deleted";
  }, "/securityhub");
}

export async function createAutomationRule(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Name");
    const order = Number(required(form, "order", "Order"));
    const label = text(form, "severity") as SeverityLabel | "";
    const status = required(form, "status", "Set workflow to") as WorkflowStatus;
    await (await securityhub())
      .send(
        new CreateAutomationRuleCommand({
          RuleName: name,
          Description: text(form, "description") || name,
          RuleOrder: order,
          RuleStatus: "ENABLED",
          Criteria: label ? { SeverityLabel: [{ Value: label, Comparison: "EQUALS" }] } : {},
          Actions: [{ Type: "FINDING_FIELDS_UPDATE", FindingFieldsUpdate: { Workflow: { Status: status } } }],
        }),
      )
      .catch((e) => onField(e, { RuleOrder: "order", RuleName: "name", Description: "description" }));
    return `Created rule ${name}`;
  }, { revalidate: ["/securityhub"], fields: { RuleName: "name", RuleOrder: "order", Description: "description" } });
}

export async function deleteAutomationRule(arn: string) {
  return act(async () => {
    const out = await (await securityhub()).send(new BatchDeleteAutomationRulesCommand({ AutomationRulesArns: [arn] }));
    const failed = out.UnprocessedAutomationRules?.[0];
    if (failed) throw new Error(failed.ErrorMessage ?? "Rule not deleted");
    return "Rule deleted";
  }, "/securityhub");
}

export async function createActionTarget(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Name");
    const id = required(form, "id", "Id");
    await (await securityhub())
      .send(new CreateActionTargetCommand({ Name: name, Id: id, Description: text(form, "description") || name }))
      .catch((e) => onField(e, { Id: "id", Name: "name", Description: "description" }));
    return `Created custom action ${name}`;
  }, { revalidate: ["/securityhub"], fields: { Name: "name", Id: "id", Description: "description", ResourceConflictException: "id" } });
}

export async function deleteActionTarget(arn: string) {
  return act(async () => {
    await (await securityhub()).send(new DeleteActionTargetCommand({ ActionTargetArn: arn }));
    return "Custom action deleted";
  }, "/securityhub");
}
