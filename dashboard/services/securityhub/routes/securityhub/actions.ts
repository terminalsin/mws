"use server";

import {
  BatchDeleteAutomationRulesCommand,
  BatchDisableStandardsCommand,
  BatchImportFindingsCommand,
  BatchUpdateAutomationRulesCommand,
  DisableSecurityHubCommand,
  UpdateInsightCommand,
  UpdateSecurityHubConfigurationCommand,
  UpdateStandardsControlCommand,
  type AwsSecurityFinding,
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
import { act, checkFailures, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

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

export async function setWorkflow(id: string, product: string, status: WorkflowStatus) {
  return act(async () => {
    const r = await (await securityhub()).send(new BatchUpdateFindingsCommand({ FindingIdentifiers: [{ Id: id, ProductArn: product }], Workflow: { Status: status } }));
    checkFailures(r.UnprocessedFindings, (f) => `${f.FindingIdentifier?.Id}: ${f.ErrorMessage ?? f.ErrorCode}`);
    return { NEW: "Reopened", NOTIFIED: "Notified", RESOLVED: "Resolved", SUPPRESSED: "Suppressed" }[status];
  }, "/securityhub", "/securityhub/finding");
}

/** Workflow, severity and a note on one finding, as the finding page edits them. */
export async function updateFinding(id: string, product: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const status = text(form, "workflow") as WorkflowStatus | "";
    const label = text(form, "severity") as SeverityLabel | "";
    const note = text(form, "note");
    const r = await (await securityhub()).send(
      new BatchUpdateFindingsCommand({
        FindingIdentifiers: [{ Id: id, ProductArn: product }],
        ...(status ? { Workflow: { Status: status } } : {}),
        ...(label ? { Severity: { Label: label } } : {}),
        ...(note ? { Note: { Text: note, UpdatedBy: "console" } } : {}),
      }),
    );
    checkFailures(r.UnprocessedFindings, (f) => f.ErrorMessage ?? f.ErrorCode ?? "Not updated");
    return "Finding updated";
  }, { revalidate: ["/securityhub/finding", "/securityhub"], fields: { Note: "note", "Note.Text": "note" } });
}

/** Findings in ASFF, as a product (or a developer's own tool) sends them. */
export async function importFindings(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const raw = required(form, "findings", "Findings");
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      throw new FieldError("findings", `Not JSON: ${(e as Error).message}`, "format");
    }
    const Findings = (Array.isArray(parsed) ? parsed : [parsed]) as AwsSecurityFinding[];
    const r = await (await securityhub()).send(new BatchImportFindingsCommand({ Findings }));
    checkFailures(r.FailedFindings, (f) => `${f.Id}: ${f.ErrorMessage ?? f.ErrorCode}`);
    return `Imported ${r.SuccessCount ?? Findings.length} finding${Findings.length === 1 ? "" : "s"}`;
  }, { revalidate: ["/securityhub"], fields: { Findings: "findings" } });
}

export async function disableStandard(subscription: string) {
  return act(async () => {
    await (await securityhub()).send(new BatchDisableStandardsCommand({ StandardsSubscriptionArns: [subscription] }));
    return "Standard disabled";
  }, "/securityhub", "/securityhub/standard");
}

export async function setControl(controlArn: string, enable: boolean, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await securityhub()).send(
      new UpdateStandardsControlCommand({ StandardsControlArn: controlArn, ControlStatus: enable ? "ENABLED" : "DISABLED", ...(enable ? {} : { DisabledReason: text(form, "reason") || "Disabled in the console" }) }),
    );
    return enable ? "Control enabled" : "Control disabled";
  }, { revalidate: ["/securityhub/standard"], fields: { DisabledReason: "reason" } });
}

export async function updateInsight(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const label = text(form, "severity") as SeverityLabel | "";
    await (await securityhub())
      .send(
        new UpdateInsightCommand({
          InsightArn: arn,
          Name: required(form, "name", "Name"),
          GroupByAttribute: required(form, "group", "Group by"),
          Filters: { RecordState: [{ Value: "ACTIVE", Comparison: "EQUALS" }], ...(label ? { SeverityLabel: [{ Value: label, Comparison: "EQUALS" }] } : {}) },
        }),
      )
      .catch((e) => onField(e, { GroupByAttribute: "group", Name: "name" }));
    return "Insight saved";
  }, { revalidate: ["/securityhub/insight", "/securityhub"], fields: { Name: "name", GroupByAttribute: "group" } });
}

export async function setRuleStatus(arn: string, enabled: boolean) {
  return act(async () => {
    const r = await (await securityhub()).send(new BatchUpdateAutomationRulesCommand({ UpdateAutomationRulesRequestItems: [{ RuleArn: arn, RuleStatus: enabled ? "ENABLED" : "DISABLED" }] }));
    checkFailures(r.UnprocessedAutomationRules, (f) => f.ErrorMessage ?? "Rule not updated");
    return enabled ? "Rule enabled" : "Rule disabled";
  }, "/securityhub", "/securityhub/rule");
}

export async function updateAutomationRule(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const label = text(form, "severity") as SeverityLabel | "";
    const status = required(form, "status", "Set workflow to") as WorkflowStatus;
    const r = await (await securityhub())
      .send(
        new BatchUpdateAutomationRulesCommand({
          UpdateAutomationRulesRequestItems: [
            {
              RuleArn: arn,
              RuleName: required(form, "name", "Name"),
              Description: text(form, "description") || required(form, "name", "Name"),
              RuleOrder: Number(required(form, "order", "Order")),
              Criteria: label ? { SeverityLabel: [{ Value: label, Comparison: "EQUALS" }] } : {},
              Actions: [{ Type: "FINDING_FIELDS_UPDATE", FindingFieldsUpdate: { Workflow: { Status: status } } }],
            },
          ],
        }),
      )
      .catch((e) => onField(e, { RuleOrder: "order", RuleName: "name", Description: "description" }));
    checkFailures(r.UnprocessedAutomationRules, (f) => f.ErrorMessage ?? "Rule not updated");
    return "Rule saved";
  }, { revalidate: ["/securityhub/rule", "/securityhub"], fields: { RuleName: "name", RuleOrder: "order", Description: "description" } });
}

export async function updateHubSettings(_: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await securityhub()).send(
      new UpdateSecurityHubConfigurationCommand({
        AutoEnableControls: form.get("autoEnable") === "on",
        ControlFindingGenerator: (text(form, "generator") || undefined) as "STANDARD_CONTROL" | "SECURITY_CONTROL" | undefined,
      }),
    );
    return "Settings saved";
  }, "/securityhub");
}

export async function disableHub() {
  return act(async () => {
    await (await securityhub()).send(new DisableSecurityHubCommand({}));
    redirect("/securityhub");
  });
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
