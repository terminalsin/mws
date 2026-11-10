import { ActionForm, Field, Sheet, type Rule } from "@mws-dashboard/ui";
import { CreateActionTarget, CreateAutomationRule, CreateInsight } from "@mws-dashboard/ui/model/securityhub";

import { createActionTarget, createAutomationRule, createInsight } from "./actions";

/** The finding attributes an insight can group by (the ASFF filter names). */
export const GROUP_BY = [
  "ResourceId", "ResourceType", "ResourceRegion", "ResourceTags", "ResourceAwsIamUserUserName", "ResourceContainerImageName",
  "AwsAccountId", "AwsAccountName", "Region", "ProductArn", "ProductName", "CompanyName", "GeneratorId", "Type", "Title",
  "SeverityLabel", "Criticality", "Confidence", "ComplianceStatus", "ComplianceSecurityControlId", "ComplianceAssociatedStandardsId",
  "WorkflowStatus", "RecordState", "VerificationState", "MalwareName", "MalwareType", "NetworkSourceIpV4", "NetworkDestinationDomain",
  "ProcessName", "ThreatIntelIndicatorType", "NoteUpdatedBy", "VulnerabilitiesExploitAvailable", "VulnerabilitiesFixAvailable",
];

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"] as const;
const label = (s: string) => s[0] + s.slice(1).toLowerCase();

function Severity({ any }: { any: string }) {
  return (
    <Field label="Severity">
      <select name="severity" defaultValue="">
        <option value="">{any}</option>
        {SEVERITIES.map((s) => (
          <option key={s} value={s}>
            {label(s)}
          </option>
        ))}
      </select>
    </Field>
  );
}

// The model leaves names unconstrained; these limits are AWS's documented ones.
const INSIGHT_NAME: Rule = { ...CreateInsight.Name, maxLength: 128 };
const GROUP: Rule = { ...CreateInsight.GroupByAttribute, enum: GROUP_BY, hint: "A finding attribute, e.g. ResourceId" };

export function NewInsight({ names }: { names: string[] }) {
  return (
    <Sheet title="New insight" label="Create insight" testId="create-insight">
      <ActionForm action={createInsight} submit="Create" testId="create-insight">
        <Field label="Name" rule={INSIGHT_NAME} taken={names} unique>
          <input name="name" required autoFocus />
        </Field>
        <div className="form-row">
          <Field label="Group by" rule={GROUP}>
            <input name="group" required defaultValue="ResourceId" spellCheck={false} />
          </Field>
          <Severity any="Any severity" />
        </div>
      </ActionForm>
    </Sheet>
  );
}

const RULE_NAME: Rule = { ...CreateAutomationRule.RuleName, maxLength: 256 };
const RULE_DESCRIPTION: Rule = { ...CreateAutomationRule.Description, required: false, maxLength: 1024 };

export function NewAutomationRule({ next, names }: { next: number; names: string[] }) {
  return (
    <Sheet title="New automation rule" label="Create automation rule" testId="create-rule">
      <ActionForm action={createAutomationRule} submit="Create" testId="create-rule">
        <Field label="Name" rule={RULE_NAME} taken={names}>
          <input name="name" required autoFocus />
        </Field>
        <Field label="Description" rule={RULE_DESCRIPTION}>
          <input name="description" />
        </Field>
        <div className="form-row">
          <Severity any="Every finding" />
          <Field label="Set workflow to">
            <select name="status" defaultValue="SUPPRESSED">
              {["NEW", "NOTIFIED", "RESOLVED", "SUPPRESSED"].map((s) => (
                <option key={s} value={s}>
                  {label(s)}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Order" rule={CreateAutomationRule.RuleOrder}>
            <input name="order" type="number" required defaultValue={String(Math.min(next, 1000))} />
          </Field>
        </div>
      </ActionForm>
    </Sheet>
  );
}

const ACTION_NAME: Rule = { ...CreateActionTarget.Name, maxLength: 20 };
const ACTION_ID: Rule = { ...CreateActionTarget.Id, pattern: "^[A-Za-z0-9]{1,20}$", maxLength: 20, hint: "Up to 20 letters and digits", generate: { kind: "token" } };
const ACTION_DESCRIPTION: Rule = { ...CreateActionTarget.Description, required: false, maxLength: 256 };

export function NewActionTarget({ ids }: { ids: string[] }) {
  return (
    <Sheet title="New custom action" label="Create custom action" testId="create-action">
      <ActionForm action={createActionTarget} submit="Create" testId="create-action">
        <div className="form-row">
          <Field label="Name" rule={ACTION_NAME}>
            <input name="name" required autoFocus />
          </Field>
          <Field label="Id" rule={ACTION_ID} taken={ids} unique>
            <input name="id" required spellCheck={false} />
          </Field>
        </div>
        <Field label="Description" rule={ACTION_DESCRIPTION}>
          <input name="description" />
        </Field>
      </ActionForm>
    </Sheet>
  );
}
