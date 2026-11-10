import { Field } from "@mws-dashboard/ui";
import { CreateAssociation } from "@mws-dashboard/ui/model/ssm";

export interface AssociationDefaults {
  document?: string;
  name?: string;
  targets?: string;
  schedule?: string;
  parameters?: string;
  maxConcurrency?: string;
  maxErrors?: string;
  severity?: string;
}

/** The fields CreateAssociation and UpdateAssociation share. */
export function AssociationFields({ documents, defaults = {}, fixedDocument }: { documents: string[]; defaults?: AssociationDefaults; fixedDocument?: boolean }) {
  return (
    <>
      {!fixedDocument && (
        <Field label="Document" rule={CreateAssociation.Name} known={documents}>
          <input name="document" required defaultValue={defaults.document ?? "AWS-RunShellScript"} list="ssm-documents" />
        </Field>
      )}
      <Field label="Association name" rule={CreateAssociation.AssociationName} unique>
        <input name="name" defaultValue={defaults.name} />
      </Field>
      <Field label="Targets" hint="InstanceIds=i-1,i-2 · tag:env=prod · InstanceIds=* (one a line)" member="Targets">
        <textarea name="targets" rows={2} required defaultValue={defaults.targets ?? "InstanceIds=*"} />
      </Field>
      <Field label="Schedule" rule={{ ...CreateAssociation.ScheduleExpression, hint: "rate(30 minutes) or cron(0 2 ? * SUN *)" }}>
        <input name="schedule" defaultValue={defaults.schedule} placeholder="rate(30 minutes)" />
      </Field>
      <Field label="Parameters" hint="name=value, one a line; indented lines continue a list (commands)" member="Parameters">
        <textarea name="parameters" rows={4} className="code-editor" spellCheck={false} defaultValue={defaults.parameters} placeholder={"commands=echo hello\n  uptime"} />
      </Field>
      <div className="form-row">
        <Field label="Concurrency" rule={CreateAssociation.MaxConcurrency}>
          <input name="maxConcurrency" defaultValue={defaults.maxConcurrency} placeholder="50" />
        </Field>
        <Field label="Error threshold" rule={CreateAssociation.MaxErrors}>
          <input name="maxErrors" defaultValue={defaults.maxErrors} placeholder="0" />
        </Field>
        <Field label="Compliance severity" rule={CreateAssociation.ComplianceSeverity}>
          <select name="severity" defaultValue={defaults.severity ?? ""}>
            <option value="">Unspecified</option>
            {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </Field>
      </div>
      {!fixedDocument && (
        <label className="check">
          <input type="checkbox" name="cronOnly" /> Apply only at the next scheduled time
        </label>
      )}
      <datalist id="ssm-documents">
        {documents.map((d) => (
          <option key={d} value={d} />
        ))}
      </datalist>
    </>
  );
}
