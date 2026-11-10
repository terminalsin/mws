"use client";

import { ActionForm, AutoPick, Field } from "@mws-dashboard/ui";
import { CreateJob } from "@mws-dashboard/ui/model/s3control";
import { MoreFields, PresetGallery } from "@mws-dashboard/ui/presets";
import { ruleAt } from "@mws-dashboard/ui/validation";
import { Copy, Eraser, Snowflake, Tag } from "lucide-react";
import { useState } from "react";

import { createJob } from "./control-actions";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";

const ICON = { size: 26, strokeWidth: 1.5, "aria-hidden": true } as const;

const OPERATIONS = [
  { id: "tag", label: "Tag", title: "Replace all object tags", icon: <Tag {...ICON} /> },
  { id: "untag", label: "Untag", title: "Delete all object tags", icon: <Eraser {...ICON} /> },
  { id: "copy", label: "Copy", title: "Copy every object to another bucket", icon: <Copy {...ICON} /> },
  { id: "lambda", label: "Lambda", title: "Invoke a Lambda function per object", icon: "service/AWSLambda" },
  { id: "restore", label: "Restore", title: "Restore archived objects for a day", icon: <Snowflake {...ICON} /> },
];

/** The batch job form: it opens on the operation, and asks only what that
 * operation needs. */
export function JobForm({ buckets, roles, roleName }: { buckets: string[]; roles: { value: string; label: string }[]; roleName: string }) {
  const [op, setOp] = useState(OPERATIONS[0]);
  const bucketOptions = buckets.map((b) => <option key={b}>{b}</option>);
  return (
    <ActionForm action={createJob} submit="Create job" testId="create-job">
      <PresetGallery presets={OPERATIONS} chosen={op.id} choose={setOp} label="Operation" testId="operation" />
      <input type="hidden" name="operation" value={op.id} />
      <div className="form-row">
        <Field label="Source bucket" hint="Every object (S3-generated manifest)">
          <select name="source" required>
            {bucketOptions}
          </select>
        </Field>
        <Field label="Key prefix">
          <input name="prefix" placeholder="logs/" />
        </Field>
      </div>
      {op.id === "tag" && (
        <Field label="Tags" format="tags">
          <textarea name="tags" rows={2} placeholder="processed=true" required />
        </Field>
      )}
      {op.id === "copy" && (
        <div className="form-row">
          <Field label="Copy to bucket">
            <select name="target" required defaultValue={buckets[1] ?? ""}>
              {bucketOptions}
            </select>
          </Field>
          <Field label="Copy key prefix">
            <input name="targetPrefix" />
          </Field>
        </div>
      )}
      {op.id === "lambda" && (
        <Field label="Lambda function ARN" rule={ruleAt(CreateJob, "Operation.LambdaInvoke.FunctionArn")}>
          <ResourcePicker kind="lambda-function" name="function" required />
        </Field>
      )}
      <AutoPick name="role" label="IAM role" creates={roleName} options={roles} testId="job-role" />
      <MoreFields>
        <div className="form-row">
          <Field label="Priority" rule={{ ...ruleAt(CreateJob, "Priority"), type: "integer", min: 0 }}>
            <input name="priority" type="number" min={0} defaultValue={10} />
          </Field>
          <Field label="Completion report bucket">
            <select name="report" defaultValue="">
              <option value="">No report</option>
              {bucketOptions}
            </select>
          </Field>
        </div>
        <Field label="Description" rule={ruleAt(CreateJob, "Description")}>
          <input name="description" />
        </Field>
        <label className="check">
          <input type="checkbox" name="confirm" /> Wait for confirmation before running
        </label>
      </MoreFields>
    </ActionForm>
  );
}
