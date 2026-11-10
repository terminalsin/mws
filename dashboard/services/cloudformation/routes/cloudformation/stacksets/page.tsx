import { ListStackSetsCommand } from "@aws-sdk/client-cloudformation";
import { all, load, region } from "@mws-dashboard/aws";
import { roleOptions } from "@mws-dashboard/aws/auto";
import { ActionForm, AutoPick, Empty, ErrorNotice, Field, List, Page, Pill, Sheet, Status } from "@mws-dashboard/ui";
import { CreateStackInstances as InstanceRules, CreateStackSet as Rules } from "@mws-dashboard/ui/model/cloudformation";
import { Boxes } from "lucide-react";
import type { Metadata } from "next";

import { PARAMETERS, SAMPLE_TEMPLATE, STACK_NAME, TEMPLATE, word } from "../../../lib/cloudformation";
import { ICONS, cloudformation, stackTone } from "../../../lib/clients";
import { CloudFormationNav } from "../../../lib/nav";
import { ADMIN_ROLE, EXECUTION_ROLE } from "../../../lib/stacksets";
import { Capabilities } from "../forms";
import { createStackSet } from "./actions";

export const metadata: Metadata = { title: "StackSets" };

function CreateStackSet({ names, roles, here }: { names: string[]; roles: { value: string; label: string }[]; here: string }) {
  return (
    <Sheet title="Create StackSet" label="Create StackSet" testId="create-stack-set">
      <ActionForm action={createStackSet} submit="Create StackSet" testId="create-stack-set">
        <Field label="StackSet name" rule={{ ...Rules.StackSetName, ...STACK_NAME }} taken={names} unique>
          <input name="name" required maxLength={128} />
        </Field>
        <Field label="Description" rule={Rules.Description}>
          <input name="description" />
        </Field>
        <Field label="Template" rule={{ ...Rules.TemplateBody, ...TEMPLATE }}>
          <textarea name="template" rows={12} required className="code-editor" spellCheck={false} defaultValue={SAMPLE_TEMPLATE} />
        </Field>
        <Field label="Parameters" rule={PARAMETERS}>
          <textarea name="parameters" rows={2} spellCheck={false} placeholder="Env=prod" />
        </Field>
        <Capabilities />
        <AutoPick name="adminRole" label="Administration role" options={roles} creates={ADMIN_ROLE} testId="admin-role" />
        <Field label="Execution role name" rule={Rules.ExecutionRoleName}>
          <input name="executionRole" defaultValue={EXECUTION_ROLE} />
        </Field>
        <div className="form-row">
          <Field label="Deploy to accounts" rule={InstanceRules.Accounts} hint="Blank for this account">
            <input name="accounts" placeholder="123456789012" />
          </Field>
          <Field label="Regions" rule={InstanceRules.Regions} hint="Blank to deploy later">
            <input name="regions" placeholder={here} />
          </Field>
        </div>
      </ActionForm>
    </Sheet>
  );
}

export default async function StackSets() {
  const data = await load(async () => {
    const client = await cloudformation();
    return all(
      (NextToken) => client.send(new ListStackSetsCommand({ NextToken, Status: "ACTIVE" })),
      (r) => r.Summaries,
      (r) => r.NextToken,
    );
  });
  const [roles, here] = await Promise.all([roleOptions("cloudformation.amazonaws.com"), region()]);
  const names = data.ok ? data.value.map((s) => s.StackSetName!) : [];
  return (
    <Page title="StackSets" actions={<CreateStackSet names={names} roles={roles} here={here} />}>
      <CloudFormationNav active="stacksets" />
      {!data.ok ? (
        <ErrorNotice error={data.error} />
      ) : (
        <List
          label="StackSets"
          empty={<Empty icon={ICONS.cloudformation} />}
          rows={data.value.map((s) => ({
            key: s.StackSetId!,
            icon: <Boxes size={20} aria-hidden />,
            title: s.StackSetName,
            subtitle: s.Description,
            href: `/cloudformation/stackset?name=${encodeURIComponent(s.StackSetName!)}`,
            meta: (
              <>
                {s.DriftStatus && s.DriftStatus !== "NOT_CHECKED" && <Status tone={stackTone(s.DriftStatus)}>{word(s.DriftStatus)}</Status>}
                <Pill>{word(s.PermissionModel)}</Pill>
                <Status tone={stackTone(s.Status)}>{word(s.Status)}</Status>
              </>
            ),
          }))}
        />
      )}
    </Page>
  );
}
