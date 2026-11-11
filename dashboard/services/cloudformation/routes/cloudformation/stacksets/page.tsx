import { ListStackSetsCommand } from "@aws-sdk/client-cloudformation";
import { all, load, region } from "@mws-dashboard/aws";
import { roleOptions } from "@mws-dashboard/aws/auto";
import { ActionForm, AutoPick, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Sheet, Status } from "@mws-dashboard/ui";
import { CreateStackInstances as InstanceRules, CreateStackSet as Rules } from "@mws-dashboard/ui/model/cloudformation";
import { MoreFields } from "@mws-dashboard/ui/presets";
import { Section, Sections } from "@mws-dashboard/ui/sections";
import type { Metadata } from "next";

import { PARAMETERS, SAMPLE_TEMPLATE, STACK_NAME, TEMPLATE, word } from "../../../lib/cloudformation";
import { ICONS, cloudformation, stackTone } from "../../../lib/clients";
import { CloudFormationNav } from "../../../lib/nav";
import { ADMIN_ROLE, EXECUTION_ROLE } from "../../../lib/stacksets";
import { Capabilities } from "../forms";
import { createStackSet } from "./actions";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";

export const metadata: Metadata = { title: "StackSets" };

function CreateStackSet({ names, roles, here }: { names: string[]; roles: { value: string; label: string }[]; here: string }) {
  return (
    <Sheet title="Create StackSet" label="Create StackSet" testId="create-stack-set">
      <ActionForm action={createStackSet} submit="Create StackSet" testId="create-stack-set">
        <Sections testId="stack-set">
          <Section id="template" label="Template">
            <Field label="Template" rule={{ ...Rules.TemplateBody, ...TEMPLATE }}>
              <textarea name="template" rows={12} required className="code-editor" spellCheck={false} defaultValue={SAMPLE_TEMPLATE} />
            </Field>
          </Section>
          <Section id="details" label="Details">
            <Field label="StackSet name" rule={{ ...Rules.StackSetName, ...STACK_NAME }} taken={names} unique>
              <input name="name" required maxLength={128} />
            </Field>
            <Field label="Parameters" rule={PARAMETERS}>
              <textarea name="parameters" rows={2} spellCheck={false} placeholder="Env=prod" />
            </Field>
            <Field label="Description" rule={Rules.Description}>
              <input name="description" />
            </Field>
            <Capabilities />
          </Section>
          <Section id="deploy" label="Deploy">
            <Field label="Regions" rule={InstanceRules.Regions} hint="Blank to deploy later">
              <input name="regions" defaultValue={here} placeholder={here} />
            </Field>
            <Field label="Deploy to accounts" rule={InstanceRules.Accounts} hint="Blank for this account">
              <input name="accounts" placeholder="123456789012" />
            </Field>
            <MoreFields label="Roles">
              <AutoPick name="adminRole" label="Administration role" options={roles} creates={ADMIN_ROLE} testId="admin-role" />
              <Field label="Execution role name" rule={Rules.ExecutionRoleName}>
                <ResourcePicker kind="iam-role" use="name" name="executionRole" defaultValue={EXECUTION_ROLE} />
              </Field>
            </MoreFields>
          </Section>
        </Sections>
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
  const create = <CreateStackSet names={names} roles={roles} here={here} />;
  return (
    <Page title="StackSets" actions={create}>
      <CloudFormationNav active="stacksets" />
      {!data.ok ? (
        <ErrorNotice error={data.error} />
      ) : (
        <List
          label="StackSets"
          empty={<Empty icon={ICONS.cloudformation} action={create} />}
          rows={data.value.map((s) => ({
            key: s.StackSetId!,
            icon: <AwsIcon icon={ICONS.stack} size={24} />,
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
