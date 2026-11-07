import { ListStacksCommand } from "@aws-sdk/client-cloudformation";
import { ago, collect, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, Page, Sheet, Status } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { ICONS, cloudformation, stackTone } from "../../lib/clients";
import { SAMPLE_TEMPLATE } from "../../lib/cloudformation";
import { createStack } from "./actions";

export const metadata: Metadata = { title: "CloudFormation" };

function CreateStack() {
  return (
    <Sheet title="Create stack" label="Create stack" testId="create-stack">
      <ActionForm action={createStack} submit="Create stack" testId="create-stack">
        <Field label="Stack name">
          <input name="name" required pattern="[A-Za-z][A-Za-z0-9\-]*" autoFocus />
        </Field>
        <textarea name="template" rows={16} required aria-label="Template" className="code-editor" spellCheck={false} defaultValue={SAMPLE_TEMPLATE} />
        <Field label="Parameters">
          <textarea name="parameters" rows={2} placeholder="Env=prod" />
        </Field>
        <Field label="On failure">
          <select name="onFailure" defaultValue="ROLLBACK">
            <option value="ROLLBACK">Roll back</option>
            <option value="DO_NOTHING">Preserve resources</option>
            <option value="DELETE">Delete</option>
          </select>
        </Field>
      </ActionForm>
    </Sheet>
  );
}

export default async function Stacks() {
  const stacks = await load(async () => {
    const client = await cloudformation();
    const all = await collect(
      (NextToken) => client.send(new ListStacksCommand({ NextToken })),
      (r) => r.StackSummaries,
      (r) => r.NextToken,
    );
    return all.filter((s) => s.StackStatus !== "DELETE_COMPLETE");
  });
  if (!stacks.ok) {
    return (
      <Page title="Stacks" actions={<CreateStack />}>
        <ErrorNotice error={stacks.error} />
      </Page>
    );
  }
  const all = stacks.value.sort((a, b) => (b.LastUpdatedTime ?? b.CreationTime)!.getTime() - (a.LastUpdatedTime ?? a.CreationTime)!.getTime());
  return (
    <Page title="Stacks" actions={<CreateStack />}>
      <Curated
        label="Stacks"
        sections={[
          { id: "failed", title: "Failed or rolled back", items: all.filter((s) => stackTone(s.StackStatus) === "bad") },
          { id: "progress", title: "In progress", items: all.filter((s) => stackTone(s.StackStatus) === "warn") },
          { id: "complete", title: "Complete", items: all.filter((s) => stackTone(s.StackStatus) === "good" || stackTone(s.StackStatus) === "neutral") },
        ]}
        empty={<Empty icon={ICONS.cloudformation} action={<CreateStack />} />}
        row={(s) => ({
          key: s.StackId!,
          icon: <AwsIcon icon={s.ParentId ? ICONS.stack : ICONS.cloudformation} size={24} />,
          title: s.StackName,
          subtitle: s.StackStatusReason ?? s.TemplateDescription,
          href: `/cloudformation/stack?name=${encodeURIComponent(s.StackName!)}`,
          meta: (
            <>
              {s.DriftInformation?.StackDriftStatus === "DRIFTED" && <Status tone="warn">Drifted</Status>}
              <Status tone={stackTone(s.StackStatus)}>{s.StackStatus?.toLowerCase().replace(/_/g, " ")}</Status>
              <span>{ago(s.LastUpdatedTime ?? s.CreationTime)}</span>
            </>
          ),
        })}
      />
    </Page>
  );
}
