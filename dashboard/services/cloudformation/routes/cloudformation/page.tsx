import { ListStacksCommand } from "@aws-sdk/client-cloudformation";
import { ago, all, load } from "@mws-dashboard/aws";
import { AwsIcon, Curated, Empty, ErrorNotice, Page, Status } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { word } from "../../lib/cloudformation";
import { ICONS, cloudformation, stackTone } from "../../lib/clients";
import { CloudFormationNav, stackName } from "../../lib/nav";
import { CreateChangeSet, CreateStack } from "./forms";

export const metadata: Metadata = { title: "CloudFormation" };

export default async function Stacks() {
  const stacks = await load(async () => {
    const client = await cloudformation();
    const list = await all(
      (NextToken) => client.send(new ListStacksCommand({ NextToken })),
      (r) => r.StackSummaries,
      (r) => r.NextToken,
    );
    return list.filter((s) => s.StackStatus !== "DELETE_COMPLETE");
  });
  const names = stacks.ok ? stacks.value.map((s) => s.StackName!) : [];
  const actions = (
    <>
      <CreateChangeSet names={names} />
      <CreateStack names={names} />
    </>
  );
  if (!stacks.ok) {
    return (
      <Page title="Stacks" actions={actions}>
        <CloudFormationNav active="stacks" />
        <ErrorNotice error={stacks.error} />
      </Page>
    );
  }
  const list = stacks.value.sort((a, b) => (b.LastUpdatedTime ?? b.CreationTime)!.getTime() - (a.LastUpdatedTime ?? a.CreationTime)!.getTime());
  const tone = (s: (typeof list)[number]) => stackTone(s.StackStatus);
  return (
    <Page title="Stacks" actions={actions}>
      <CloudFormationNav active="stacks" />
      <Curated
        label="Stacks"
        sections={[
          { id: "failed", title: "Failed or rolled back", items: list.filter((s) => tone(s) === "bad") },
          { id: "progress", title: "In progress", items: list.filter((s) => tone(s) === "warn") },
          { id: "complete", title: "Complete", items: list.filter((s) => tone(s) === "good" || tone(s) === "neutral") },
        ]}
        empty={<Empty icon={ICONS.cloudformation} action={<CreateStack names={[]} />} />}
        row={(s) => ({
          key: s.StackId!,
          icon: <AwsIcon icon={s.ParentId ? ICONS.stack : ICONS.cloudformation} size={24} />,
          title: s.StackName,
          subtitle: s.StackStatusReason ?? (s.RootId ? `Nested in ${stackName(s.RootId)}` : s.TemplateDescription),
          href: `/cloudformation/stack?name=${encodeURIComponent(s.StackName!)}`,
          meta: (
            <>
              {s.DriftInformation?.StackDriftStatus === "DRIFTED" && <Status tone="warn">Drifted</Status>}
              <Status tone={stackTone(s.StackStatus)}>{word(s.StackStatus)}</Status>
              <span>{ago(s.LastUpdatedTime ?? s.CreationTime)}</span>
            </>
          ),
        })}
      />
    </Page>
  );
}
