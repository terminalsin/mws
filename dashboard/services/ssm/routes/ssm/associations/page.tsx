import { ListAssociationsCommand } from "@aws-sdk/client-ssm";
import { ago, all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, List, Page, Pill, Sheet, Status } from "@mws-dashboard/ui";
import { Play, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, ssm } from "../../../lib/clients";
import { SsmNav } from "../../../lib/nav";
import { listDocuments } from "../../../lib/nodes";
import { targetsText, tone, words } from "../../../lib/status";
import { AssociationFields } from "./fields";
import { applyNow, createAssociation, deleteAssociation } from "./actions";

export const metadata: Metadata = { title: "State Manager" };

export default async function Associations() {
  const c = await ssm();
  const [list, docs] = await Promise.all([
    load(() => all((NextToken) => c.send(new ListAssociationsCommand({ NextToken, MaxResults: 50 })), (r) => r.Associations, (r) => r.NextToken)),
    listDocuments([{ Key: "DocumentType", Values: ["Command", "Policy", "Automation"] }]).catch(() => []),
  ]);
  const create = (
    <Sheet title="Create association" label="Create association" testId="create-association">
      <ActionForm action={createAssociation} submit="Create" testId="create-association">
        <AssociationFields documents={docs.map((d) => d.Name!)} />
      </ActionForm>
    </Sheet>
  );
  return (
    <Page title="State Manager" icon={ICONS.ssm} actions={create}>
      <SsmNav active="associations" />
      {list.ok ? (
        <List
          label="Associations"
          empty={<Empty icon={ICONS.association} action={create} />}
          rows={list.value.map((a) => ({
            key: a.AssociationId!,
            icon: <AwsIcon icon={ICONS.association} size={24} />,
            title: a.AssociationName || a.Name,
            subtitle: [a.AssociationName ? a.Name : null, targetsText(a.Targets) || a.InstanceId, a.ScheduleExpression].filter(Boolean).join(" · "),
            href: `/ssm/association?id=${a.AssociationId}`,
            meta: (
              <>
                <Pill>v{a.AssociationVersion}</Pill>
                {a.LastExecutionDate && <span>{ago(a.LastExecutionDate)}</span>}
                <Status tone={tone(a.Overview?.Status)}>{words(a.Overview?.Status ?? "Pending")}</Status>
              </>
            ),
            actions: (
              <>
                <ActionForm action={applyNow.bind(null, a.AssociationId!)} submit={`Apply ${a.AssociationName || a.Name} now`} icon={<Play size={15} />} />
                <ActionForm action={deleteAssociation.bind(null, a.AssociationId!, false)} submit={`Delete ${a.AssociationName || a.Name}`} icon={<Trash2 size={15} />} tone="danger" confirm="Delete this association?" />
              </>
            ),
          }))}
        />
      ) : (
        <ErrorNotice error={list.error} />
      )}
    </Page>
  );
}
