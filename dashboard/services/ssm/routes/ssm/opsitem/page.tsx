import { GetOpsItemCommand, ListOpsItemEventsCommand, ListOpsItemRelatedItemsCommand } from "@aws-sdk/client-ssm";
import { ago, load, when } from "@mws-dashboard/aws";
import { ActionForm, CodeBlock, Empty, ErrorNotice, Facts, List, Page, Pill, Section, Sheet } from "@mws-dashboard/ui";
import { CircleCheckBig, Pencil, Play, RotateCcw, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, ssm } from "../../../lib/clients";
import { tone, words } from "../../../lib/status";
import { deleteOpsItem, setStatus, updateOpsItem } from "../opsitems/actions";
import { OpsItemFields } from "../opsitems/fields";

export const metadata: Metadata = { title: "OpsItem" };

type Props = { searchParams: Promise<{ id?: string }> };

/** Where an OpsItem's related resource lives in the console. */
function relatedHref(type: string | undefined, uri: string | undefined) {
  if (!uri) return undefined;
  if (type === "AWS::SSM::Document" || uri.includes(":document/")) return `/ssm/document?name=${encodeURIComponent(uri.split("/").pop()!)}`;
  if (type === "AWS::SSMIncidents::IncidentRecord") return undefined;
  if (uri.includes(":automation-execution/")) return `/ssm/automation/execution?id=${uri.split("/").pop()}`;
  if (uri.includes(":instance/")) return `/ec2/instance?id=${uri.split("/").pop()}`;
  return undefined;
}

export default async function OpsItem({ searchParams }: Props) {
  const { id = "" } = await searchParams;
  const back = { href: "/ssm/opsitems", label: "OpsCenter" };
  const c = await ssm();
  const data = await load(async () => {
    const [item, events, related] = await Promise.all([
      c.send(new GetOpsItemCommand({ OpsItemId: id })).then((r) => r.OpsItem!),
      c.send(new ListOpsItemEventsCommand({ Filters: [{ Key: "OpsItemId", Operator: "Equal", Values: [id] }] })).then((r) => r.Summaries ?? [], () => []),
      c.send(new ListOpsItemRelatedItemsCommand({ OpsItemId: id })).then((r) => r.Summaries ?? [], () => []),
    ]);
    return { item, events, related };
  });
  if (!data.ok) {
    return (
      <Page title="OpsItem" icon={ICONS.opsItem} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { item: o, events, related } = data.value;
  const open = o.Status === "Open" || o.Status === "InProgress";
  return (
    <Page
      title={o.Title}
      icon={ICONS.opsItem}
      back={back}
      subtitle={o.OpsItemArn ?? o.OpsItemId}
      actions={
        <>
          {o.Status === "Open" && <ActionForm action={setStatus.bind(null, id, "InProgress")} submit="Set in progress" icon={<Play size={16} />} testId="opsitem-progress" />}
          {open && <ActionForm action={setStatus.bind(null, id, "Resolved")} submit="Resolve" icon={<CircleCheckBig size={16} />} testId="opsitem-resolve" />}
          {o.Status === "Resolved" && <ActionForm action={setStatus.bind(null, id, "Open")} submit="Reopen" icon={<RotateCcw size={16} />} />}
          <Sheet title="Edit OpsItem" label="Edit OpsItem" icon={<Pencil size={16} />} testId="edit-opsitem">
            <ActionForm action={updateOpsItem.bind(null, id)} submit="Save" testId="edit-opsitem">
              <OpsItemFields d={{ title: o.Title, description: o.Description, priority: o.Priority, severity: o.Severity, category: o.Category }} />
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteOpsItem.bind(null, id)} submit="Delete OpsItem" icon={<Trash2 size={16} />} tone="danger" confirm="Delete this OpsItem?" />
        </>
      }
    >
      <Facts
        items={[
          ["Status", <Pill key="s" tone={tone(o.Status)}>{words(o.Status)}</Pill>],
          o.Priority && ["Priority", `P${o.Priority}`],
          o.Severity && ["Severity", o.Severity],
          o.Category && ["Category", o.Category],
          ["Source", o.Source],
          o.OpsItemType && ["Type", o.OpsItemType],
          ["Created", `${when(o.CreatedTime)} by ${o.CreatedBy?.split("/").pop()}`],
          o.LastModifiedTime && ["Modified", `${ago(o.LastModifiedTime)} by ${o.LastModifiedBy?.split("/").pop()}`],
          o.RelatedOpsItems?.length && ["Related OpsItems", o.RelatedOpsItems.map((r) => <Link key={r.OpsItemId} href={`/ssm/opsitem?id=${r.OpsItemId}`}>{r.OpsItemId} </Link>)],
        ]}
      />
      <Section title="Description">
        <p>{o.Description}</p>
      </Section>
      {related.length > 0 && (
        <Section title="Related resources" count={related.length} plain>
          <List
            label="Related resources"
            rows={related.map((r) => ({ key: r.AssociationId!, title: r.ResourceUri, subtitle: [r.ResourceType, r.AssociationType].join(" · "), href: relatedHref(r.ResourceType, r.ResourceUri), meta: <span>{ago(r.CreatedTime)}</span> }))}
          />
        </Section>
      )}
      {o.OperationalData && Object.keys(o.OperationalData).length > 0 && (
        <Section title="Operational data">
          <CodeBlock value={JSON.stringify(Object.fromEntries(Object.entries(o.OperationalData).map(([k, v]) => [k, v.Value])))} label="Operational data" />
        </Section>
      )}
      <Section title="Events" count={events.length} plain>
        <List
          label="Events"
          empty={<Empty>No events</Empty>}
          rows={events.map((e) => ({ key: e.EventId!, title: e.DetailType, subtitle: [e.Source, e.CreatedBy?.Arn?.split("/").pop()].filter(Boolean).join(" · "), meta: <span>{ago(e.CreatedTime)}</span> }))}
        />
      </Section>
    </Page>
  );
}
