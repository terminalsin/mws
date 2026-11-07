import { DescribeStackEventsCommand, DescribeStackResourcesCommand, DescribeStacksCommand, GetTemplateCommand } from "@aws-sdk/client-cloudformation";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Facts, Field, List, Page, Segments, Sheet, Specs, Status, Tags } from "@mws-dashboard/ui";
import { Clock, Layers, Pencil, ShieldCheck, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, cloudformation, stackTone } from "../../../lib/clients";
import { resourceType } from "../../../lib/cloudformation";
import { deleteStack, updateStack } from "../actions";

export const metadata: Metadata = { title: "Stack" };

type Props = { searchParams: Promise<{ name?: string; tab?: string }> };

export default async function Stack({ searchParams }: Props) {
  const { name = "", tab = "resources" } = await searchParams;
  const back = { href: "/cloudformation", label: "Stacks" };
  const base = `/cloudformation/stack?name=${encodeURIComponent(name)}`;
  const data = await load(async () => {
    const client = await cloudformation();
    const [stack, resources, events, template] = await Promise.all([
      client.send(new DescribeStacksCommand({ StackName: name })).then((r) => r.Stacks![0]),
      client.send(new DescribeStackResourcesCommand({ StackName: name })).then((r) => r.StackResources ?? []),
      client.send(new DescribeStackEventsCommand({ StackName: name })).then((r) => r.StackEvents ?? []),
      client.send(new GetTemplateCommand({ StackName: name })).then((r) => r.TemplateBody ?? "", () => ""),
    ]);
    return { stack, resources, events, template };
  });
  if (!data.ok) {
    return (
      <Page title={name} icon={ICONS.stack} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { stack: s, resources, events, template } = data.value;
  const busy = s.StackStatus?.endsWith("_IN_PROGRESS");
  let body;
  if (tab === "outputs") {
    body = <List label="Outputs" empty={<Empty icon={ICONS.stack} />} rows={(s.Outputs ?? []).map((o) => ({ key: o.OutputKey!, title: o.OutputKey, subtitle: <code className="clip">{o.OutputValue}</code>, meta: o.ExportName ? <span>export {o.ExportName}</span> : undefined }))} />;
  } else if (tab === "events") {
    body = (
      <List
        label="Events"
        rows={events.slice(0, 100).map((e) => ({
          key: e.EventId!,
          icon: <AwsIcon icon={resourceType(e.ResourceType).icon} size={20} />,
          title: e.LogicalResourceId,
          subtitle: e.ResourceStatusReason,
          meta: (
            <>
              <Status tone={stackTone(e.ResourceStatus)}>{e.ResourceStatus?.toLowerCase().replace(/_/g, " ")}</Status>
              <span>{ago(e.Timestamp)}</span>
            </>
          ),
        }))}
      />
    );
  } else if (tab === "parameters") {
    body = <Facts items={(s.Parameters ?? []).map((p) => [p.ParameterKey, <code key={p.ParameterKey}>{p.ResolvedValue ?? p.ParameterValue}</code>])} />;
  } else if (tab === "template") {
    body = <CodeBlock value={template} label="Template" />;
  } else {
    body = (
      <List
        label="Resources"
        empty={<Empty icon={ICONS.stack} />}
        rows={resources.map((r) => {
          const t = resourceType(r.ResourceType);
          return {
            key: r.LogicalResourceId!,
            icon: <AwsIcon icon={t.icon} size={22} />,
            title: r.LogicalResourceId,
            subtitle: `${r.ResourceType} · ${r.PhysicalResourceId ?? ""}`,
            href: t.href && r.PhysicalResourceId ? t.href(r.PhysicalResourceId) : undefined,
            external: true,
            meta: <Status tone={stackTone(r.ResourceStatus)}>{r.ResourceStatus?.toLowerCase().replace(/_/g, " ")}</Status>,
          };
        })}
      />
    );
  }
  return (
    <Page
      title={name}
      icon={ICONS.stack}
      back={back}
      subtitle={s.StackId}
      actions={
        <>
          {!busy && (
            <Sheet title="Update stack" label="Update stack" icon={<Pencil size={16} />} testId="update-stack">
              <ActionForm action={updateStack.bind(null, name)} submit="Update" testId="update-stack">
                <textarea name="template" rows={18} required aria-label="Template" className="code-editor" spellCheck={false} defaultValue={template} />
                <Field label="Parameters">
                  <textarea name="parameters" rows={2} defaultValue={(s.Parameters ?? []).map((p) => `${p.ParameterKey}=${p.ParameterValue}`).join("\n")} />
                </Field>
              </ActionForm>
            </Sheet>
          )}
          <ActionForm action={deleteStack.bind(null, name)} submit="Delete stack" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name} and its resources?`} testId="delete-stack" />
        </>
      }
    >
      <Specs
        items={[
          { label: "Status", icon: <AwsIcon icon={ICONS.cloudformation} size={16} />, value: <Status tone={stackTone(s.StackStatus)}>{s.StackStatus?.toLowerCase().replace(/_/g, " ")}</Status> },
          { label: "Resources", icon: <Layers size={15} />, value: resources.length },
          s.EnableTerminationProtection && { label: "Termination protection", icon: <ShieldCheck size={15} />, value: "Protected" },
          { label: "Updated", icon: <Clock size={15} />, value: ago(s.LastUpdatedTime ?? s.CreationTime) },
        ]}
      />
      {s.StackStatusReason && <div className={`banner${stackTone(s.StackStatus) === "bad" ? " error" : ""}`}>{s.StackStatusReason}</div>}
      <Segments
        items={[
          { label: "Resources", href: base, active: tab === "resources", count: resources.length },
          { label: "Outputs", href: `${base}&tab=outputs`, active: tab === "outputs", count: s.Outputs?.length || undefined },
          { label: "Events", href: `${base}&tab=events`, active: tab === "events" },
          { label: "Parameters", href: `${base}&tab=parameters`, active: tab === "parameters", count: s.Parameters?.length || undefined },
          { label: "Template", href: `${base}&tab=template`, active: tab === "template" },
        ]}
      />
      {body}
      <Tags tags={s.Tags} />
    </Page>
  );
}
