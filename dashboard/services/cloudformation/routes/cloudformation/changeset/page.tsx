import { DescribeChangeSetCommand, DescribeChangeSetHooksCommand, GetTemplateCommand, type Change } from "@aws-sdk/client-cloudformation";
import { ago, load, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Facts, List, Page, Pill, Segments, Specs, Status, Tags, type Tone } from "@mws-dashboard/ui";
import { Clock, GitBranch, Play, Trash2 } from "lucide-react";
import Link from "next/link";
import type { Metadata } from "next";

import { ICONS, cloudformation, stackTone } from "../../../lib/clients";
import { resourceType, word } from "../../../lib/cloudformation";
import { deleteChangeSet, executeChangeSet } from "../actions";

export const metadata: Metadata = { title: "Change set" };

type Props = { searchParams: Promise<{ stack?: string; name?: string; tab?: string }> };

const enc = encodeURIComponent;
const ACTION_TONE: Record<string, Tone> = { Add: "good", Modify: "info", Remove: "bad", Import: "info", Dynamic: "neutral", SyncWithActual: "neutral" };

export default async function ChangeSet({ searchParams }: Props) {
  const { stack = "", name = "", tab = "changes" } = await searchParams;
  const back = { href: `/cloudformation/stack?name=${enc(stack)}&tab=changesets`, label: stack };
  const base = `/cloudformation/changeset?stack=${enc(stack)}&name=${enc(name)}`;
  const data = await load(async () => {
    const client = await cloudformation();
    const first = await client.send(new DescribeChangeSetCommand({ StackName: stack, ChangeSetName: name }));
    const changes: Change[] = [...(first.Changes ?? [])];
    let token = first.NextToken;
    while (token) {
      const next = await client.send(new DescribeChangeSetCommand({ StackName: stack, ChangeSetName: name, NextToken: token }));
      changes.push(...(next.Changes ?? []));
      token = next.NextToken;
    }
    const [template, hooks] = await Promise.all([
      tab === "template"
        ? client.send(new GetTemplateCommand({ StackName: stack, ChangeSetName: name })).then(
            (r) => r.TemplateBody ?? "",
            () => "",
          )
        : "",
      client.send(new DescribeChangeSetHooksCommand({ StackName: stack, ChangeSetName: name })).then(
        (r) => r.Hooks ?? [],
        () => [],
      ),
    ]);
    return { cs: first, changes, template, hooks };
  });
  if (!data.ok) {
    return (
      <Page title={name} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { cs, changes, template, hooks } = data.value;
  const executable = cs.ExecutionStatus === "AVAILABLE";

  let body;
  if (tab === "template") {
    body = <CodeBlock value={template} label="Template" />;
  } else if (tab === "parameters") {
    body = <Facts items={(cs.Parameters ?? []).map((p) => [p.ParameterKey, <code key={p.ParameterKey}>{p.UsePreviousValue ? "(previous value)" : (p.ResolvedValue ?? p.ParameterValue)}</code>])} />;
  } else if (tab === "hooks") {
    body = (
      <List
        label="Hooks"
        empty={<Empty icon={ICONS.stack} />}
        rows={hooks.map((h, i) => ({
          key: `${h.TypeName}-${i}`,
          title: h.TypeName,
          subtitle: [h.TargetDetails?.ResourceTargetDetails?.LogicalResourceId, h.InvocationPoint].filter(Boolean).join(" · "),
          meta: <Pill>{word(h.FailureMode)}</Pill>,
        }))}
      />
    );
  } else {
    body = (
      <List
        label="Changes"
        empty={<Empty icon={ICONS.stack}>{cs.Status === "FAILED" ? undefined : "No changes"}</Empty>}
        rows={changes.map((c, i) => {
          const r = c.ResourceChange ?? {};
          const t = resourceType(r.ResourceType);
          const details = (r.Details ?? [])
            .map((d) => [d.Target?.Attribute, d.Target?.Name].filter(Boolean).join(".") + (d.Target?.RequiresRecreation && d.Target.RequiresRecreation !== "Never" ? ` (recreate ${word(d.Target.RequiresRecreation)})` : ""))
            .filter(Boolean);
          return {
            key: `${r.LogicalResourceId}-${i}`,
            icon: <AwsIcon icon={t.icon} size={22} />,
            title: r.LogicalResourceId,
            subtitle: [r.ResourceType, r.PhysicalResourceId, details.length ? `changes ${details.join(", ")}` : ""].filter(Boolean).join(" · "),
            href: t.href && r.PhysicalResourceId ? t.href(r.PhysicalResourceId) : undefined,
            meta: (
              <>
                {r.Replacement === "True" && <Pill tone="bad">replacement</Pill>}
                {r.Replacement === "Conditional" && <Pill tone="warn">may replace</Pill>}
                <Pill tone={ACTION_TONE[r.Action ?? ""] ?? "neutral"}>{r.Action}</Pill>
              </>
            ),
          };
        })}
      />
    );
  }

  return (
    <Page
      title={name}
      back={back}
      subtitle={cs.Description}
      actions={
        <>
          {executable && (
            <ActionForm action={executeChangeSet.bind(null, stack, name)} submit="Execute change set" icon={<Play size={16} />} confirm={`Execute ${name} on ${stack}?`} testId="execute-change-set" />
          )}
          <ActionForm action={deleteChangeSet.bind(null, stack, name)} submit="Delete change set" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete change set ${name}?`} testId="delete-change-set" />
        </>
      }
    >
      <Specs
        items={[
          { label: "Status", icon: <GitBranch size={15} />, value: <Status tone={stackTone(cs.Status)}>{word(cs.Status)}</Status> },
          { label: "Execution", icon: <Play size={15} />, value: <Status tone={stackTone(cs.ExecutionStatus)}>{word(cs.ExecutionStatus)}</Status> },
          {
            label: "Stack",
            icon: <AwsIcon icon={ICONS.stack} size={16} />,
            value: <Link href={`/cloudformation/stack?name=${enc(cs.StackId ?? stack)}`}>{cs.StackName ?? stack}</Link>,
          },
          { label: "Created", icon: <Clock size={15} />, value: <span title={when(cs.CreationTime)}>{ago(cs.CreationTime)}</span> },
        ]}
      />
      {cs.StatusReason && <div className={`banner${cs.Status === "FAILED" ? " error" : ""}`}>{cs.StatusReason}</div>}
      <Segments
        items={[
          { label: "Changes", href: base, active: tab === "changes", count: changes.length || undefined },
          { label: "Parameters", href: `${base}&tab=parameters`, active: tab === "parameters", count: cs.Parameters?.length || undefined },
          { label: "Template", href: `${base}&tab=template`, active: tab === "template" },
          ...(hooks.length > 0 ? [{ label: "Hooks", href: `${base}&tab=hooks`, active: tab === "hooks", count: hooks.length }] : []),
        ]}
      />
      {body}
      <Tags tags={cs.Tags} />
    </Page>
  );
}
