import { DescribeStackSetCommand, ListStackInstancesCommand, ListStackSetOperationResultsCommand, ListStackSetOperationsCommand } from "@aws-sdk/client-cloudformation";
import { ago, all, load, region } from "@mws-dashboard/aws";
import { ActionForm, CodeBlock, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Segments, Sheet, Specs, Status, Tags } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { CreateStackInstances as InstanceRules, UpdateStackSet as UpdateRules } from "@mws-dashboard/ui/model/cloudformation";
import { Boxes, Ban, Globe, Pencil, Plus, Radar, Trash2 } from "lucide-react";
import Link from "next/link";
import type { Metadata } from "next";

import { PARAMETERS, TEMPLATE, word } from "../../../lib/cloudformation";
import { ICONS, cloudformation, stackTone } from "../../../lib/clients";
import { Capabilities } from "../forms";
import { addStackInstances, deleteStackInstance, deleteStackSet, detectStackSetDrift, stopOperation, updateStackSet } from "../stacksets/actions";

export const metadata: Metadata = { title: "StackSet" };

type Props = { searchParams: Promise<{ name?: string; tab?: string; op?: string }> };
const enc = encodeURIComponent;
const BUSY = new Set(["RUNNING", "QUEUED", "STOPPING"]);

export default async function StackSet({ searchParams }: Props) {
  const { name = "", tab = "instances", op } = await searchParams;
  const back = { href: "/cloudformation/stacksets", label: "StackSets" };
  const base = `/cloudformation/stackset?name=${enc(name)}`;
  const data = await load(async () => {
    const client = await cloudformation();
    const [set, instances, operations, here] = await Promise.all([
      client.send(new DescribeStackSetCommand({ StackSetName: name })).then((r) => r.StackSet!),
      all(
        (NextToken) => client.send(new ListStackInstancesCommand({ StackSetName: name, NextToken })),
        (r) => r.Summaries,
        (r) => r.NextToken,
      ),
      all(
        (NextToken) => client.send(new ListStackSetOperationsCommand({ StackSetName: name, NextToken })),
        (r) => r.Summaries,
        (r) => r.NextToken,
      ),
      region(),
    ]);
    const results = op
      ? await all(
          (NextToken) => client.send(new ListStackSetOperationResultsCommand({ StackSetName: name, OperationId: op, NextToken })),
          (r) => r.Summaries,
          (r) => r.NextToken,
        )
      : [];
    return { set, instances, operations, results, here };
  });
  if (!data.ok) {
    return (
      <Page title={name} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { set, instances, operations, results, here } = data.value;
  const running = operations.some((o) => BUSY.has(o.Status ?? ""));
  operations.sort((a, b) => (b.CreationTimestamp?.getTime() ?? 0) - (a.CreationTimestamp?.getTime() ?? 0));
  const account = set.StackSetARN?.split(":")[4] ?? "";

  let body;
  if (tab === "operations") {
    body = (
      <>
        <List
          label="Operations"
          empty={<Empty icon={ICONS.cloudformation} />}
          rows={operations.map((o) => ({
            key: o.OperationId!,
            title: word(o.Action),
            subtitle: [o.StatusReason, o.OperationId].filter(Boolean).join(" · "),
            href: `${base}&tab=operations&op=${enc(o.OperationId!)}`,
            meta: (
              <>
                <Status tone={stackTone(o.Status)}>{word(o.Status)}</Status>
                <span>{ago(o.CreationTimestamp)}</span>
              </>
            ),
            actions: BUSY.has(o.Status ?? "") ? <ActionForm action={stopOperation.bind(null, name, o.OperationId!)} submit="Stop operation" icon={<Ban size={16} />} /> : undefined,
          }))}
        />
        {op && (
          <List
            label="Operation results"
            rows={results.map((r) => ({
              key: `${r.Account}-${r.Region}`,
              icon: <Globe size={18} aria-hidden />,
              title: `${r.Account} · ${r.Region}`,
              subtitle: r.StatusReason,
              meta: <Status tone={stackTone(r.Status)}>{word(r.Status)}</Status>,
            }))}
          />
        )}
      </>
    );
  } else if (tab === "parameters") {
    body = <Facts items={(set.Parameters ?? []).map((p) => [p.ParameterKey, <code key={p.ParameterKey}>{p.ParameterValue}</code>])} />;
  } else if (tab === "template") {
    body = <CodeBlock value={set.TemplateBody} label="Template" />;
  } else {
    body = (
      <List
        label="Stack instances"
        empty={<Empty icon={ICONS.cloudformation} />}
        rows={instances.map((i) => ({
          key: `${i.Account}-${i.Region}`,
          icon: <Globe size={18} aria-hidden />,
          title: `${i.Account} · ${i.Region}`,
          subtitle: i.StatusReason ?? i.StackId,
          href: i.StackId && i.Region === here && i.Account === account ? `/cloudformation/stack?name=${enc(i.StackId)}` : undefined,
          meta: (
            <>
              {i.DriftStatus && i.DriftStatus !== "NOT_CHECKED" && <Status tone={stackTone(i.DriftStatus)}>{word(i.DriftStatus)}</Status>}
              <Status tone={i.Status === "CURRENT" ? "good" : i.Status === "INOPERABLE" ? "bad" : "warn"}>{word(i.StackInstanceStatus?.DetailedStatus ?? i.Status)}</Status>
            </>
          ),
          actions: !running ? (
            <ActionForm action={deleteStackInstance.bind(null, name, i.Account!, i.Region!, false)} submit={`Delete stack instance ${i.Account} ${i.Region}`} icon={<Trash2 size={16} />} tone="danger" confirm={`Delete the stack in ${i.Account} / ${i.Region}?`} />
          ) : undefined,
        }))}
      />
    );
  }

  return (
    <Page
      title={set.StackSetName ?? name}
      back={back}
      subtitle={set.StackSetARN}
      actions={
        !running && (
          <>
            <Sheet title="Add stack instances" label="Add stack instances" icon={<Plus size={16} />} testId="add-stack-instances">
              <ActionForm action={addStackInstances.bind(null, name)} submit="Add" testId="add-stack-instances">
                <Field label="Accounts" rule={InstanceRules.Accounts} hint="Blank for this account">
                  <input name="accounts" placeholder={account} />
                </Field>
                <Field label="Regions" rule={InstanceRules.Regions} hint="Comma-separated">
                  <input name="regions" defaultValue={here} />
                </Field>
              </ActionForm>
            </Sheet>
            <Sheet title="Update StackSet" label="Update StackSet" icon={<Pencil size={16} />} testId="update-stack-set">
              <ActionForm action={updateStackSet.bind(null, name)} submit="Update" testId="update-stack-set">
                <Field label="Description" rule={UpdateRules.Description}>
                  <input name="description" defaultValue={set.Description} />
                </Field>
                <Field label="Template" rule={{ ...UpdateRules.TemplateBody, ...TEMPLATE }}>
                  <textarea name="template" rows={14} required className="code-editor" spellCheck={false} defaultValue={set.TemplateBody} />
                </Field>
                <Field label="Parameters" rule={PARAMETERS}>
                  <textarea name="parameters" rows={2} spellCheck={false} defaultValue={(set.Parameters ?? []).map((p) => `${p.ParameterKey}=${p.ParameterValue}`).join("\n")} />
                </Field>
                <Capabilities />
              </ActionForm>
            </Sheet>
            {instances.length > 0 && <ActionForm action={detectStackSetDrift.bind(null, name)} submit="Detect drift" icon={<Radar size={16} />} testId="detect-stack-set-drift" />}
            {instances.length === 0 && <ActionForm action={deleteStackSet.bind(null, name)} submit="Delete StackSet" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete StackSet ${name}?`} testId="delete-stack-set" />}
          </>
        )
      }
    >
      <Specs
        items={[
          { label: "Status", icon: <Boxes size={15} />, value: <Status tone={stackTone(set.Status)}>{word(set.Status)}</Status> },
          { label: "Instances", icon: <Globe size={15} />, value: instances.length },
          { label: "Permissions", icon: <Boxes size={15} />, value: <Pill>{word(set.PermissionModel)}</Pill> },
          set.StackSetDriftDetectionDetails?.DriftStatus && set.StackSetDriftDetectionDetails.DriftStatus !== "NOT_CHECKED" && {
            label: "Drift",
            icon: <Radar size={15} />,
            value: <Status tone={stackTone(set.StackSetDriftDetectionDetails.DriftStatus)}>{word(set.StackSetDriftDetectionDetails.DriftStatus)}</Status>,
          },
          set.AdministrationRoleARN && {
            label: "Administration role",
            icon: <Boxes size={15} />,
            value: <Link href={`/iam/roles/${enc(set.AdministrationRoleARN.split("/").pop()!)}`}>{set.AdministrationRoleARN.split("/").pop()}</Link>,
          },
        ]}
      />
      <LiveRefresh when={running || instances.some((i) => i.Status === "OUTDATED" && ["PENDING", "RUNNING"].includes(i.StackInstanceStatus?.DetailedStatus ?? ""))} />
      {set.Description && <p className="muted">{set.Description}</p>}
      <Segments
        items={[
          { label: "Stack instances", href: base, active: tab === "instances", count: instances.length || undefined },
          { label: "Operations", href: `${base}&tab=operations`, active: tab === "operations", count: operations.length || undefined },
          { label: "Parameters", href: `${base}&tab=parameters`, active: tab === "parameters", count: set.Parameters?.length || undefined },
          { label: "Template", href: `${base}&tab=template`, active: tab === "template" },
        ]}
      />
      {body}
      <Tags tags={set.Tags} />
    </Page>
  );
}
