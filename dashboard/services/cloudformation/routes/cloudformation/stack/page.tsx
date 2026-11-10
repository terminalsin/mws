import {
  DescribeStackDriftDetectionStatusCommand,
  DescribeStackEventsCommand,
  DescribeStackResourceDriftsCommand,
  DescribeStackResourcesCommand,
  DescribeStacksCommand,
  GetStackPolicyCommand,
  GetTemplateCommand,
  ListChangeSetsCommand,
  ListImportsCommand,
  type CloudFormationClient,
} from "@aws-sdk/client-cloudformation";
import { ago, all, load, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, CopyValue, Empty, ErrorNotice, Facts, Field, List, More, Page, Pill, Section, Segments, Sheet, Specs, Status, Tags } from "@mws-dashboard/ui";
import { CopyButton, LiveRefresh } from "@mws-dashboard/ui/client";
import { MoreFields } from "@mws-dashboard/ui/presets";
import { SetStackPolicy as PolicyRules, UpdateStack as UpdateStackRules } from "@mws-dashboard/ui/model/cloudformation";
import { Ban, Clock, GitBranch, Layers, Pencil, Radar, RotateCcw, ShieldCheck, ShieldOff, Trash2, Undo2 } from "lucide-react";
import Link from "next/link";
import type { Metadata } from "next";

import { ICONS, cloudformation, stackTone } from "../../../lib/clients";
import { PARAMETERS, TEMPLATE, resourceType, word } from "../../../lib/cloudformation";
import { stackName } from "../../../lib/nav";
import { cancelUpdate, continueRollback, deleteStack, detectDrift, detectResourceDrift, rollbackStack, setStackPolicy, setTerminationProtection, updateStack } from "../actions";
import { Capabilities, CreateChangeSet } from "../forms";

export const metadata: Metadata = { title: "Stack" };

type Props = { searchParams: Promise<{ name?: string; tab?: string; events?: string; detection?: string }> };

const enc = encodeURIComponent;
const stackLink = (arn: string) => `/cloudformation/stack?name=${enc(arn)}`;

/** Stable states an update, a change set or drift detection may start from. */
const UPDATABLE = new Set(["CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE"]);
const ROLLBACKABLE = new Set(["CREATE_FAILED", "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_ROLLBACK_FAILED"]);

async function imports(client: CloudFormationClient, ExportName: string) {
  try {
    return await all(
      (NextToken) => client.send(new ListImportsCommand({ ExportName, NextToken })),
      (r) => r.Imports,
      (r) => r.NextToken,
    );
  } catch {
    // "Export 'x' is not imported by any stack."
    return [];
  }
}

export default async function Stack({ searchParams }: Props) {
  const { name = "", tab = "resources", events: eventsToken, detection } = await searchParams;
  const back = { href: "/cloudformation", label: "Stacks" };
  const base = `/cloudformation/stack?name=${enc(name)}`;
  const data = await load(async () => {
    const client = await cloudformation();
    const [stack, resources, template, changeSets] = await Promise.all([
      client.send(new DescribeStacksCommand({ StackName: name })).then((r) => r.Stacks![0]),
      client.send(new DescribeStackResourcesCommand({ StackName: name })).then((r) => r.StackResources ?? []),
      client.send(new GetTemplateCommand({ StackName: name })).then(
        (r) => r.TemplateBody ?? "",
        () => "",
      ),
      all(
        (NextToken) => client.send(new ListChangeSetsCommand({ StackName: name, NextToken })),
        (r) => r.Summaries,
        (r) => r.NextToken,
      ).catch(() => []),
    ]);
    const events = tab === "events" ? await client.send(new DescribeStackEventsCommand({ StackName: name, NextToken: eventsToken })) : undefined;
    const drifts =
      tab === "drift"
        ? await all(
            (NextToken) => client.send(new DescribeStackResourceDriftsCommand({ StackName: name, NextToken })),
            (r) => r.StackResourceDrifts,
            (r) => r.NextToken,
          )
        : [];
    const detecting = tab === "drift" && detection ? await client.send(new DescribeStackDriftDetectionStatusCommand({ StackDriftDetectionId: detection })).catch(() => undefined) : undefined;
    const importers =
      tab === "outputs"
        ? Object.fromEntries(await Promise.all((stack.Outputs ?? []).filter((o) => o.ExportName).map(async (o) => [o.ExportName!, await imports(client, o.ExportName!)] as const)))
        : {};
    const policy = tab === "info" ? await client.send(new GetStackPolicyCommand({ StackName: name })).then((r) => r.StackPolicyBody ?? "") : "";
    return { stack, resources, template, changeSets, events, drifts, detecting, importers, policy };
  });
  if (!data.ok) {
    return (
      <Page title={stackName(name)} icon={ICONS.stack} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { stack: s, resources, template, changeSets, events, drifts, detecting, importers, policy } = data.value;
  const status = s.StackStatus ?? "";
  const title = s.StackName ?? name;
  const busy = status.endsWith("_IN_PROGRESS");
  const updatable = UPDATABLE.has(status);
  const shown = Object.fromEntries((s.Parameters ?? []).map((p) => [p.ParameterKey!, p.ParameterValue ?? ""]));
  const paramText = (s.Parameters ?? []).map((p) => `${p.ParameterKey}=${p.ParameterValue}`).join("\n");
  const hidden = Object.values(shown).includes("****");
  const failedResources = resources.filter((r) => r.ResourceStatus?.endsWith("_FAILED"));
  const pending = changeSets.filter((c) => c.ExecutionStatus === "AVAILABLE");

  let body;
  if (tab === "outputs") {
    body = (
      <List
        label="Outputs"
        empty={<Empty icon={ICONS.stack} />}
        rows={(s.Outputs ?? []).map((o) => {
          const users = o.ExportName ? (importers[o.ExportName] ?? []) : [];
          return {
            key: o.OutputKey!,
            title: o.OutputKey,
            subtitle: (
              <>
                <code className="clip">{o.OutputValue}</code>
                {users.length > 0 && (
                  <span>
                    {" "}
                    · imported by{" "}
                    {users.map((u, i) => (
                      <span key={u}>
                        {i > 0 && ", "}
                        <Link href={`/cloudformation/stack?name=${enc(u)}`}>{u}</Link>
                      </span>
                    ))}
                  </span>
                )}
              </>
            ),
            meta: o.ExportName ? <Pill tone={users.length ? "info" : "neutral"}>export {o.ExportName}</Pill> : undefined,
            actions: o.OutputValue ? <CopyButton value={o.OutputValue} label={`Copy ${o.OutputKey}`} /> : undefined,
          };
        })}
      />
    );
  } else if (tab === "events") {
    const list = events?.StackEvents ?? [];
    const next = events?.NextToken;
    body = (
      <>
        <List
          label="Events"
          empty={<Empty icon={ICONS.stack} />}
          rows={list.map((e) => {
            const t = resourceType(e.ResourceType);
            return {
              key: e.EventId!,
              icon: <AwsIcon icon={t.icon} size={20} />,
              title: e.LogicalResourceId,
              subtitle: [e.ResourceStatusReason, e.ResourceType, e.PhysicalResourceId && e.PhysicalResourceId !== e.LogicalResourceId ? e.PhysicalResourceId : ""].filter(Boolean).join(" · "),
              meta: (
                <>
                  <Status tone={stackTone(e.ResourceStatus)}>{word(e.ResourceStatus)}</Status>
                  <span title={when(e.Timestamp)}>{ago(e.Timestamp)}</span>
                </>
              ),
            };
          })}
        />
        <More shown={list.length} noun="events" href={next ? `${base}&tab=events&events=${enc(next)}` : undefined} />
      </>
    );
  } else if (tab === "parameters") {
    body = (
      <Facts
        items={(s.Parameters ?? []).map((p) => [
          p.ParameterKey,
          <code key={p.ParameterKey}>
            {p.ResolvedValue ?? p.ParameterValue}
            {p.ResolvedValue && <span className="muted"> ({p.ParameterValue})</span>}
          </code>,
        ])}
      />
    );
  } else if (tab === "template") {
    body = <CodeBlock value={template} label="Template" />;
  } else if (tab === "changesets") {
    body = (
      <List
        label="Change sets"
        empty={<Empty icon={ICONS.stack} action={updatable || status === "REVIEW_IN_PROGRESS" ? <CreateChangeSet stack={title} template={template} parameters={paramText} previous={shown} /> : undefined} />}
        rows={changeSets.map((c) => ({
          key: c.ChangeSetId!,
          icon: <GitBranch size={18} aria-hidden />,
          title: c.ChangeSetName,
          subtitle: c.StatusReason ?? c.Description,
          href: `/cloudformation/changeset?stack=${enc(title)}&name=${enc(c.ChangeSetName!)}`,
          meta: (
            <>
              <Status tone={stackTone(c.Status)}>{word(c.Status)}</Status>
              <Status tone={stackTone(c.ExecutionStatus)}>{word(c.ExecutionStatus)}</Status>
              <span>{ago(c.CreationTime)}</span>
            </>
          ),
        }))}
      />
    );
  } else if (tab === "drift") {
    const inProgress = detecting?.DetectionStatus === "DETECTION_IN_PROGRESS";
    body = (
      <>
        {inProgress && <LiveRefresh />}
        {detecting && (
          <div className={`banner${detecting.DetectionStatus === "DETECTION_FAILED" ? " error" : ""}`}>
            {inProgress ? "Detecting drift…" : `Drift detection ${word(detecting.DetectionStatus)}`}
            {detecting.DetectionStatusReason ? `: ${detecting.DetectionStatusReason}` : ""}
          </div>
        )}
        <List
          label="Drift"
          empty={<Empty icon={ICONS.stack}>{s.DriftInformation?.StackDriftStatus === "NOT_CHECKED" ? "Drift has not been checked" : undefined}</Empty>}
          rows={drifts.map((d) => {
            const t = resourceType(d.ResourceType);
            const diffs = d.PropertyDifferences ?? [];
            return {
              key: d.LogicalResourceId!,
              icon: <AwsIcon icon={t.icon} size={22} />,
              title: d.LogicalResourceId,
              subtitle: diffs.length
                ? diffs.map((p) => `${p.PropertyPath}: ${p.ExpectedValue ?? "∅"} → ${p.ActualValue ?? "∅"} (${word(p.DifferenceType)})`).join(" · ")
                : `${d.ResourceType} · ${d.PhysicalResourceId ?? ""}`,
              href: t.href && d.PhysicalResourceId ? t.href(d.PhysicalResourceId) : undefined,
              meta: (
                <>
                  <Status tone={stackTone(d.StackResourceDriftStatus)}>{word(d.StackResourceDriftStatus)}</Status>
                  <span>{ago(d.Timestamp)}</span>
                </>
              ),
              actions: <ActionForm action={detectResourceDrift.bind(null, title, d.LogicalResourceId!)} submit={`Detect drift on ${d.LogicalResourceId}`} icon={<Radar size={16} />} />,
            };
          })}
        />
      </>
    );
  } else if (tab === "info") {
    const d = s.DriftInformation;
    body = (
      <>
        <Facts
          items={[
            ["Stack ID", <CopyValue key="id" value={s.StackId} label="Copy stack ID" />],
            s.Description && ["Description", s.Description],
            ["Created", when(s.CreationTime)],
            s.LastUpdatedTime && ["Updated", when(s.LastUpdatedTime)],
            s.DeletionTime && ["Deleted", when(s.DeletionTime)],
            d && ["Drift", <Status key="drift" tone={stackTone(d.StackDriftStatus)}>{word(d.StackDriftStatus)}</Status>],
            d?.LastCheckTimestamp && ["Drift checked", when(d.LastCheckTimestamp)],
            s.ParentId && [
              "Parent stack",
              <Link key="parent" href={stackLink(s.ParentId)}>
                {stackName(s.ParentId)}
              </Link>,
            ],
            s.RootId && s.RootId !== s.ParentId && [
              "Root stack",
              <Link key="root" href={stackLink(s.RootId)}>
                {stackName(s.RootId)}
              </Link>,
            ],
            s.RoleARN && [
              "Service role",
              <Link key="role" href={`/iam/roles/${enc(s.RoleARN.split("/").pop()!)}`}>
                {s.RoleARN}
              </Link>,
            ],
            ["Termination protection", s.EnableTerminationProtection ? "Enabled" : "Disabled"],
            ["Rollback on failure", s.DisableRollback ? "Disabled" : "Enabled"],
            s.TimeoutInMinutes && ["Timeout", `${s.TimeoutInMinutes} min`],
            (s.Capabilities ?? []).length > 0 && ["Capabilities", s.Capabilities!.join(", ")],
            (s.NotificationARNs ?? []).length > 0 && [
              "Notifications",
              <span key="sns">
                {s.NotificationARNs!.map((a) => (
                  <Link key={a} href={`/sns/topic?arn=${enc(a)}`} className="block">
                    {a.split(":").pop()}
                  </Link>
                ))}
              </span>,
            ],
            (s.RollbackConfiguration?.RollbackTriggers ?? []).length > 0 && ["Rollback triggers", s.RollbackConfiguration!.RollbackTriggers!.map((t) => t.Arn).join(", ")],
          ]}
        />
        <Section
          title="Stack policy"
          actions={
            !s.DeletionTime && (
              <Sheet title="Stack policy" label="Edit stack policy" icon={<Pencil size={16} />} testId="stack-policy">
                <ActionForm action={setStackPolicy.bind(null, title)} submit="Save" testId="stack-policy">
                  <Field label="Policy" rule={PolicyRules.StackPolicyBody} format="policy">
                    <textarea
                      name="policy"
                      rows={12}
                      className="code-editor"
                      spellCheck={false}
                      required
                      defaultValue={policy || JSON.stringify({ Statement: [{ Effect: "Allow", Action: "Update:*", Principal: "*", Resource: "*" }] }, null, 2)}
                    />
                  </Field>
                </ActionForm>
              </Sheet>
            )
          }
        >
          <CodeBlock value={policy} label="Stack policy" />
        </Section>
      </>
    );
  } else {
    body = (
      <List
        label="Resources"
        empty={<Empty icon={ICONS.stack} />}
        rows={resources.map((r) => {
          const t = resourceType(r.ResourceType);
          const drift = r.DriftInformation?.StackResourceDriftStatus;
          return {
            key: r.LogicalResourceId!,
            icon: <AwsIcon icon={t.icon} size={22} />,
            title: r.LogicalResourceId,
            subtitle: [r.ResourceStatusReason, r.ResourceType, r.PhysicalResourceId].filter(Boolean).join(" · "),
            href: t.href && r.PhysicalResourceId ? t.href(r.PhysicalResourceId) : undefined,
            meta: (
              <>
                {(drift === "MODIFIED" || drift === "DELETED") && <Status tone="warn">{word(drift)}</Status>}
                <Status tone={stackTone(r.ResourceStatus)}>{word(r.ResourceStatus)}</Status>
              </>
            ),
          };
        })}
      />
    );
  }

  const protectedStack = !!s.EnableTerminationProtection;
  return (
    <Page
      title={title}
      icon={ICONS.stack}
      back={back}
      subtitle={s.Description}
      actions={
        !s.DeletionTime && (
          <>
            {status === "UPDATE_IN_PROGRESS" && <ActionForm action={cancelUpdate.bind(null, title)} submit="Cancel update" icon={<Ban size={16} />} confirm={`Cancel the update of ${title}? It rolls back.`} testId="cancel-update" />}
            {status === "UPDATE_ROLLBACK_FAILED" && (
              <Sheet title="Continue update rollback" label="Continue update rollback" icon={<RotateCcw size={16} />} testId="continue-rollback">
                <ActionForm action={continueRollback.bind(null, title)} submit="Continue rollback" testId="continue-rollback">
                  {failedResources.length > 0 && (
                    <fieldset className="checks">
                      <legend>Resources to skip</legend>
                      {failedResources.map((r) => (
                        <label key={r.LogicalResourceId} className="check">
                          <input type="checkbox" name="skip" value={r.LogicalResourceId} /> {r.LogicalResourceId}
                        </label>
                      ))}
                    </fieldset>
                  )}
                </ActionForm>
              </Sheet>
            )}
            {ROLLBACKABLE.has(status) && <ActionForm action={rollbackStack.bind(null, title)} submit="Roll back" icon={<Undo2 size={16} />} confirm={`Roll ${title} back to its last stable state?`} testId="rollback-stack" />}
            {updatable && (
              <Sheet title="Update stack" label="Update stack" icon={<Pencil size={16} />} testId="update-stack">
                <ActionForm action={updateStack.bind(null, title, shown)} submit="Update" testId="update-stack">
                  <Field label="Template" rule={{ ...UpdateStackRules.TemplateBody, ...TEMPLATE }}>
                    <textarea name="template" rows={18} required className="code-editor" spellCheck={false} defaultValue={template} />
                  </Field>
                  <Field label="Parameters" rule={PARAMETERS} hint={hidden ? "Leave **** to keep a hidden value" : undefined}>
                    <textarea name="parameters" rows={2} spellCheck={false} defaultValue={paramText} />
                  </Field>
                  <MoreFields expanded={!!s.Capabilities?.length}>
                    <Capabilities checked={s.Capabilities} />
                    <Field label="Service role" rule={UpdateStackRules.RoleARN} format="arn">
                      <input name="role" defaultValue={s.RoleARN} />
                    </Field>
                    <label className="check">
                      <input type="checkbox" name="disableRollback" /> Preserve resources on failure
                    </label>
                  </MoreFields>
                </ActionForm>
              </Sheet>
            )}
            {(updatable || status === "REVIEW_IN_PROGRESS") && <CreateChangeSet stack={title} template={template} parameters={paramText} previous={shown} taken={changeSets.map((c) => c.ChangeSetName!)} />}
            {updatable && <ActionForm action={detectDrift.bind(null, title)} submit="Detect drift" icon={<Radar size={16} />} testId="detect-drift" />}
            {!busy && (
              <ActionForm
                action={setTerminationProtection.bind(null, title, !protectedStack)}
                submit={protectedStack ? "Turn off termination protection" : "Turn on termination protection"}
                icon={protectedStack ? <ShieldOff size={16} /> : <ShieldCheck size={16} />}
                testId="termination-protection"
              />
            )}
            {!protectedStack && status === "DELETE_FAILED" && (
              <Sheet title="Delete stack" label="Delete stack" icon={<Trash2 size={16} />} testId="delete-stack">
                <ActionForm action={deleteStack.bind(null, title)} submit="Delete stack" tone="danger" testId="delete-stack">
                  {failedResources.length > 0 && (
                    <fieldset className="checks">
                      <legend>Resources to retain</legend>
                      {failedResources.map((r) => (
                        <label key={r.LogicalResourceId} className="check">
                          <input type="checkbox" name="retain" value={r.LogicalResourceId} defaultChecked /> {r.LogicalResourceId}
                        </label>
                      ))}
                    </fieldset>
                  )}
                </ActionForm>
              </Sheet>
            )}
            {!protectedStack && !busy && status !== "DELETE_FAILED" && (
              <ActionForm action={deleteStack.bind(null, title)} submit="Delete stack" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${title} and its resources?`} testId="delete-stack" />
            )}
          </>
        )
      }
    >
      <Specs
        items={[
          { label: "Status", icon: <AwsIcon icon={ICONS.cloudformation} size={16} />, value: <Status tone={stackTone(status)}>{word(status)}</Status> },
          { label: "Resources", icon: <Layers size={15} />, value: resources.length },
          s.DriftInformation?.StackDriftStatus === "DRIFTED" && { label: "Drift", icon: <Radar size={15} />, value: <Status tone="warn">drifted</Status> },
          protectedStack && { label: "Termination protection", icon: <ShieldCheck size={15} />, value: "Protected" },
          s.ParentId && { label: "Parent stack", icon: <AwsIcon icon={ICONS.stack} size={16} />, value: <Link href={stackLink(s.ParentId)}>{stackName(s.ParentId)}</Link> },
          { label: "Updated", icon: <Clock size={15} />, value: ago(s.LastUpdatedTime ?? s.CreationTime) },
        ]}
      />
      {s.StackStatusReason && <div className={`banner${stackTone(status) === "bad" ? " error" : ""}`}>{s.StackStatusReason}</div>}
      {pending.length > 0 && tab !== "changesets" && (
        <div className="banner">
          {status === "REVIEW_IN_PROGRESS" ? "This stack waits for a change set to be executed: " : "Change sets ready to execute: "}
          {pending.map((c, i) => (
            <span key={c.ChangeSetId}>
              {i > 0 && ", "}
              <Link href={`/cloudformation/changeset?stack=${enc(title)}&name=${enc(c.ChangeSetName!)}`}>{c.ChangeSetName}</Link>
            </span>
          ))}
        </div>
      )}
      <Segments
        items={[
          { label: "Stack info", href: `${base}&tab=info`, active: tab === "info" },
          { label: "Events", href: `${base}&tab=events`, active: tab === "events" },
          { label: "Resources", href: base, active: tab === "resources", count: resources.length },
          { label: "Outputs", href: `${base}&tab=outputs`, active: tab === "outputs", count: s.Outputs?.length || undefined },
          { label: "Parameters", href: `${base}&tab=parameters`, active: tab === "parameters", count: s.Parameters?.length || undefined },
          { label: "Template", href: `${base}&tab=template`, active: tab === "template" },
          { label: "Change sets", href: `${base}&tab=changesets`, active: tab === "changesets", count: changeSets.length || undefined },
          { label: "Drift", href: `${base}&tab=drift`, active: tab === "drift" },
        ]}
      />
      {body}
      <Tags tags={s.Tags} />
    </Page>
  );
}
