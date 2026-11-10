import { ListCommandInvocationsCommand, ListCommandsCommand } from "@aws-sdk/client-ssm";
import { ago, all, load, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Facts, Page, Pill, Section, Status } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { Ban, RotateCw } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, ssm } from "../../../lib/clients";
import { RUNNING, targetsText, tone, words } from "../../../lib/status";
import { cancelCommand, rerun } from "../commands/actions";

export const metadata: Metadata = { title: "Command" };

type Props = { searchParams: Promise<{ id?: string }> };

export default async function Command({ searchParams }: Props) {
  const { id = "" } = await searchParams;
  const back = { href: "/ssm/commands", label: "Run Command" };
  const data = await load(async () => {
    const c = await ssm();
    const [cmd, invocations] = await Promise.all([
      c.send(new ListCommandsCommand({ CommandId: id })).then((r) => r.Commands?.[0]),
      all((NextToken) => c.send(new ListCommandInvocationsCommand({ CommandId: id, Details: true, NextToken })), (r) => r.CommandInvocations, (r) => r.NextToken),
    ]);
    if (!cmd) throw new Error(`InvalidCommandId: ${id}`);
    return { cmd, invocations };
  });
  if (!data.ok) {
    return (
      <Page title="Command" icon={ICONS.runCommand} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { cmd, invocations } = data.value;
  const running = RUNNING.has(cmd.Status ?? "") || invocations.some((i) => RUNNING.has(i.Status ?? ""));
  return (
    <Page
      title={cmd.Comment || cmd.DocumentName}
      icon={ICONS.runCommand}
      back={back}
      subtitle={cmd.CommandId}
      actions={
        <>
          {running && <ActionForm action={cancelCommand.bind(null, id, undefined)} submit="Cancel command" icon={<Ban size={16} />} tone="danger" confirm="Cancel this command?" testId="cancel-command" />}
          <ActionForm
            action={rerun.bind(null, id, {
              DocumentName: cmd.DocumentName!,
              DocumentVersion: cmd.DocumentVersion,
              Parameters: cmd.Parameters,
              InstanceIds: cmd.InstanceIds,
              Targets: cmd.Targets,
              Comment: cmd.Comment,
              TimeoutSeconds: cmd.TimeoutSeconds,
            })}
            submit="Rerun"
            icon={<RotateCw size={16} />}
          />
        </>
      }
    >
      {running && <LiveRefresh />}
      <Facts
        items={[
          ["Status", <Status key="s" tone={tone(cmd.Status)}>{words(cmd.StatusDetails ?? cmd.Status)}</Status>],
          ["Document", <Link key="d" href={`/ssm/document?name=${encodeURIComponent(cmd.DocumentName!)}`}>{cmd.DocumentName}{cmd.DocumentVersion && cmd.DocumentVersion !== "$DEFAULT" ? ` v${cmd.DocumentVersion}` : ""}</Link>],
          ["Targets", cmd.InstanceIds?.length ? cmd.InstanceIds.join(", ") : targetsText(cmd.Targets)],
          ["Progress", `${cmd.CompletedCount ?? 0} of ${cmd.TargetCount ?? 0}${cmd.ErrorCount ? `, ${cmd.ErrorCount} failed` : ""}${cmd.DeliveryTimedOutCount ? `, ${cmd.DeliveryTimedOutCount} undelivered` : ""}`],
          ["Requested", when(cmd.RequestedDateTime)],
          cmd.TimeoutSeconds && ["Timeout", `${cmd.TimeoutSeconds}s`],
          cmd.MaxConcurrency && ["Concurrency", `${cmd.MaxConcurrency}, error threshold ${cmd.MaxErrors}`],
        ]}
      />
      {cmd.Parameters && Object.keys(cmd.Parameters).length > 0 && (
        <details>
          <summary>Parameters</summary>
          <CodeBlock value={JSON.stringify(cmd.Parameters)} label="Parameters" />
        </details>
      )}
      {invocations.length === 0 && <Empty icon={ICONS.node}>No node matched the targets</Empty>}
      {invocations.map((inv) => (
        <Section
          key={inv.InstanceId}
          title={
            <Link href={`/ssm/node?id=${encodeURIComponent(inv.InstanceId!)}`}>
              <AwsIcon icon={ICONS.node} size={16} /> {inv.InstanceName || inv.InstanceId}
            </Link>
          }
          actions={
            <>
              <Status tone={tone(inv.Status)}>{words(inv.StatusDetails ?? inv.Status)}</Status>
              {RUNNING.has(inv.Status ?? "") && <ActionForm action={cancelCommand.bind(null, id, inv.InstanceId)} submit={`Cancel on ${inv.InstanceId}`} icon={<Ban size={15} />} tone="danger" />}
            </>
          }
        >
          {(inv.CommandPlugins ?? []).map((p) => (
            <div key={p.Name} className="plugin-output" data-testid="command-output">
              <Facts
                items={[
                  ["Step", p.Name],
                  ["Status", <Pill key="s" tone={tone(p.Status)}>{words(p.StatusDetails ?? p.Status)}</Pill>],
                  p.ResponseCode !== undefined && p.ResponseCode !== -1 && ["Exit code", <code key="e" className={p.ResponseCode ? "tone-bad" : undefined}>{p.ResponseCode}</code>],
                  p.ResponseStartDateTime && ["Started", ago(p.ResponseStartDateTime)],
                  p.ResponseFinishDateTime && p.ResponseStartDateTime && ["Took", `${Math.max(0, (p.ResponseFinishDateTime.getTime() - p.ResponseStartDateTime.getTime()) / 1000).toFixed(1)}s`],
                ]}
              />
              {p.Output ? <pre className="code" aria-label={`Output of ${p.Name} on ${inv.InstanceId}`}>{p.Output}</pre> : null}
            </div>
          ))}
          {!inv.CommandPlugins?.length && inv.TraceOutput && <pre className="code">{inv.TraceOutput}</pre>}
        </Section>
      ))}
    </Page>
  );
}
