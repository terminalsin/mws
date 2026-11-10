import { GetAutomationExecutionCommand } from "@aws-sdk/client-ssm";
import { ago, load, when } from "@mws-dashboard/aws";
import { ActionForm, CodeBlock, ErrorNotice, Facts, Field, List, Page, Pill, Section, Sheet, Status } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { Ban, Check, CircleCheckBig, Play, SkipForward, X } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, ssm } from "../../../../lib/clients";
import { RUNNING, targetsText, tone, words } from "../../../../lib/status";
import { signal, stopAutomation } from "../actions";

export const metadata: Metadata = { title: "Automation execution" };

type Props = { searchParams: Promise<{ id?: string }> };

const DONE = new Set(["Success", "Failed", "TimedOut", "Cancelled", "CompletedWithSuccess", "CompletedWithFailure", "Rejected", "Exited"]);

export default async function Execution({ searchParams }: Props) {
  const { id = "" } = await searchParams;
  const back = { href: "/ssm/automation", label: "Automation" };
  const data = await load(async () => (await (await ssm()).send(new GetAutomationExecutionCommand({ AutomationExecutionId: id }))).AutomationExecution!);
  if (!data.ok) {
    return (
      <Page title="Execution" icon={ICONS.automation} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const x = data.value;
  const status = x.AutomationExecutionStatus ?? "";
  const done = DONE.has(status);
  const steps = x.StepExecutions ?? [];
  const waiting = steps.find((s) => s.StepStatus === "Waiting" || s.StepStatus === "Pending" && status === "Waiting");
  const approval = waiting?.Action === "aws:approve" || status === "PendingApproval";
  const paused = waiting?.Action === "aws:pause";
  const interactive = x.Mode === "Interactive";
  const nextPending = interactive ? steps.find((s) => s.StepStatus === "Pending") : undefined;
  const comment = (
    <Field label="Comment">
      <input name="comment" />
    </Field>
  );
  return (
    <Page
      title={x.DocumentName}
      icon={ICONS.automation}
      back={back}
      subtitle={x.AutomationExecutionId}
      actions={
        !done && (
          <>
            {approval && (
              <>
                <Sheet title="Approve" label="Approve" icon={<Check size={16} />} testId="approve">
                  <ActionForm action={signal.bind(null, id, "Approve", undefined)} submit="Approve" testId="approve">
                    {comment}
                  </ActionForm>
                </Sheet>
                <Sheet title="Reject" label="Reject" icon={<X size={16} />} testId="reject">
                  <ActionForm action={signal.bind(null, id, "Reject", undefined)} submit="Reject" tone="danger" testId="reject">
                    {comment}
                  </ActionForm>
                </Sheet>
              </>
            )}
            {paused && <ActionForm action={signal.bind(null, id, "Resume", undefined)} submit="Resume" icon={<Play size={16} />} testId="resume" />}
            {nextPending && <ActionForm action={signal.bind(null, id, "StartStep", nextPending.StepName)} submit={`Run step ${nextPending.StepName}`} icon={<SkipForward size={16} />} testId="start-step" />}
            <ActionForm action={stopAutomation.bind(null, id, "Cancel")} submit="Cancel execution" icon={<Ban size={16} />} tone="danger" confirm="Cancel this execution?" testId="cancel-automation" />
            {interactive && <ActionForm action={stopAutomation.bind(null, id, "Complete")} submit="Complete execution" icon={<CircleCheckBig size={16} />} />}
          </>
        )
      }
    >
      {(RUNNING.has(status) || status === "Waiting" || status === "PendingApproval") && <LiveRefresh />}
      <Facts
        items={[
          ["Status", <Status key="s" tone={tone(status)}>{words(status)}</Status>],
          ["Runbook", <Link key="d" href={`/ssm/document?name=${encodeURIComponent(x.DocumentName!)}`}>{x.DocumentName}{x.DocumentVersion ? ` v${x.DocumentVersion}` : ""}</Link>],
          x.FailureMessage && ["Failure", <span key="f" className="tone-bad">{x.FailureMessage}</span>],
          x.CurrentStepName && !done && ["Current step", `${x.CurrentStepName} (${x.CurrentAction})`],
          ["Started", when(x.ExecutionStartTime)],
          x.ExecutionEndTime && ["Ended", when(x.ExecutionEndTime)],
          ["Executed by", x.ExecutedBy?.split("/").pop()],
          x.Mode === "Interactive" && ["Mode", "Manual"],
          x.ParentAutomationExecutionId && ["Parent", <Link key="p" href={`/ssm/automation/execution?id=${x.ParentAutomationExecutionId}`}>{x.ParentAutomationExecutionId}</Link>],
          x.Targets?.length && ["Targets", targetsText(x.Targets)],
          x.ProgressCounters && ["Progress", `${x.ProgressCounters.SuccessSteps ?? 0} succeeded, ${x.ProgressCounters.FailedSteps ?? 0} failed of ${x.ProgressCounters.TotalSteps ?? 0}`],
          x.OpsItemId && ["OpsItem", <Link key="o" href={`/ssm/opsitem?id=${x.OpsItemId}`}>{x.OpsItemId}</Link>],
        ]}
      />
      <Section title="Steps" count={steps.length} plain>
        <List
          label="Steps"
          rows={steps.map((s, i) => ({
            key: s.StepExecutionId ?? String(i),
            icon: <span className="pill">{i + 1}</span>,
            title: s.StepName,
            subtitle: [s.Action, s.FailureMessage, s.ExecutionStartTime ? ago(s.ExecutionStartTime) : null, s.ExecutionEndTime && s.ExecutionStartTime ? `${((s.ExecutionEndTime.getTime() - s.ExecutionStartTime.getTime()) / 1000).toFixed(1)}s` : null]
              .filter(Boolean)
              .join(" · "),
            meta: (
              <>
                {s.IsCritical === false && <Pill>non-critical</Pill>}
                {s.Outputs && Object.keys(s.Outputs).length > 0 && <Pill>{Object.keys(s.Outputs).length} outputs</Pill>}
                <Status tone={tone(s.StepStatus)}>{words(s.StepStatus)}</Status>
              </>
            ),
          }))}
        />
      </Section>
      {steps
        .filter((s) => s.Outputs && Object.keys(s.Outputs).length)
        .map((s) => (
          <details key={s.StepExecutionId}>
            <summary>Outputs of {s.StepName}</summary>
            <CodeBlock value={JSON.stringify(s.Outputs)} label={`Outputs of ${s.StepName}`} />
          </details>
        ))}
      {x.Parameters && Object.keys(x.Parameters).length > 0 && (
        <details>
          <summary>Input parameters</summary>
          <CodeBlock value={JSON.stringify(x.Parameters)} label="Input parameters" />
        </details>
      )}
      {x.Outputs && Object.keys(x.Outputs).length > 0 && (
        <Section title="Outputs">
          <CodeBlock value={JSON.stringify(x.Outputs)} label="Outputs" />
        </Section>
      )}
    </Page>
  );
}
