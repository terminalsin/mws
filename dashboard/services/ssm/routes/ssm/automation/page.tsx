import { DescribeAutomationExecutionsCommand } from "@aws-sdk/client-ssm";
import { ago, load } from "@mws-dashboard/aws";
import { AwsIcon, Empty, ErrorNotice, List, More, Page, Pill, Status } from "@mws-dashboard/ui";
import { Play } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, ssm } from "../../../lib/clients";
import { SsmNav } from "../../../lib/nav";
import { tone, words } from "../../../lib/status";

export const metadata: Metadata = { title: "Automation" };

type Props = { searchParams: Promise<{ token?: string }> };

export default async function Automation({ searchParams }: Props) {
  const { token } = await searchParams;
  const page = await load(async () => (await ssm()).send(new DescribeAutomationExecutionsCommand({ MaxResults: 50, NextToken: token })));
  const start = (
    <Link className="icon-button primary" href="/ssm/automation/start" aria-label="Execute automation" title="Execute automation" data-testid="start-automation">
      <Play size={16} />
    </Link>
  );
  if (!page.ok) {
    return (
      <Page title="Automation" icon={ICONS.ssm} actions={start}>
        <SsmNav active="automation" />
        <ErrorNotice error={page.error} />
      </Page>
    );
  }
  const runs = page.value.AutomationExecutionMetadataList ?? [];
  return (
    <Page title="Automation" icon={ICONS.ssm} actions={start}>
      <SsmNav active="automation" />
      <List
        label="Executions"
        empty={<Empty icon={ICONS.automation} action={start} />}
        rows={runs.map((r) => ({
          key: r.AutomationExecutionId!,
          icon: <AwsIcon icon={ICONS.automation} size={24} />,
          title: r.DocumentName,
          subtitle: [r.AutomationExecutionId, r.CurrentStepName && `at ${r.CurrentStepName}`, r.FailureMessage, r.ExecutedBy?.split("/").pop()].filter(Boolean).join(" · "),
          href: `/ssm/automation/execution?id=${r.AutomationExecutionId}`,
          meta: (
            <>
              {r.Mode === "Interactive" && <Pill>interactive</Pill>}
              {r.ParentAutomationExecutionId && <Pill>child</Pill>}
              {r.AutomationType === "CrossAccount" && <Pill>multi-account</Pill>}
              <span>{ago(r.ExecutionStartTime)}</span>
              <Status tone={tone(r.AutomationExecutionStatus)}>{words(r.AutomationExecutionStatus)}</Status>
            </>
          ),
        }))}
      />
      <More shown={runs.length} noun="executions" href={page.value.NextToken ? `/ssm/automation?token=${encodeURIComponent(page.value.NextToken)}` : undefined} />
    </Page>
  );
}
