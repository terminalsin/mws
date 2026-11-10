import { ListCommandsCommand } from "@aws-sdk/client-ssm";
import { ago, load } from "@mws-dashboard/aws";
import { AwsIcon, Empty, ErrorNotice, List, More, Page, Pill, Status } from "@mws-dashboard/ui";
import { Plus } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, ssm } from "../../../lib/clients";
import { SsmNav } from "../../../lib/nav";
import { targetsText, tone, words } from "../../../lib/status";

export const metadata: Metadata = { title: "Run Command" };

type Props = { searchParams: Promise<{ token?: string }> };

export default async function Commands({ searchParams }: Props) {
  const { token } = await searchParams;
  const page = await load(async () => (await ssm()).send(new ListCommandsCommand({ MaxResults: 50, NextToken: token })));
  const run = (
    <Link className="icon-button primary" href="/ssm/commands/send" aria-label="Run command" title="Run command" data-testid="run-command">
      <Plus size={16} />
    </Link>
  );
  if (!page.ok) {
    return (
      <Page title="Run Command" icon={ICONS.ssm} actions={run}>
        <SsmNav active="commands" />
        <ErrorNotice error={page.error} />
      </Page>
    );
  }
  const commands = page.value.Commands ?? [];
  return (
    <Page title="Run Command" icon={ICONS.ssm} actions={run}>
      <SsmNav active="commands" />
      <List
        label="Commands"
        empty={<Empty icon={ICONS.runCommand} action={run} />}
        rows={commands.map((c) => ({
          key: c.CommandId!,
          icon: <AwsIcon icon={ICONS.runCommand} size={24} />,
          title: c.Comment || c.DocumentName,
          subtitle: [c.Comment ? c.DocumentName : null, c.InstanceIds?.length ? c.InstanceIds.join(", ") : targetsText(c.Targets), c.CommandId].filter(Boolean).join(" · "),
          href: `/ssm/command?id=${c.CommandId}`,
          meta: (
            <>
              {(c.ErrorCount ?? 0) > 0 && <Pill tone="bad">{c.ErrorCount} failed</Pill>}
              <span title="Completed">
                {c.CompletedCount ?? 0}/{c.TargetCount ?? 0}
              </span>
              <span>{ago(c.RequestedDateTime)}</span>
              <Status tone={tone(c.Status)}>{words(c.Status)}</Status>
            </>
          ),
        }))}
      />
      <More shown={commands.length} noun="commands" href={page.value.NextToken ? `/ssm/commands?token=${encodeURIComponent(page.value.NextToken)}` : undefined} />
    </Page>
  );
}
