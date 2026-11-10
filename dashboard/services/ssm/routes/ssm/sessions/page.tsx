import { DescribeSessionsCommand } from "@aws-sdk/client-ssm";
import { ago, all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, List, Page, Pill, Segments, Status } from "@mws-dashboard/ui";
import { XCircle } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, ssm } from "../../../lib/clients";
import { SsmNav } from "../../../lib/nav";
import { tone, words } from "../../../lib/status";
import { terminate } from "./actions";

export const metadata: Metadata = { title: "Session Manager" };

type Props = { searchParams: Promise<{ state?: string }> };

export default async function Sessions({ searchParams }: Props) {
  const { state = "Active" } = await searchParams;
  const State = state === "History" ? "History" : "Active";
  const c = await ssm();
  const list = await load(() => all((NextToken) => c.send(new DescribeSessionsCommand({ State, NextToken, MaxResults: 200 })), (r) => r.Sessions, (r) => r.NextToken));
  return (
    <Page title="Session Manager" icon={ICONS.ssm}>
      <SsmNav active="sessions" />
      <Segments
        label="Sessions"
        items={[
          { label: "Sessions", href: "/ssm/sessions", active: State === "Active" },
          { label: "Session history", href: "/ssm/sessions?state=History", active: State === "History" },
        ]}
      />
      {list.ok ? (
        <List
          label="Sessions"
          empty={<Empty icon={ICONS.session}>{State === "Active" ? "No active sessions; aws ssm start-session opens one" : "No sessions yet"}</Empty>}
          rows={list.value.map((s) => ({
            key: s.SessionId!,
            icon: <AwsIcon icon={ICONS.session} size={24} />,
            title: s.SessionId,
            subtitle: [s.Target, s.DocumentName, s.Owner?.split("/").pop(), s.Reason, s.EndDate && s.StartDate ? `${Math.round((s.EndDate.getTime() - s.StartDate.getTime()) / 1000)}s` : null].filter(Boolean).join(" · "),
            href: s.Target?.startsWith("i-") || s.Target?.startsWith("mi-") ? `/ssm/node?id=${encodeURIComponent(s.Target)}&tab=sessions` : undefined,
            meta: (
              <>
                {s.MaxSessionDuration && <Pill>max {s.MaxSessionDuration}m</Pill>}
                <span>{ago(s.StartDate)}</span>
                <Status tone={tone(s.Status)}>{words(s.Status)}</Status>
              </>
            ),
            actions: State === "Active" && s.Status !== "Terminating" ? <ActionForm action={terminate.bind(null, s.SessionId!)} submit={`Terminate ${s.SessionId}`} icon={<XCircle size={15} />} tone="danger" confirm="Terminate this session?" /> : undefined,
          }))}
        />
      ) : (
        <ErrorNotice error={list.error} />
      )}
    </Page>
  );
}
