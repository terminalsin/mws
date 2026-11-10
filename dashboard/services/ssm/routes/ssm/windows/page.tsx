import { DescribeMaintenanceWindowsCommand } from "@aws-sdk/client-ssm";
import { all, load, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, List, Page, Pill, Sheet, Status } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { ICONS, ssm } from "../../../lib/clients";
import { SsmNav } from "../../../lib/nav";
import { createWindow } from "./actions";
import { WindowFields } from "./fields";

export const metadata: Metadata = { title: "Maintenance Windows" };

export default async function Windows() {
  const c = await ssm();
  const list = await load(() => all((NextToken) => c.send(new DescribeMaintenanceWindowsCommand({ NextToken, MaxResults: 50 })), (r) => r.WindowIdentities, (r) => r.NextToken));
  const create = (
    <Sheet title="Create maintenance window" label="Create maintenance window" testId="create-window">
      <ActionForm action={createWindow} submit="Create" testId="create-window">
        <WindowFields taken={list.ok ? list.value.map((w) => w.Name!) : []} />
      </ActionForm>
    </Sheet>
  );
  return (
    <Page title="Maintenance Windows" icon={ICONS.ssm} actions={create}>
      <SsmNav active="windows" />
      {list.ok ? (
        <List
          label="Maintenance windows"
          empty={<Empty icon={ICONS.window} action={create} />}
          rows={list.value.map((w) => ({
            key: w.WindowId!,
            icon: <AwsIcon icon={ICONS.window} size={24} />,
            title: w.Name,
            subtitle: [w.Schedule, w.ScheduleTimezone, `${w.Duration}h`].filter(Boolean).join(" · "),
            href: `/ssm/window?id=${w.WindowId}`,
            meta: (
              <>
                {w.Enabled && w.NextExecutionTime && <Pill tone="info">next {when(w.NextExecutionTime)}</Pill>}
                <Status tone={w.Enabled ? "good" : "neutral"}>{w.Enabled ? "Enabled" : "Disabled"}</Status>
              </>
            ),
          }))}
        />
      ) : (
        <ErrorNotice error={list.error} />
      )}
    </Page>
  );
}
