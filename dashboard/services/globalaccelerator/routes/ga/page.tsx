import { ListAcceleratorsCommand } from "@aws-sdk/client-global-accelerator";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Sheet, Status } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { ICONS, ga } from "../../lib/clients";
import { createAccelerator } from "./actions";

export const metadata: Metadata = { title: "Global Accelerator" };

export default async function Accelerators() {
  const list = await load(async () => (await (await ga()).send(new ListAcceleratorsCommand({}))).Accelerators ?? []);
  const create = (
    <Sheet title="Create accelerator" label="Create accelerator" testId="create-accelerator">
      <ActionForm action={createAccelerator} submit="Create" testId="create-accelerator">
        <Field label="Name">
          <input name="name" required maxLength={64} autoFocus />
        </Field>
        <Field label="IP address type">
          <select name="ip" defaultValue="IPV4">
            <option value="IPV4">IPv4</option>
            <option value="DUAL_STACK">Dual-stack</option>
          </select>
        </Field>
      </ActionForm>
    </Sheet>
  );
  return (
    <Page title="Accelerators" actions={create}>
      {list.ok ? (
        <List
          label="Accelerators"
          empty={<Empty icon={ICONS.ga} action={create} />}
          rows={list.value.map((a) => ({
            key: a.AcceleratorArn!,
            icon: <AwsIcon icon={ICONS.ga} size={24} />,
            title: a.Name,
            subtitle: <code className="clip">{a.DnsName}</code>,
            href: `/ga/accelerator?arn=${encodeURIComponent(a.AcceleratorArn!)}`,
            meta: (
              <>
                {a.IpSets?.flatMap((s) => s.IpAddresses ?? []).slice(0, 2).map((ip) => <Pill key={ip}>{ip}</Pill>)}
                <Status tone={!a.Enabled ? "neutral" : a.Status === "DEPLOYED" ? "good" : "warn"}>{!a.Enabled ? "Disabled" : a.Status === "DEPLOYED" ? "Deployed" : "In progress"}</Status>
                <span>{ago(a.CreatedTime)}</span>
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
