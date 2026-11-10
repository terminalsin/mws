import { ListAcceleratorsCommand, ListCustomRoutingAcceleratorsCommand } from "@aws-sdk/client-global-accelerator";
import { all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Section, Sheet, Status } from "@mws-dashboard/ui";
import { CreateAccelerator } from "@mws-dashboard/ui/model/global-accelerator";
import { MoreFields } from "@mws-dashboard/ui/presets";
import type { Metadata } from "next";

import { ICONS, acceleratorHref, acceleratorState, ga } from "../../lib/clients";
import { NAME, nextName } from "../../lib/rules";
import { createAccelerator } from "./actions";

export const metadata: Metadata = { title: "Global Accelerator" };

export default async function Accelerators() {
  const client = await ga();
  const [list, custom] = await Promise.all([
    load(() =>
      all(
        (NextToken) => client.send(new ListAcceleratorsCommand({ NextToken })),
        (r) => r.Accelerators,
        (r) => r.NextToken,
      ),
    ),
    load(() =>
      all(
        (NextToken) => client.send(new ListCustomRoutingAcceleratorsCommand({ NextToken })),
        (r) => r.Accelerators,
        (r) => r.NextToken,
      ),
    ),
  ]);
  const names = [...(list.ok ? list.value : []), ...(custom.ok ? custom.value : [])].map((a) => a.Name!).filter(Boolean);
  const create = (
    <Sheet title="Create accelerator" label="Create accelerator" testId="create-accelerator">
      <ActionForm action={createAccelerator} submit="Create" testId="create-accelerator">
        <Field label="Name" rule={NAME} generate="name" taken={names} unique>
          <input name="name" required autoFocus defaultValue={nextName("accelerator", names)} />
        </Field>
        <MoreFields>
          <Field label="IP address type" rule={CreateAccelerator.IpAddressType}>
            <select name="ip" defaultValue="IPV4">
              <option value="IPV4">IPv4</option>
              <option value="DUAL_STACK">Dual-stack</option>
            </select>
          </Field>
        </MoreFields>
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
            href: acceleratorHref(a.AcceleratorArn),
            meta: (
              <>
                {a.IpSets?.flatMap((s) => s.IpAddresses ?? []).map((ip) => <Pill key={ip}>{ip}</Pill>)}
                <Status tone={acceleratorState(a).tone}>{acceleratorState(a).word}</Status>
              </>
            ),
          }))}
        />
      ) : (
        <ErrorNotice error={list.error} />
      )}
      {custom.ok && custom.value.length > 0 && (
        <Section title="Custom routing accelerators" count={custom.value.length} plain>
          <List
            label="Custom routing accelerators"
            rows={custom.value.map((a) => ({
              key: a.AcceleratorArn!,
              icon: <AwsIcon icon={ICONS.ga} size={24} />,
              title: a.Name,
              subtitle: <code className="clip">{a.DnsName}</code>,
              meta: (
                <>
                  {a.IpSets?.flatMap((s) => s.IpAddresses ?? []).map((ip) => <Pill key={ip}>{ip}</Pill>)}
                  <Status tone={acceleratorState(a).tone}>{acceleratorState(a).word}</Status>
                </>
              ),
            }))}
          />
        </Section>
      )}
    </Page>
  );
}
