import { DescribeAcceleratorCommand, ListEndpointGroupsCommand, ListListenersCommand } from "@aws-sdk/client-global-accelerator";
import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, ErrorNotice, Field, List, Page, Pill, Section, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { Globe, MapPin, Pause, Play, Plus, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, ga } from "../../../lib/clients";
import { addEndpointGroup, addListener, deleteAccelerator, deleteEndpointGroup, deleteListener, setEnabled } from "../actions";

export const metadata: Metadata = { title: "Accelerator" };

type Props = { searchParams: Promise<{ arn?: string }> };

const REGIONS = ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-northeast-1"];

export default async function Accelerator({ searchParams }: Props) {
  const { arn = "" } = await searchParams;
  const back = { href: "/ga", label: "Accelerators" };
  const data = await load(async () => {
    const client = await ga();
    const [a, listeners] = await Promise.all([
      client.send(new DescribeAcceleratorCommand({ AcceleratorArn: arn })).then((r) => r.Accelerator!),
      client.send(new ListListenersCommand({ AcceleratorArn: arn })).then((r) => r.Listeners ?? []),
    ]);
    const groups = await Promise.all(listeners.map((l) => client.send(new ListEndpointGroupsCommand({ ListenerArn: l.ListenerArn })).then((r) => r.EndpointGroups ?? [])));
    return { a, listeners, groups };
  });
  if (!data.ok) {
    return (
      <Page title="Accelerator" icon={ICONS.ga} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { a, listeners, groups } = data.value;
  return (
    <Page
      title={a.Name}
      icon={ICONS.ga}
      back={back}
      subtitle={arn}
      actions={
        <>
          <Sheet title="Add listener" label="Add listener" icon={<Plus size={16} />} testId="add-ga-listener">
            <ActionForm action={addListener.bind(null, arn)} submit="Add listener" testId="add-ga-listener">
              <div className="form-row">
                <Field label="Ports">
                  <input name="ports" required defaultValue="80" placeholder="80 or 8000-8100" />
                </Field>
                <Field label="Protocol">
                  <select name="protocol" defaultValue="TCP">
                    <option>TCP</option>
                    <option>UDP</option>
                  </select>
                </Field>
              </div>
            </ActionForm>
          </Sheet>
          {a.Enabled ? (
            <ActionForm action={setEnabled.bind(null, arn, false)} submit="Disable accelerator" icon={<Pause size={16} />} />
          ) : (
            <>
              <ActionForm action={setEnabled.bind(null, arn, true)} submit="Enable accelerator" icon={<Play size={16} />} />
              <ActionForm action={deleteAccelerator.bind(null, arn)} submit="Delete accelerator" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${a.Name}?`} testId="delete-accelerator" />
            </>
          )}
        </>
      }
    >
      <Specs
        items={[
          { label: "Status", icon: <Globe size={15} />, value: <Status tone={!a.Enabled ? "neutral" : a.Status === "DEPLOYED" ? "good" : "warn"}>{!a.Enabled ? "Disabled" : a.Status === "DEPLOYED" ? "Deployed" : "In progress"}</Status> },
          ...(a.IpSets ?? []).flatMap((s) => (s.IpAddresses ?? []).map((ip) => ({ label: `Static IP (${s.IpAddressFamily ?? s.IpFamily})`, icon: <MapPin size={15} />, value: ip }))),
        ]}
      />
      <CodeBlock value={a.DnsName} label="DNS name" />
      {listeners.map((l, i) => (
        <Section
          key={l.ListenerArn}
          title={`${l.Protocol} ${l.PortRanges?.map((p) => (p.FromPort === p.ToPort ? p.FromPort : `${p.FromPort}-${p.ToPort}`)).join(", ")}`}
          plain
          actions={
            <>
              <Sheet title="Add endpoint group" label={`Add endpoint group to ${l.Protocol} listener`} icon={<Plus size={16} />} testId={`add-endpoint-group-${i}`}>
                <ActionForm action={addEndpointGroup.bind(null, l.ListenerArn!)} submit="Add endpoint group" testId={`add-endpoint-group-${i}`}>
                  <Field label="Region">
                    <select name="region" defaultValue="us-east-1">
                      {REGIONS.map((r) => (
                        <option key={r}>{r}</option>
                      ))}
                    </select>
                  </Field>
                  <Field label="Endpoint (load balancer ARN, instance id or EIP allocation)">
                    <input name="endpoint" />
                  </Field>
                </ActionForm>
              </Sheet>
              <ActionForm action={deleteListener.bind(null, l.ListenerArn!)} submit="Delete listener" icon={<Trash2 size={16} />} tone="danger" confirm="Delete this listener?" />
            </>
          }
        >
          <List
            label="Endpoint groups"
            empty={<div className="empty">No endpoint groups</div>}
            rows={groups[i].map((g) => ({
              key: g.EndpointGroupArn!,
              icon: <AwsIcon icon="group/Region" size={22} />,
              title: g.EndpointGroupRegion,
              subtitle: g.EndpointDescriptions?.map((e) => e.EndpointId?.split("/").slice(-2, -1)[0] ?? e.EndpointId).join(", "),
              meta: (
                <>
                  <Pill title="Traffic dial">{g.TrafficDialPercentage ?? 100}%</Pill>
                  {g.EndpointDescriptions?.map((e) => (
                    <Status key={e.EndpointId} tone={e.HealthState === "HEALTHY" ? "good" : e.HealthState === "UNHEALTHY" ? "bad" : "neutral"}>
                      {e.HealthState?.toLowerCase() ?? "initial"}
                    </Status>
                  ))}
                </>
              ),
              actions: <ActionForm action={deleteEndpointGroup.bind(null, g.EndpointGroupArn!)} submit={`Delete endpoint group ${g.EndpointGroupRegion}`} icon={<Trash2 size={15} />} tone="danger" />,
            }))}
          />
        </Section>
      ))}
    </Page>
  );
}
