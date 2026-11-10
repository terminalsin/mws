import { DescribeAcceleratorAttributesCommand, DescribeAcceleratorCommand, ListEndpointGroupsCommand, ListListenersCommand, ListTagsForResourceCommand } from "@aws-sdk/client-global-accelerator";
import { all, load, region as currentRegion } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Field, List, Page, Pill, Section, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { FileText, Globe, MapPin, Pause, Pencil, Play, Plus, Tag, Trash2, X } from "lucide-react";
import { CreateAccelerator, TagResource, UpdateAcceleratorAttributes } from "@mws-dashboard/ui/model/global-accelerator";
import type { Metadata } from "next";

import { EndpointGroupFields, ListenerFields } from "../../../components/listener-fields.tsx";
import { ICONS, acceleratorState, endpointCandidates, endpointName, ga, groupHref, regions } from "../../../lib/clients";
import { ENDPOINTS, GROUP_RULES, NAME } from "../../../lib/rules";
import {
  addEndpointGroup,
  addListener,
  addTag,
  deleteAccelerator,
  deleteEndpointGroup,
  deleteListener,
  removeTag,
  setEnabled,
  updateAccelerator,
  updateFlowLogs,
  updateListener,
} from "../actions";

export const metadata: Metadata = { title: "Accelerator" };

type Props = { searchParams: Promise<{ arn?: string }> };

// Ports are 1-65535; several ranges are comma-separated.
const PORTS = { required: true, format: "portList" as const };

const range = (p: { FromPort?: number; ToPort?: number }) => (p.FromPort === p.ToPort ? `${p.FromPort}` : `${p.FromPort}-${p.ToPort}`);
const TAG = TagResource.Tags.item?.fields ?? {};

export default async function Accelerator({ searchParams }: Props) {
  const { arn = "" } = await searchParams;
  const back = { href: "/ga", label: "Accelerators" };
  const data = await load(async () => {
    const client = await ga();
    const [a, listeners, attributes, tags, here, all_regions] = await Promise.all([
      client.send(new DescribeAcceleratorCommand({ AcceleratorArn: arn })).then((r) => r.Accelerator!),
      all(
        (NextToken) => client.send(new ListListenersCommand({ AcceleratorArn: arn, NextToken })),
        (r) => r.Listeners,
        (r) => r.NextToken,
      ),
      client.send(new DescribeAcceleratorAttributesCommand({ AcceleratorArn: arn })).then((r) => r.AcceleratorAttributes, () => undefined),
      client.send(new ListTagsForResourceCommand({ ResourceArn: arn })).then((r) => r.Tags ?? [], () => []),
      currentRegion(),
      regions(),
    ]);
    const [groups, candidates] = await Promise.all([
      Promise.all(
        listeners.map((l) =>
          all(
            (NextToken) => client.send(new ListEndpointGroupsCommand({ ListenerArn: l.ListenerArn, NextToken })),
            (r) => r.EndpointGroups,
            (r) => r.NextToken,
          ),
        ),
      ),
      Promise.all(all_regions.map(async (r) => [r, await endpointCandidates(r)] as const)).then((e) => Object.fromEntries(e)),
    ]);
    return { a, listeners, groups, attributes, tags, here, regions: all_regions, candidates };
  });
  if (!data.ok) {
    return (
      <Page title="Accelerator" icon={ICONS.ga} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { a, listeners, groups, attributes, tags, here, regions: regionList, candidates } = data.value;
  const used = (protocol: string, except?: string) => listeners.filter((l) => l.Protocol === protocol && l.ListenerArn !== except).flatMap((l) => (l.PortRanges ?? []).map(range));
  const state = acceleratorState(a);
  const settling = groups.flat().some((g) => g.EndpointDescriptions?.some((e) => !e.HealthState || e.HealthState === "INITIAL"));
  // AWS deletes only a disabled, deployed accelerator without listeners.
  const deletable = !a.Enabled && a.Status === "DEPLOYED" && listeners.length === 0;
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
              <ListenerFields rule={PORTS} used={{ TCP: used("TCP"), UDP: used("UDP") }} />
            </ActionForm>
          </Sheet>
          <Sheet title="Edit accelerator" label="Edit accelerator" icon={<Pencil size={16} />} testId="edit-accelerator">
            <ActionForm action={updateAccelerator.bind(null, arn)} submit="Save" testId="edit-accelerator">
              <Field label="Name" rule={NAME}>
                <input name="name" required defaultValue={a.Name} />
              </Field>
              <Field label="IP address type" rule={CreateAccelerator.IpAddressType}>
                <select name="ip" defaultValue={a.IpAddressType}>
                  <option value="IPV4">IPv4</option>
                  <option value="DUAL_STACK">Dual-stack</option>
                </select>
              </Field>
            </ActionForm>
          </Sheet>
          {a.Enabled ? (
            <ActionForm action={setEnabled.bind(null, arn, false)} submit="Disable accelerator" icon={<Pause size={16} />} />
          ) : (
            <ActionForm action={setEnabled.bind(null, arn, true)} submit="Enable accelerator" icon={<Play size={16} />} />
          )}
          {deletable && <ActionForm action={deleteAccelerator.bind(null, arn)} submit="Delete accelerator" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${a.Name}?`} testId="delete-accelerator" />}
        </>
      }
    >
      {settling && <LiveRefresh />}
      <Specs
        items={[
          { label: "Status", icon: <Globe size={15} />, value: <Status tone={state.tone}>{state.word}</Status> },
          a.Enabled === false && a.Status !== "DEPLOYED" && { label: "Enabled", icon: <Pause size={15} />, value: "Disabled" },
          ...(a.IpSets ?? []).flatMap((s) => (s.IpAddresses ?? []).map((ip) => ({ label: `Static IP (${s.IpAddressFamily ?? s.IpFamily})`, icon: <MapPin size={15} />, value: ip }))),
          attributes?.FlowLogsEnabled && { label: "Flow logs", icon: <FileText size={15} />, value: `s3://${attributes.FlowLogsS3Bucket}/${attributes.FlowLogsS3Prefix ?? ""}` },
        ]}
      />
      <CodeBlock value={a.DnsName} label="DNS name" />
      {a.DualStackDnsName && <CodeBlock value={a.DualStackDnsName} label="Dual-stack DNS name" />}
      {listeners.map((l, i) => {
        const taken = new Set(groups[i].map((g) => g.EndpointGroupRegion));
        const free = regionList.filter((r) => !taken.has(r));
        return (
          <Section
            key={l.ListenerArn}
            title={`${l.Protocol} ${l.PortRanges?.map(range).join(", ")}`}
            plain
            actions={
              <>
                {free.length > 0 && (
                  <Sheet title="Add endpoint group" label={`Add endpoint group to ${l.Protocol} listener`} icon={<Plus size={16} />} testId={`add-endpoint-group-${i}`}>
                    <ActionForm action={addEndpointGroup.bind(null, l.ListenerArn!)} submit="Add endpoint group" testId={`add-endpoint-group-${i}`}>
                      {/* A listener has one endpoint group per Region. */}
                      <EndpointGroupFields regions={free} candidates={candidates} initial={here} rule={ENDPOINTS} />
                      <div className="form-row">
                        <Field label="Traffic dial (%)" rule={GROUP_RULES.TrafficDialPercentage}>
                          <input name="dial" type="number" defaultValue={100} />
                        </Field>
                        <Field label="Health check protocol" rule={GROUP_RULES.HealthCheckProtocol}>
                          <select name="hcProtocol" defaultValue="TCP">
                            <option>TCP</option>
                            <option>HTTP</option>
                            <option>HTTPS</option>
                          </select>
                        </Field>
                      </div>
                      <label className="check">
                        <input type="checkbox" name="preserve" /> Preserve client IP address
                      </label>
                    </ActionForm>
                  </Sheet>
                )}
                <Sheet title="Edit listener" label={`Edit ${l.Protocol} listener`} icon={<Pencil size={16} />} testId={`edit-ga-listener-${i}`}>
                  <ActionForm action={updateListener.bind(null, l.ListenerArn!)} submit="Save" testId={`edit-ga-listener-${i}`}>
                    <ListenerFields
                      rule={PORTS}
                      used={{ TCP: used("TCP", l.ListenerArn), UDP: used("UDP", l.ListenerArn) }}
                      defaults={{ ports: (l.PortRanges ?? []).map(range).join(", "), protocol: (l.Protocol as "TCP" | "UDP") ?? "TCP", affinity: l.ClientAffinity }}
                    />
                  </ActionForm>
                </Sheet>
                <ActionForm action={deleteListener.bind(null, l.ListenerArn!)} submit="Delete listener" icon={<Trash2 size={16} />} tone="danger" confirm="Delete this listener?" />
              </>
            }
          >
            {l.ClientAffinity === "SOURCE_IP" && <Pill>Source IP affinity</Pill>}
            <List
              label="Endpoint groups"
              empty={<div className="empty">No endpoint groups</div>}
              rows={groups[i].map((g) => {
                const ends = g.EndpointDescriptions ?? [];
                const healthy = ends.filter((e) => e.HealthState === "HEALTHY").length;
                const bad = ends.filter((e) => e.HealthState === "UNHEALTHY").length;
                return {
                  key: g.EndpointGroupArn!,
                  icon: <AwsIcon icon={ICONS.region} size={22} />,
                  title: g.EndpointGroupRegion,
                  subtitle: ends.map((e) => endpointName(e.EndpointId)).join(", ") || undefined,
                  href: groupHref(g.EndpointGroupArn),
                  meta: (
                    <>
                      <Pill title="Traffic dial">{g.TrafficDialPercentage ?? 100}%</Pill>
                      {ends.length > 0 && (
                        <Status tone={bad ? "bad" : healthy === ends.length ? "good" : "neutral"}>{bad ? `${bad} unhealthy` : healthy === ends.length ? "healthy" : "initial"}</Status>
                      )}
                    </>
                  ),
                  actions: <ActionForm action={deleteEndpointGroup.bind(null, g.EndpointGroupArn!, undefined)} submit={`Delete endpoint group ${g.EndpointGroupRegion}`} icon={<Trash2 size={15} />} tone="danger" />,
                };
              })}
            />
          </Section>
        );
      })}
      <Section
        title="Flow logs"
        plain
        actions={
          <Sheet title="Flow logs" label="Edit flow logs" icon={<Pencil size={16} />} testId="edit-flow-logs">
            <ActionForm action={updateFlowLogs.bind(null, arn)} submit="Save" testId="edit-flow-logs">
              <label className="check">
                <input type="checkbox" name="flowLogs" defaultChecked={attributes?.FlowLogsEnabled} /> Flow logs on
              </label>
              <div className="form-row">
                <Field label="S3 bucket" rule={UpdateAcceleratorAttributes.FlowLogsS3Bucket} format="bucket">
                  <input name="bucket" defaultValue={attributes?.FlowLogsS3Bucket} />
                </Field>
                <Field label="Prefix" rule={UpdateAcceleratorAttributes.FlowLogsS3Prefix}>
                  <input name="prefix" defaultValue={attributes?.FlowLogsS3Prefix} />
                </Field>
              </div>
            </ActionForm>
          </Sheet>
        }
      >
        <span className="muted">{attributes?.FlowLogsEnabled ? `s3://${attributes.FlowLogsS3Bucket}/${attributes.FlowLogsS3Prefix ?? ""}` : "Off"}</span>
      </Section>
      <Section
        title="Tags"
        count={tags.length}
        plain
        actions={
          <Sheet title="Add tag" label="Add tag" testId="add-ga-tag">
            <ActionForm action={addTag.bind(null, arn)} submit="Add tag" testId="add-ga-tag">
              <div className="form-row">
                <Field label="Key" rule={TAG.Key}>
                  <input name="key" required />
                </Field>
                <Field label="Value" rule={TAG.Value}>
                  <input name="value" />
                </Field>
              </div>
            </ActionForm>
          </Sheet>
        }
      >
        <List
          label="Tags"
          empty={<Empty icon={ICONS.ga} />}
          rows={tags.map((t) => ({
            key: t.Key!,
            icon: <Tag size={16} />,
            title: t.Key,
            subtitle: t.Value,
            actions: <ActionForm action={removeTag.bind(null, arn, t.Key!)} submit={`Remove tag ${t.Key}`} icon={<X size={15} />} tone="danger" />,
          }))}
        />
      </Section>
    </Page>
  );
}
