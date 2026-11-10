import { DescribeAcceleratorCommand, DescribeEndpointGroupCommand, DescribeListenerCommand } from "@aws-sdk/client-global-accelerator";
import { load, region as currentRegion } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Section, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { Gauge, HeartPulse, Pencil, Plus, Shuffle, Trash2, X } from "lucide-react";
import { MoreFields } from "@mws-dashboard/ui/presets";
import type { Metadata } from "next";

import { ICONS, acceleratorHref, endpointCandidates, endpointHref, endpointIcon, endpointName, ga } from "../../../lib/clients";
import { ENDPOINTS, GROUP_RULES } from "../../../lib/rules";
import { addEndpoints, deleteEndpointGroup, removeEndpoint, updateEndpointGroup } from "../actions";

export const metadata: Metadata = { title: "Endpoint group" };

type Props = { searchParams: Promise<{ arn?: string }> };

const HEALTH_TONE: Record<string, "good" | "bad" | "neutral"> = { HEALTHY: "good", UNHEALTHY: "bad", INITIAL: "neutral" };
const WEIGHT = GROUP_RULES.EndpointConfigurations.item!.fields!.Weight;
const range = (p: { FromPort?: number; ToPort?: number }) => (p.FromPort === p.ToPort ? `${p.FromPort}` : `${p.FromPort}-${p.ToPort}`);

export default async function EndpointGroup({ searchParams }: Props) {
  const { arn = "" } = await searchParams;
  // Endpoint group ARNs extend their listener's, which extends the accelerator's.
  const listenerArn = arn.split("/endpoint-group/")[0];
  const acceleratorArn = arn.split("/listener/")[0];
  const back = { href: acceleratorHref(acceleratorArn), label: "Accelerator" };
  const data = await load(async () => {
    const client = await ga();
    const [g, listener, accelerator, here] = await Promise.all([
      client.send(new DescribeEndpointGroupCommand({ EndpointGroupArn: arn })).then((r) => r.EndpointGroup!),
      client.send(new DescribeListenerCommand({ ListenerArn: listenerArn })).then((r) => r.Listener, () => undefined),
      client.send(new DescribeAcceleratorCommand({ AcceleratorArn: acceleratorArn })).then((r) => r.Accelerator, () => undefined),
      currentRegion(),
    ]);
    return { g, listener, accelerator, here, candidates: await endpointCandidates(g.EndpointGroupRegion!) };
  });
  if (!data.ok) {
    return (
      <Page title="Endpoint group" icon={ICONS.ga} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { g, listener, accelerator, here, candidates } = data.value;
  const ends = g.EndpointDescriptions ?? [];
  const present = new Set(ends.map((e) => e.EndpointId));
  const free = candidates.filter((c) => !present.has(c.id));
  const settling = ends.some((e) => !e.HealthState || e.HealthState === "INITIAL");
  const http = g.HealthCheckProtocol === "HTTP" || g.HealthCheckProtocol === "HTTPS";
  return (
    <Page
      title={g.EndpointGroupRegion}
      icon={ICONS.region}
      back={accelerator ? { ...back, label: accelerator.Name ?? back.label } : back}
      subtitle={arn}
      actions={
        <>
          <Sheet title="Add endpoints" label="Add endpoints" icon={<Plus size={16} />} testId="add-endpoints">
            <ActionForm action={addEndpoints.bind(null, arn)} submit="Add" testId="add-endpoints">
              <Field label="Endpoints (one per line, id or id=weight)" rule={ENDPOINTS} known={free.map((c) => c.id)} member="EndpointId">
                <textarea name="endpoint" rows={2} placeholder={free[0]?.id ?? "Load balancer, instance or Elastic IP"} />
              </Field>
              <label className="check">
                <input type="checkbox" name="preserve" /> Preserve client IP address
              </label>
            </ActionForm>
          </Sheet>
          <Sheet title="Edit endpoint group" label="Edit endpoint group" icon={<Pencil size={16} />} testId="edit-endpoint-group">
            <ActionForm action={updateEndpointGroup.bind(null, arn)} submit="Save" testId="edit-endpoint-group">
              <Field label="Traffic dial (%)" rule={GROUP_RULES.TrafficDialPercentage}>
                <input name="dial" type="number" defaultValue={g.TrafficDialPercentage ?? 100} />
              </Field>
              <Field label="Port overrides (listener=endpoint)" rule={{ pattern: "^\\s*(\\d{1,5}\\s*=\\s*\\d{1,5}\\s*([,\\n]\\s*\\d{1,5}\\s*=\\s*\\d{1,5}\\s*)*)?$", hint: "Like 80=8080" }} member="PortOverrides">
                <textarea name="overrides" rows={2} defaultValue={(g.PortOverrides ?? []).map((o) => `${o.ListenerPort}=${o.EndpointPort}`).join("\n")} />
              </Field>
              {ends.map((e) => (
                <div className="form-row" key={e.EndpointId}>
                  <Field label={`Weight · ${endpointName(e.EndpointId)}`} rule={WEIGHT}>
                    <input name={`weight:${e.EndpointId}`} type="number" defaultValue={e.Weight ?? 128} />
                  </Field>
                  <input type="hidden" name={`ip:${e.EndpointId}`} value="off" />
                  <label className="check">
                    <input type="checkbox" name={`ip:${e.EndpointId}`} defaultChecked={e.ClientIPPreservationEnabled} /> Preserve client IP
                  </label>
                </div>
              ))}
              <MoreFields label="Health check">
                <div className="form-row">
                  <Field label="Health check protocol" rule={GROUP_RULES.HealthCheckProtocol}>
                    <select name="hcProtocol" defaultValue={g.HealthCheckProtocol ?? "TCP"}>
                      <option>TCP</option>
                      <option>HTTP</option>
                      <option>HTTPS</option>
                    </select>
                  </Field>
                  <Field label="Health check port" rule={GROUP_RULES.HealthCheckPort} format="port">
                    <input name="hcPort" type="number" defaultValue={g.HealthCheckPort} />
                  </Field>
                </div>
                <Field label="Health check path (HTTP, HTTPS)" rule={GROUP_RULES.HealthCheckPath}>
                  <input name="hcPath" defaultValue={g.HealthCheckPath ?? "/"} />
                </Field>
                <div className="form-row">
                  <Field label="Interval" rule={{ ...GROUP_RULES.HealthCheckIntervalSeconds, unit: "seconds" }} member="HealthCheckIntervalSeconds">
                    <select name="interval" defaultValue={String(g.HealthCheckIntervalSeconds ?? 30)}>
                      <option value="10">10 seconds</option>
                      <option value="30">30 seconds</option>
                    </select>
                  </Field>
                  <Field label="Threshold" rule={GROUP_RULES.ThresholdCount}>
                    <input name="threshold" type="number" defaultValue={g.ThresholdCount ?? 3} />
                  </Field>
                </div>
              </MoreFields>
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteEndpointGroup.bind(null, arn, acceleratorArn)} submit="Delete endpoint group" icon={<Trash2 size={16} />} tone="danger" confirm="Delete this endpoint group?" testId="delete-endpoint-group" />
        </>
      }
    >
      {settling && <LiveRefresh />}
      <Specs
        items={[
          listener && { label: "Listener", icon: <Shuffle size={15} />, value: `${listener.Protocol} ${listener.PortRanges?.map(range).join(", ")}` },
          { label: "Traffic dial", icon: <Gauge size={15} />, value: `${g.TrafficDialPercentage ?? 100}%` },
          {
            label: "Health check",
            icon: <HeartPulse size={15} />,
            value: `${g.HealthCheckProtocol}${g.HealthCheckPort ? `:${g.HealthCheckPort}` : ""}${http ? (g.HealthCheckPath ?? "/") : ""} · ${g.HealthCheckIntervalSeconds}s × ${g.ThresholdCount}`,
          },
          g.PortOverrides?.length && { label: "Port overrides", icon: <Shuffle size={15} />, value: g.PortOverrides.map((o) => `${o.ListenerPort}→${o.EndpointPort}`).join(", ") },
        ]}
      />
      <Section title="Endpoints" count={ends.length} plain>
        <List
          label="Endpoints"
          empty={<Empty icon={ICONS.ga} />}
          rows={ends.map((e) => {
            const total = ends.reduce((n, x) => n + (x.Weight ?? 0), 0);
            return {
              key: e.EndpointId!,
              icon: <AwsIcon icon={endpointIcon(e.EndpointId)} size={22} />,
              title: endpointName(e.EndpointId),
              subtitle: e.HealthReason && e.HealthState !== "HEALTHY" ? e.HealthReason : undefined,
              href: endpointHref(e.EndpointId, g.EndpointGroupRegion, here),
              meta: (
                <>
                  <Pill title="Weight">
                    {e.Weight ?? 0}
                    {total > 0 ? ` · ${Math.round(((e.Weight ?? 0) / total) * 100)}%` : ""}
                  </Pill>
                  {e.ClientIPPreservationEnabled && <Pill>Client IP</Pill>}
                  <Status tone={HEALTH_TONE[e.HealthState ?? "INITIAL"] ?? "neutral"}>{e.HealthState?.toLowerCase() ?? "initial"}</Status>
                </>
              ),
              actions: <ActionForm action={removeEndpoint.bind(null, arn, e.EndpointId!)} submit={`Remove ${endpointName(e.EndpointId)}`} icon={<X size={15} />} tone="danger" confirm={`Remove ${endpointName(e.EndpointId)}?`} />,
            };
          })}
        />
      </Section>
    </Page>
  );
}
