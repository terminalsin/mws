"use server";

import {
  AddEndpointsCommand,
  CreateAcceleratorCommand,
  CreateEndpointGroupCommand,
  CreateListenerCommand,
  DeleteAcceleratorCommand,
  DeleteEndpointGroupCommand,
  DeleteListenerCommand,
  DescribeEndpointGroupCommand,
  RemoveEndpointsCommand,
  TagResourceCommand,
  UntagResourceCommand,
  UpdateAcceleratorAttributesCommand,
  UpdateAcceleratorCommand,
  UpdateEndpointGroupCommand,
  UpdateListenerCommand,
  type EndpointConfiguration,
  type HealthCheckProtocol,
} from "@aws-sdk/client-global-accelerator";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { portRanges } from "@mws-dashboard/ui/validation";
import { redirect } from "next/navigation";

import { acceleratorHref, ga } from "../../lib/clients";

const token = () => `console-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

export async function createAccelerator(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await ga()).send(
      new CreateAcceleratorCommand({
        Name: required(form, "name", "Name"),
        IpAddressType: (text(form, "ip") || "IPV4") as "IPV4" | "DUAL_STACK",
        Enabled: true,
        IdempotencyToken: token(),
      }),
    );
    redirect(acceleratorHref(out.Accelerator!.AcceleratorArn));
  }, { fields: { Name: "name", InvalidArgumentException: "name" } });
}

export async function updateAccelerator(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await ga()).send(
      new UpdateAcceleratorCommand({ AcceleratorArn: arn, Name: required(form, "name", "Name"), IpAddressType: (text(form, "ip") || undefined) as "IPV4" | "DUAL_STACK" | undefined }),
    );
    return "Accelerator saved";
  }, { revalidate: ["/ga", "/ga/accelerator"], fields: { Name: "name", IpAddressType: "ip", InvalidArgumentException: "name" } });
}

export async function updateFlowLogs(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const on = form.get("flowLogs") === "on";
    await (await ga()).send(
      new UpdateAcceleratorAttributesCommand({
        AcceleratorArn: arn,
        FlowLogsEnabled: on,
        FlowLogsS3Bucket: on ? required(form, "bucket", "S3 bucket") : undefined,
        FlowLogsS3Prefix: on ? text(form, "prefix") || undefined : undefined,
      }),
    );
    return on ? "Flow logs on" : "Flow logs off";
  }, { revalidate: ["/ga/accelerator"], fields: { FlowLogsS3Bucket: "bucket", FlowLogsS3Prefix: "prefix", InvalidArgumentException: "bucket" } });
}

export async function setEnabled(arn: string, Enabled: boolean) {
  return act(async () => {
    await (await ga()).send(new UpdateAcceleratorCommand({ AcceleratorArn: arn, Enabled }));
    return Enabled ? "Enabled" : "Disabled";
  }, "/ga", "/ga/accelerator");
}

export async function deleteAccelerator(arn: string) {
  return act(async () => {
    await (await ga()).send(new DeleteAcceleratorCommand({ AcceleratorArn: arn }));
    redirect("/ga");
  });
}

function ranges(form: FormData) {
  const r = portRanges(required(form, "ports", "Ports"));
  if (!r) throw new FieldError("ports", "Like 80, 443 or 8000-8100", "format");
  return r.map((x) => ({ FromPort: x.from, ToPort: x.to }));
}

const LISTENER_FIELDS = { PortRanges: "ports", InvalidPortRangeException: "ports", LimitExceededException: "ports", ClientAffinity: "affinity" };

export async function addListener(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await ga()).send(
      new CreateListenerCommand({
        AcceleratorArn: arn,
        Protocol: (text(form, "protocol") || "TCP") as "TCP" | "UDP",
        PortRanges: ranges(form),
        ClientAffinity: (text(form, "affinity") || undefined) as "NONE" | "SOURCE_IP" | undefined,
        IdempotencyToken: token(),
      }),
    );
    return "Listener added";
  }, { revalidate: ["/ga/accelerator"], fields: LISTENER_FIELDS });
}

export async function updateListener(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await ga()).send(
      new UpdateListenerCommand({
        ListenerArn: arn,
        Protocol: (text(form, "protocol") || "TCP") as "TCP" | "UDP",
        PortRanges: ranges(form),
        ClientAffinity: (text(form, "affinity") || "NONE") as "NONE" | "SOURCE_IP",
      }),
    );
    return "Listener saved";
  }, { revalidate: ["/ga/accelerator"], fields: LISTENER_FIELDS });
}

export async function deleteListener(arn: string) {
  return act(async () => {
    await (await ga()).send(new DeleteListenerCommand({ ListenerArn: arn }));
    return "Listener deleted";
  }, "/ga/accelerator");
}

/** "id" or "id=weight" per line (weight 128 by default). */
function endpoints(form: FormData, field = "endpoint"): EndpointConfiguration[] {
  const preserve = form.get("preserve") === "on";
  return text(form, field)
    .split(/[\n,]+/)
    .map((l) => l.trim())
    .filter(Boolean)
    .map((line) => {
      const [id, w] = line.split(/\s*=\s*/);
      if (w !== undefined && !/^\d{1,3}$/.test(w)) throw new FieldError(field, `${line}: weight 0-255`, "format");
      return { EndpointId: id, Weight: w === undefined ? 128 : Number(w), ClientIPPreservationEnabled: preserve || undefined };
    });
}

/** "80=8080" lines: listener port to endpoint port. */
function portOverrides(form: FormData) {
  const raw = text(form, "overrides");
  if (!raw) return [];
  return raw
    .split(/[\n,]+/)
    .map((l) => l.trim())
    .filter(Boolean)
    .map((line) => {
      const m = line.match(/^(\d{1,5})\s*(?:=|->|→|:)\s*(\d{1,5})$/);
      if (!m) throw new FieldError("overrides", `${line}: like 80=8080`, "format");
      return { ListenerPort: Number(m[1]), EndpointPort: Number(m[2]) };
    });
}

const num = (form: FormData, name: string) => (text(form, name) ? Number(text(form, name)) : undefined);

function healthSettings(form: FormData) {
  const protocol = (text(form, "hcProtocol") || undefined) as HealthCheckProtocol | undefined;
  return {
    TrafficDialPercentage: num(form, "dial"),
    HealthCheckProtocol: protocol,
    HealthCheckPort: num(form, "hcPort"),
    HealthCheckPath: protocol && protocol !== "TCP" ? text(form, "hcPath") || undefined : undefined,
    HealthCheckIntervalSeconds: num(form, "interval"),
    ThresholdCount: num(form, "threshold"),
  };
}

const GROUP_FIELDS = {
  EndpointGroupRegion: "region",
  EndpointGroupAlreadyExistsException: "region",
  EndpointId: "endpoint",
  EndpointConfigurations: "endpoint",
  InvalidArgumentException: "endpoint",
  EndpointNotFoundException: "endpoint",
  EndpointAlreadyExistsException: "endpoint",
  TrafficDialPercentage: "dial",
  HealthCheckPort: "hcPort",
  HealthCheckPath: "hcPath",
  HealthCheckIntervalSeconds: "interval",
  ThresholdCount: "threshold",
  PortOverrides: "overrides",
};

export async function addEndpointGroup(listener: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const list = endpoints(form);
    const overrides = portOverrides(form);
    await (await ga()).send(
      new CreateEndpointGroupCommand({
        ListenerArn: listener,
        EndpointGroupRegion: required(form, "region", "Region"),
        EndpointConfigurations: list.length ? list : undefined,
        PortOverrides: overrides.length ? overrides : undefined,
        ...healthSettings(form),
        IdempotencyToken: token(),
      }),
    );
    return "Endpoint group added";
  }, { revalidate: ["/ga/accelerator"], fields: GROUP_FIELDS });
}

/** Group settings and every endpoint's weight and client IP preservation
 * (UpdateEndpointGroup replaces the endpoint list, so all are sent). */
export async function updateEndpointGroup(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await ga();
    const current = (await client.send(new DescribeEndpointGroupCommand({ EndpointGroupArn: arn }))).EndpointGroup;
    const configs: EndpointConfiguration[] = (current?.EndpointDescriptions ?? []).map((e) => ({
      EndpointId: e.EndpointId,
      Weight: num(form, `weight:${e.EndpointId}`) ?? e.Weight,
      ClientIPPreservationEnabled: form.has(`ip:${e.EndpointId}`) ? form.getAll(`ip:${e.EndpointId}`).includes("on") : e.ClientIPPreservationEnabled,
    }));
    await client.send(new UpdateEndpointGroupCommand({ EndpointGroupArn: arn, EndpointConfigurations: configs, PortOverrides: portOverrides(form), ...healthSettings(form) }));
    return "Endpoint group saved";
  }, { revalidate: ["/ga/group", "/ga/accelerator"], fields: GROUP_FIELDS });
}

export async function addEndpoints(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const list = endpoints(form);
    if (!list.length) throw new FieldError("endpoint", "Add an endpoint", "required");
    await (await ga()).send(new AddEndpointsCommand({ EndpointGroupArn: arn, EndpointConfigurations: list }));
    return `Added ${list.length}`;
  }, { revalidate: ["/ga/group", "/ga/accelerator"], fields: GROUP_FIELDS });
}

export async function removeEndpoint(arn: string, id: string) {
  return act(async () => {
    await (await ga()).send(new RemoveEndpointsCommand({ EndpointGroupArn: arn, EndpointIdentifiers: [{ EndpointId: id }] }));
    return `Removed ${id}`;
  }, "/ga/group", "/ga/accelerator");
}

export async function deleteEndpointGroup(arn: string, back?: string) {
  return act(async () => {
    await (await ga()).send(new DeleteEndpointGroupCommand({ EndpointGroupArn: arn }));
    if (back) redirect(acceleratorHref(back));
    return "Endpoint group deleted";
  }, "/ga/accelerator");
}

export async function addTag(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Key = required(form, "key", "Key");
    await (await ga()).send(new TagResourceCommand({ ResourceArn: arn, Tags: [{ Key, Value: text(form, "value") }] }));
    return `Tagged ${Key}`;
  }, { revalidate: ["/ga/accelerator"], fields: { "Tags.member.Key": "key", "Tags.member.Value": "value" } });
}

export async function removeTag(arn: string, key: string) {
  return act(async () => {
    await (await ga()).send(new UntagResourceCommand({ ResourceArn: arn, TagKeys: [key] }));
    return `Removed ${key}`;
  }, "/ga/accelerator");
}
