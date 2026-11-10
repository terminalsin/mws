"use server";

import {
  CreateAcceleratorCommand,
  CreateEndpointGroupCommand,
  CreateListenerCommand,
  DeleteAcceleratorCommand,
  DeleteEndpointGroupCommand,
  DeleteListenerCommand,
  UpdateAcceleratorCommand,
} from "@aws-sdk/client-global-accelerator";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { portRanges } from "@mws-dashboard/ui/validation";
import { redirect } from "next/navigation";

import { ga } from "../../lib/clients";

const href = (arn: string) => `/ga/accelerator?arn=${encodeURIComponent(arn)}`;

export async function createAccelerator(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await ga()).send(
      new CreateAcceleratorCommand({
        Name: required(form, "name", "Name"),
        IpAddressType: (text(form, "ip") || "IPV4") as "IPV4" | "DUAL_STACK",
        Enabled: true,
        IdempotencyToken: `console-${Date.now()}`,
      }),
    );
    redirect(href(out.Accelerator!.AcceleratorArn!));
  }, { fields: { Name: "name", InvalidArgumentException: "name" } });
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

export async function addListener(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const ranges = portRanges(required(form, "ports", "Ports"));
    if (!ranges) throw new FieldError("ports", "Like 80, 443 or 8000-8100", "format");
    await (await ga()).send(
      new CreateListenerCommand({
        AcceleratorArn: arn,
        Protocol: (text(form, "protocol") || "TCP") as "TCP" | "UDP",
        PortRanges: ranges.map((r) => ({ FromPort: r.from, ToPort: r.to })),
        IdempotencyToken: `console-${Date.now()}`,
      }),
    );
    return "Listener added";
  }, { revalidate: ["/ga/accelerator"], fields: { PortRanges: "ports", InvalidPortRangeException: "ports", LimitExceededException: "ports" } });
}

export async function deleteListener(arn: string) {
  return act(async () => {
    await (await ga()).send(new DeleteListenerCommand({ ListenerArn: arn }));
    return "Listener deleted";
  }, "/ga/accelerator");
}

export async function addEndpointGroup(listener: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const endpoint = text(form, "endpoint");
    await (await ga()).send(
      new CreateEndpointGroupCommand({
        ListenerArn: listener,
        EndpointGroupRegion: required(form, "region", "Region"),
        EndpointConfigurations: endpoint ? [{ EndpointId: endpoint, Weight: 128 }] : undefined,
        IdempotencyToken: `console-${Date.now()}`,
      }),
    );
    return "Endpoint group added";
  }, {
    revalidate: ["/ga/accelerator"],
    fields: { EndpointGroupRegion: "region", EndpointGroupAlreadyExistsException: "region", EndpointId: "endpoint", InvalidArgumentException: "endpoint", EndpointNotFoundException: "endpoint" },
  });
}

export async function deleteEndpointGroup(arn: string) {
  return act(async () => {
    await (await ga()).send(new DeleteEndpointGroupCommand({ EndpointGroupArn: arn }));
    return "Endpoint group deleted";
  }, "/ga/accelerator");
}
