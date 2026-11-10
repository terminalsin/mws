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
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
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
  });
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
    const [from, to] = required(form, "ports", "Ports").split("-").map(Number);
    await (await ga()).send(
      new CreateListenerCommand({
        AcceleratorArn: arn,
        Protocol: (text(form, "protocol") || "TCP") as "TCP" | "UDP",
        PortRanges: [{ FromPort: from, ToPort: to || from }],
        IdempotencyToken: `console-${Date.now()}`,
      }),
    );
    return "Listener added";
  }, "/ga/accelerator");
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
  }, "/ga/accelerator");
}

export async function deleteEndpointGroup(arn: string) {
  return act(async () => {
    await (await ga()).send(new DeleteEndpointGroupCommand({ EndpointGroupArn: arn }));
    return "Endpoint group deleted";
  }, "/ga/accelerator");
}
