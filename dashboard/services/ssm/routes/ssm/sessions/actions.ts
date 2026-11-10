"use server";

import { TerminateSessionCommand } from "@aws-sdk/client-ssm";
import { act } from "@mws-dashboard/aws";

import { ssm } from "../../../lib/clients";

export async function terminate(id: string) {
  return act(async () => {
    await (await ssm()).send(new TerminateSessionCommand({ SessionId: id }));
    return "Session terminated";
  }, "/ssm/sessions");
}
