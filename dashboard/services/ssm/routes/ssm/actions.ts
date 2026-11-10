"use server";

import { DeleteParameterCommand, PutParameterCommand, type ParameterType } from "@aws-sdk/client-ssm";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";

import { ssm } from "../../lib/clients";

export async function putParameter(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Name");
    const out = await (await ssm()).send(
      new PutParameterCommand({
        Name: name,
        Value: required(form, "value", "Value"),
        Type: (text(form, "type") || "String") as ParameterType,
        Overwrite: text(form, "overwrite") === "on",
      }),
    );
    return `Stored ${name} version ${out.Version}`;
  }, "/ssm");
}

export async function deleteParameter(name: string) {
  return act(async () => {
    await (await ssm()).send(new DeleteParameterCommand({ Name: name }));
    return `Deleted ${name}`;
  }, "/ssm");
}
