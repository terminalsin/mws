"use server";

import { DeleteParameterCommand, PutParameterCommand, type ParameterType } from "@aws-sdk/client-ssm";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";

import { ssm } from "../../lib/clients";

export async function putParameter(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Name");
    const out = await (await ssm())
      .send(
        new PutParameterCommand({
          Name: name,
          Value: required(form, "value", "Value"),
          Type: (text(form, "type") || "String") as ParameterType,
          Overwrite: text(form, "overwrite") === "on",
        }),
      )
      .catch((e: Error) => {
        // Parameter Store's name and value-size messages name no member.
        if (e.name === "ValidationException" && /^Parameter name/.test(e.message)) throw new FieldError("name", e.message);
        if (e.name === "ValidationException" && /parameter value/.test(e.message)) throw new FieldError("value", e.message);
        throw e;
      });
    return `Stored ${name} version ${out.Version}`;
  }, {
    revalidate: ["/ssm"],
    fields: {
      Name: "name",
      Value: "value",
      Type: "type",
      HierarchyLevelLimitExceededException: "name",
      HierarchyTypeMismatchException: "type",
      UnsupportedParameterType: "type",
      ParameterPatternMismatchException: "value",
    },
  });
}

export async function deleteParameter(name: string) {
  return act(async () => {
    await (await ssm()).send(new DeleteParameterCommand({ Name: name }));
    return `Deleted ${name}`;
  }, "/ssm");
}
