"use server";

import {
  AddTagsToResourceCommand,
  DeleteParameterCommand,
  DeleteParametersCommand,
  GetParameterCommand,
  LabelParameterVersionCommand,
  PutParameterCommand,
  RemoveTagsFromResourceCommand,
  UnlabelParameterVersionCommand,
  type ParameterTier,
  type ParameterType,
} from "@aws-sdk/client-ssm";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { listItems } from "@mws-dashboard/ui/validation";
import { redirect } from "next/navigation";

import { ssm } from "../../lib/clients";

const DETAIL = "/ssm/parameter";

/** `key=value` lines as SSM tags. */
function tagLines(form: FormData, name = "tags") {
  return text(form, name)
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l, i) => {
      const [Key, ...rest] = l.split("=");
      if (!rest.length || !Key.trim()) throw new FieldError(name, `Line ${i + 1}: key=value`, "format");
      return { Key: Key.trim(), Value: rest.join("=").trim() };
    });
}

export async function putParameter(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await ssm();
    const name = required(form, "name", "Name");
    const overwrite = text(form, "overwrite") === "on";
    let value = text(form, "value");
    // A hidden SecureString saved with an empty value keeps the value it has.
    if (!value && text(form, "keep") === "on") value = (await client.send(new GetParameterCommand({ Name: name, WithDecryption: true }))).Parameter?.Value ?? "";
    if (!value) throw new FieldError("value", "Value is required", "required");
    const type = (text(form, "type") || "String") as ParameterType;
    const Tags = overwrite ? [] : tagLines(form);
    const policies = text(form, "policies");
    const out = await client
      .send(
        new PutParameterCommand({
          Name: name,
          Value: value,
          Type: type,
          Description: overwrite || text(form, "description") ? text(form, "description") : undefined,
          Tier: (text(form, "tier") || undefined) as ParameterTier | undefined,
          KeyId: type === "SecureString" ? text(form, "keyId") || undefined : undefined,
          AllowedPattern: text(form, "allowedPattern") || undefined,
          DataType: text(form, "dataType") || undefined,
          Policies: policies || undefined,
          Tags: Tags.length ? Tags : undefined,
          Overwrite: overwrite,
        }),
      )
      .catch((e: Error) => {
        // Parameter Store's name and value-size messages name no member.
        if (e.name === "ValidationException" && /^Parameter name/.test(e.message)) throw new FieldError("name", e.message);
        if (e.name === "ValidationException" && /parameter value|maximum parameter value/i.test(e.message)) throw new FieldError("value", e.message);
        if (e.name === "ValidationException" && /tier/i.test(e.message)) throw new FieldError("tier", e.message);
        if (e.name === "ValidationException" && /data ?type|image/i.test(e.message)) throw new FieldError("dataType", e.message);
        throw e;
      });
    return `Stored ${name} version ${out.Version}`;
  }, {
    revalidate: ["/ssm", DETAIL],
    fields: {
      Name: "name",
      Value: "value",
      Type: "type",
      Description: "description",
      KeyId: "keyId",
      AllowedPattern: "allowedPattern",
      Policies: "policies",
      Tier: "tier",
      DataType: "dataType",
      Tags: "tags",
      HierarchyLevelLimitExceededException: "name",
      HierarchyTypeMismatchException: "type",
      UnsupportedParameterType: "type",
      ParameterPatternMismatchException: "value",
      InvalidKeyId: "keyId",
      InvalidAllowedPatternException: "allowedPattern",
      InvalidPolicyTypeException: "policies",
      InvalidPolicyAttributeException: "policies",
      IncompatiblePolicyException: "policies",
      PoliciesLimitExceededException: "policies",
      UnsupportedParameterTypeException: "type",
      ParameterMaxVersionLimitExceeded: "value",
    },
  });
}

export async function deleteParameter(name: string) {
  return act(async () => {
    await (await ssm()).send(new DeleteParameterCommand({ Name: name }));
    return `Deleted ${name}`;
  }, "/ssm");
}

/** Delete a parameter from its own page, then go back to its folder. */
export async function deleteAndLeave(name: string) {
  return act(async () => {
    await (await ssm()).send(new DeleteParameterCommand({ Name: name }));
    const folder = name.slice(0, name.lastIndexOf("/") + 1);
    redirect(folder && folder !== "/" ? `/ssm?path=${encodeURIComponent(folder)}` : "/ssm");
  });
}

/** Delete every parameter of a folder (DeleteParameters takes ten at a time). */
export async function deleteMany(names: string[]) {
  return act(async () => {
    const client = await ssm();
    const invalid: string[] = [];
    for (let i = 0; i < names.length; i += 10) {
      const out = await client.send(new DeleteParametersCommand({ Names: names.slice(i, i + 10) }));
      invalid.push(...(out.InvalidParameters ?? []));
    }
    if (invalid.length) throw new Error(`Not deleted: ${invalid.join(", ")}`);
    return `Deleted ${names.length} parameters`;
  }, "/ssm");
}

export async function labelVersion(name: string, version: number, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Labels = listItems(required(form, "labels", "Labels"));
    const out = await (await ssm()).send(new LabelParameterVersionCommand({ Name: name, ParameterVersion: version, Labels }));
    if (out.InvalidLabels?.length) throw new FieldError("labels", `Not valid labels: ${out.InvalidLabels.join(", ")}. Labels can't start with a number, aws or ssm, and use letters, digits, . - _`, "format");
    return `Labelled version ${version}`;
  }, { revalidate: [DETAIL], fields: { Labels: "labels", ParameterVersionLabelLimitExceeded: "labels", ParameterVersionNotFound: "labels" } });
}

export async function unlabel(name: string, version: number, label: string) {
  return act(async () => {
    await (await ssm()).send(new UnlabelParameterVersionCommand({ Name: name, ParameterVersion: version, Labels: [label] }));
    return `Removed ${label}`;
  }, DETAIL);
}

/** Save tag lines as a resource's whole tag set (any SSM resource type). */
export async function saveTags(type: string, id: string, before: string[], back: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await ssm();
    const Tags = tagLines(form);
    const gone = before.filter((k) => !Tags.some((t) => t.Key === k));
    const ResourceType = type as "Parameter";
    if (gone.length) await client.send(new RemoveTagsFromResourceCommand({ ResourceType, ResourceId: id, TagKeys: gone }));
    if (Tags.length) await client.send(new AddTagsToResourceCommand({ ResourceType, ResourceId: id, Tags }));
    return "Tags saved";
  }, { revalidate: [back], fields: { Tags: "tags", TagKeys: "tags", InvalidResourceId: "tags", TooManyTagsError: "tags" } });
}
