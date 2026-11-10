"use server";

import {
  CreateFunctionCommand,
  CreateFunctionUrlConfigCommand,
  DeleteEventSourceMappingCommand,
  DeleteFunctionCommand,
  GetFunctionCommand,
  InvokeCommand,
  PublishVersionCommand,
  UpdateEventSourceMappingCommand,
  UpdateFunctionCodeCommand,
  UpdateFunctionConfigurationCommand,
  type Runtime,
} from "@aws-sdk/client-lambda";
import { FieldError, act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { ROLES, roleFrom } from "@mws-dashboard/aws/auto";
import { strToU8, unzipSync, zipSync } from "fflate";
import { redirect } from "next/navigation";

import { STARTERS, family, lambda } from "../../lib/clients";

const page = (name: string) => `/lambda/${encodeURIComponent(name)}`;

/** Form fields by API member, so validation errors MWS returns land on them. */
const FIELDS = {
  FunctionName: "name",
  Runtime: "runtime",
  Role: "role",
  Handler: "handler",
  MemorySize: "memory",
  Timeout: "timeout",
  "Environment.Variables": "env",
};

/** Lambda reports a bad role or environment as InvalidParameterValue with
 * no member; its message says which field it means. */
async function send<T>(run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (e) {
    if (e instanceof Error && e.name === "InvalidParameterValueException") {
      if (/role/i.test(e.message)) throw new FieldError("role", "Lambda can't assume this role", "missing");
      if (/environment variables/i.test(e.message)) {
        const reserved = e.message.match(/Reserved keys used in this request: (.+)$/)?.[1];
        throw new FieldError("env", reserved ? `Reserved: ${reserved}` : "Over the 4 KB limit");
      }
      if (/runtime/i.test(e.message)) throw new FieldError("runtime", e.message);
    }
    throw e;
  }
}

/** Invoke the function synchronously and show its response and log tail. */
export async function invoke(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const payload = text(form, "payload") || "{}";
    try {
      JSON.parse(payload);
    } catch {
      throw new FieldError("payload", "Invalid JSON", "format");
    }
    const out = await (await lambda()).send(new InvokeCommand({ FunctionName: name, Payload: new TextEncoder().encode(payload), LogType: "Tail" }));
    const response = out.Payload ? new TextDecoder().decode(out.Payload) : "";
    let pretty = response;
    try {
      pretty = JSON.stringify(JSON.parse(response), null, 2);
    } catch {
      // not JSON
    }
    const logs = out.LogResult ? Buffer.from(out.LogResult, "base64").toString("utf8") : "";
    return {
      ok: !out.FunctionError,
      message: out.FunctionError ? `${out.FunctionError} · ${out.StatusCode}` : `${out.StatusCode} · ${out.ExecutedVersion ?? "$LATEST"}`,
      detail: `${pretty}${logs ? `\n\n${logs}` : ""}`,
    };
  });
}

export async function createFunction(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Function name");
    const runtime = required(form, "runtime", "Runtime");
    const starter = STARTERS[family(runtime)] ?? STARTERS.nodejs;
    const client = await lambda();
    const Role = await roleFrom(form, "role", ROLES.lambda(name));
    await send(() => client.send(
      new CreateFunctionCommand({
        FunctionName: name,
        Runtime: runtime as Runtime,
        Role,
        Handler: starter.handler,
        Code: { ZipFile: zipSync({ [starter.file]: strToU8(starter.code) }) },
        Architectures: [text(form, "arch") === "x86_64" ? "x86_64" : "arm64"],
      }),
    ));
    redirect(page(name));
  }, { fields: FIELDS });
}

/** Replace one file of the deployment package and redeploy. */
export async function saveCode(name: string, file: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await lambda();
    const fn = await client.send(new GetFunctionCommand({ FunctionName: name }));
    const zip = new Uint8Array(await (await fetch(fn.Code!.Location!)).arrayBuffer());
    const files = unzipSync(zip);
    files[file] = strToU8(text(form, "code").replace(/\r\n/g, "\n") + "\n");
    await client.send(new UpdateFunctionCodeCommand({ FunctionName: name, ZipFile: zipSync(files) }));
    return "Deployed";
  }, page(name));
}

export async function saveConfiguration(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Variables = Object.fromEntries(
      text(form, "env")
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean)
        .map((l) => {
          const [k, ...v] = l.split("=");
          return [k.trim(), v.join("=").trim()];
        }),
    );
    const client = await lambda();
    await send(() => client.send(
      new UpdateFunctionConfigurationCommand({
        FunctionName: name,
        MemorySize: Number(text(form, "memory")) || undefined,
        Timeout: Number(text(form, "timeout")) || undefined,
        Handler: text(form, "handler") || undefined,
        Role: text(form, "role") || undefined,
        Environment: { Variables },
      }),
    ));
    return "Saved";
  }, { revalidate: [page(name)], fields: FIELDS });
}

export async function publishVersion(name: string) {
  return act(async () => {
    const out = await (await lambda()).send(new PublishVersionCommand({ FunctionName: name }));
    return `Published version ${out.Version}`;
  }, page(name));
}

export async function createUrl(name: string) {
  return act(async () => {
    const out = await (await lambda()).send(new CreateFunctionUrlConfigCommand({ FunctionName: name, AuthType: "NONE" }));
    return { ok: true, message: "Function URL created", detail: out.FunctionUrl };
  }, page(name));
}

export async function setMapping(name: string, uuid: string, enabled: boolean) {
  return act(async () => {
    await (await lambda()).send(new UpdateEventSourceMappingCommand({ UUID: uuid, Enabled: enabled }));
    return enabled ? "Enabled" : "Disabled";
  }, page(name));
}

export async function deleteMapping(name: string, uuid: string) {
  return act(async () => {
    await (await lambda()).send(new DeleteEventSourceMappingCommand({ UUID: uuid }));
    return "Removed";
  }, page(name));
}

export async function deleteFunction(name: string) {
  return act(async () => {
    await (await lambda()).send(new DeleteFunctionCommand({ FunctionName: name }));
    redirect("/lambda");
  });
}
