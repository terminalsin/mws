"use server";

import { GetRoleCommand, PutRolePolicyCommand } from "@aws-sdk/client-iam";
import {
  AddLayerVersionPermissionCommand,
  AddPermissionCommand,
  CreateAliasCommand,
  CreateEventSourceMappingCommand,
  CreateFunctionCommand,
  CreateFunctionUrlConfigCommand,
  DeleteAliasCommand,
  DeleteEventSourceMappingCommand,
  DeleteFunctionCommand,
  DeleteFunctionConcurrencyCommand,
  DeleteFunctionEventInvokeConfigCommand,
  DeleteFunctionUrlConfigCommand,
  DeleteLayerVersionCommand,
  DeleteProvisionedConcurrencyConfigCommand,
  GetFunctionCommand,
  GetPolicyCommand,
  InvokeCommand,
  PublishLayerVersionCommand,
  PublishVersionCommand,
  PutFunctionConcurrencyCommand,
  PutFunctionEventInvokeConfigCommand,
  PutProvisionedConcurrencyConfigCommand,
  RemoveLayerVersionPermissionCommand,
  RemovePermissionCommand,
  TagResourceCommand,
  UntagResourceCommand,
  UpdateAliasCommand,
  UpdateEventSourceMappingCommand,
  UpdateFunctionCodeCommand,
  UpdateFunctionConfigurationCommand,
  UpdateFunctionUrlConfigCommand,
  type Architecture,
  type FunctionUrlAuthType,
  type InvocationType,
  type InvokeMode,
  type Runtime,
} from "@aws-sdk/client-lambda";
import { FieldError, act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { ROLES, roleFrom } from "@mws-dashboard/aws/auto";
import { strToU8, unzipSync, zipSync } from "fflate";
import { redirect } from "next/navigation";

import { STARTERS, family, iam, lambda } from "../../lib/clients";

const page = (name: string) => `/lambda/${encodeURIComponent(name)}`;

/** Form fields by API member, so validation errors MWS returns land on them. */
const FIELDS = {
  FunctionName: "name",
  Runtime: "runtime",
  Role: "role",
  Handler: "handler",
  MemorySize: "memory",
  Timeout: "timeout",
  Description: "description",
  "EphemeralStorage.Size": "ephemeral",
  "DeadLetterConfig.TargetArn": "dlq",
  Layers: "layers",
  "Environment.Variables": "env",
};

/** Lambda reports a bad role or environment as InvalidParameterValue with
 * no member; its message says which field it means. */
async function send<T>(run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (e) {
    if (e instanceof Error && e.name === "InvalidParameterValueException") {
      if (/execution role does not have permissions/i.test(e.message)) throw new FieldError("source", e.message, "server");
      if (/role/i.test(e.message)) throw new FieldError("role", "Lambda can't assume this role", "missing");
      if (/environment variables/i.test(e.message)) {
        const reserved = e.message.match(/Reserved keys used in this request: (.+)$/)?.[1];
        throw new FieldError("env", reserved ? `Reserved: ${reserved}` : "Over the 4 KB limit");
      }
      if (/runtime/i.test(e.message)) throw new FieldError("runtime", e.message);
      if (/layer/i.test(e.message)) throw new FieldError("layers", e.message);
      if (/dead letter|DeadLetter/i.test(e.message)) throw new FieldError("dlq", e.message);
      if (/visibility timeout|Queue visibility/i.test(e.message)) throw new FieldError("source", e.message);
      if (/Stream not found|queue does not exist/i.test(e.message)) throw new FieldError("source", e.message, "missing");
    }
    throw e;
  }
}

const lines = (v: string) =>
  v
    .split(/[\n,]/)
    .map((l) => l.trim())
    .filter(Boolean);

const pairs = (v: string) =>
  Object.fromEntries(
    v
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => {
        const [k, ...rest] = l.split("=");
        return [k.trim(), rest.join("=").trim()];
      }),
  );

/** Invoke the function and show its response and log tail. */
export async function invoke(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const payload = text(form, "payload") || "{}";
    try {
      JSON.parse(payload);
    } catch {
      throw new FieldError("payload", "Invalid JSON", "format");
    }
    const Qualifier = text(form, "qualifier") || undefined;
    const InvocationType = (text(form, "type") || "RequestResponse") as InvocationType;
    const out = await (await lambda()).send(
      new InvokeCommand({ FunctionName: name, Qualifier, InvocationType, Payload: new TextEncoder().encode(payload), ...(InvocationType === "RequestResponse" ? { LogType: "Tail" } : {}) }),
    );
    if (InvocationType === "Event") return { ok: true, message: `${out.StatusCode} · queued` };
    if (InvocationType === "DryRun") return { ok: true, message: `${out.StatusCode} · allowed` };
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
    const image = text(form, "image");
    const client = await lambda();
    const Role = await roleFrom(form, "role", ROLES.lambda(name));
    const Architectures: Architecture[] = [text(form, "arch") === "x86_64" ? "x86_64" : "arm64"];
    if (image) {
      await send(() => client.send(new CreateFunctionCommand({ FunctionName: name, PackageType: "Image", Code: { ImageUri: image }, Role, Architectures })));
      redirect(page(name));
    }
    const runtime = required(form, "runtime", "Runtime");
    const file = form.get("zip");
    const upload = file instanceof File && file.size > 0 ? new Uint8Array(await file.arrayBuffer()) : null;
    const starter = STARTERS[family(runtime)];
    if (!upload && !starter) throw new FieldError("zip", `Upload the code for ${runtime}`, "required");
    if (upload) {
      try {
        unzipSync(upload);
      } catch {
        throw new FieldError("zip", "Not a .zip archive", "format");
      }
    }
    await send(() => client.send(
      new CreateFunctionCommand({
        FunctionName: name,
        Runtime: runtime as Runtime,
        Role,
        Handler: text(form, "handler") || starter?.handler,
        Code: { ZipFile: upload ?? zipSync({ [starter!.file]: strToU8(starter!.code) }) },
        Architectures,
      }),
    ));
    redirect(page(name));
  }, { fields: { ...FIELDS, "Code.ImageUri": "image", ImageUri: "image" } });
}

/** Replace one file of the deployment package and redeploy. */
export async function saveCode(name: string, file: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await lambda();
    const fn = await client.send(new GetFunctionCommand({ FunctionName: name }));
    const zip = new Uint8Array(await (await fetch(fn.Code!.Location!)).arrayBuffer());
    const files = unzipSync(zip);
    files[file] = strToU8(text(form, "code").replace(/\r\n/g, "\n") + "\n");
    // The revision read above: a concurrent update fails instead of being overwritten.
    await client.send(new UpdateFunctionCodeCommand({ FunctionName: name, ZipFile: zipSync(files), RevisionId: fn.Configuration?.RevisionId }));
    return "Deployed";
  }, page(name));
}

/** Upload a whole .zip deployment package, or point an image function at a new image. */
export async function uploadCode(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await lambda();
    const image = text(form, "image");
    if (image) {
      await client.send(new UpdateFunctionCodeCommand({ FunctionName: name, ImageUri: image }));
      return "Deployed";
    }
    const file = form.get("zip");
    if (!(file instanceof File) || file.size === 0) throw new FieldError("zip", "Choose a .zip file", "required");
    const bytes = new Uint8Array(await file.arrayBuffer());
    try {
      unzipSync(bytes);
    } catch {
      throw new FieldError("zip", "Not a .zip archive", "format");
    }
    await client.send(new UpdateFunctionCodeCommand({ FunctionName: name, ZipFile: bytes }));
    return "Deployed";
  }, { revalidate: [page(name)], fields: { ImageUri: "image", ZipFile: "zip" } });
}

export async function saveConfiguration(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Variables = pairs(text(form, "env"));
    const ephemeral = Number(text(form, "ephemeral"));
    const client = await lambda();
    await send(() => client.send(
      new UpdateFunctionConfigurationCommand({
        FunctionName: name,
        Description: text(form, "description"),
        MemorySize: Number(text(form, "memory")) || undefined,
        Timeout: Number(text(form, "timeout")) || undefined,
        Handler: text(form, "handler") || undefined,
        Runtime: (text(form, "runtime") || undefined) as Runtime | undefined,
        Role: text(form, "role") || undefined,
        ...(ephemeral ? { EphemeralStorage: { Size: ephemeral } } : {}),
        ...(text(form, "dlq") || text(form, "hadDlq") ? { DeadLetterConfig: { TargetArn: text(form, "dlq") } } : {}),
        Layers: lines(text(form, "layers")),
        TracingConfig: { Mode: text(form, "tracing") === "Active" ? "Active" : "PassThrough" },
        Environment: { Variables },
      }),
    ));
    return "Saved";
  }, { revalidate: [page(name)], fields: FIELDS });
}

export async function publishVersion(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await lambda()).send(new PublishVersionCommand({ FunctionName: name, Description: text(form, "description") || undefined }));
    return `Published version ${out.Version}`;
  }, { revalidate: [page(name)], fields: { Description: "description" } });
}

// Function URLs ------------------------------------------------------------

/** The statements the AWS console adds for a public (`NONE`) URL: without
 * both, Lambda answers every request with 403 Forbidden. */
async function allowPublicUrl(name: string) {
  const client = await lambda();
  const existing = await client
    .send(new GetPolicyCommand({ FunctionName: name }))
    .then((r) => (JSON.parse(r.Policy ?? "{}").Statement ?? []).map((s: { Sid?: string }) => s.Sid), () => [] as string[]);
  if (!existing.includes("FunctionURLAllowPublicAccess")) {
    await client.send(
      new AddPermissionCommand({ FunctionName: name, StatementId: "FunctionURLAllowPublicAccess", Action: "lambda:InvokeFunctionUrl", Principal: "*", FunctionUrlAuthType: "NONE" }),
    );
  }
  if (!existing.includes("FunctionURLAllowInvokeAction")) {
    await client.send(
      new AddPermissionCommand({ FunctionName: name, StatementId: "FunctionURLAllowInvokeAction", Action: "lambda:InvokeFunction", Principal: "*", InvokedViaFunctionUrl: true }),
    );
  }
}

function cors(form: FormData) {
  const origins = lines(text(form, "origins"));
  if (!origins.length) return undefined;
  return {
    AllowOrigins: origins,
    AllowMethods: lines(text(form, "methods")).length ? lines(text(form, "methods")) : ["*"],
    AllowHeaders: lines(text(form, "headers")),
    AllowCredentials: text(form, "credentials") === "on",
  };
}

export async function createUrl(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const AuthType = (text(form, "auth") || "NONE") as FunctionUrlAuthType;
    const client = await lambda();
    const out = await client.send(
      new CreateFunctionUrlConfigCommand({ FunctionName: name, AuthType, InvokeMode: (text(form, "mode") || "BUFFERED") as InvokeMode, Cors: cors(form) }),
    );
    if (AuthType === "NONE") await allowPublicUrl(name);
    return { ok: true, message: "Function URL created", detail: out.FunctionUrl };
  }, { revalidate: [page(name)], fields: { AuthType: "auth", "Cors.AllowOrigins": "origins" } });
}

export async function updateUrl(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const AuthType = (text(form, "auth") || "NONE") as FunctionUrlAuthType;
    await (await lambda()).send(
      new UpdateFunctionUrlConfigCommand({
        FunctionName: name,
        AuthType,
        InvokeMode: (text(form, "mode") || "BUFFERED") as InvokeMode,
        Cors: cors(form) ?? { AllowOrigins: [], AllowMethods: [], AllowHeaders: [], AllowCredentials: false },
      }),
    );
    if (AuthType === "NONE") await allowPublicUrl(name);
    return "Saved";
  }, { revalidate: [page(name)], fields: { AuthType: "auth", "Cors.AllowOrigins": "origins" } });
}

export async function deleteUrl(name: string) {
  return act(async () => {
    await (await lambda()).send(new DeleteFunctionUrlConfigCommand({ FunctionName: name }));
    return "Function URL deleted";
  }, page(name));
}

// Triggers (event source mappings) ------------------------------------------

/** Give the execution role what Lambda's pollers need on the source, as a
 * `console-<source>` inline policy. */
async function grantSource(fn: string, source: string) {
  const role = (await (await lambda()).send(new GetFunctionCommand({ FunctionName: fn }))).Configuration?.Role;
  const roleName = role?.split("/").pop();
  if (!roleName) return;
  const service = source.split(":")[2];
  const Action =
    service === "sqs"
      ? ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
      : ["kinesis:DescribeStream", "kinesis:DescribeStreamSummary", "kinesis:GetRecords", "kinesis:GetShardIterator", "kinesis:ListShards", "kinesis:ListStreams", "kinesis:SubscribeToShard"];
  const client = await iam();
  await client.send(new GetRoleCommand({ RoleName: roleName }));
  await client.send(
    new PutRolePolicyCommand({
      RoleName: roleName,
      PolicyName: `console-${source.split(":").pop()!.replace(/[^\w+=,.@-]/g, "-")}`.slice(0, 128),
      PolicyDocument: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Action, Resource: source }] }),
    }),
  );
}

function filters(form: FormData) {
  const pattern = text(form, "filter");
  if (!pattern) return { Filters: [] };
  try {
    JSON.parse(pattern);
  } catch {
    throw new FieldError("filter", "Invalid JSON", "format");
  }
  return { Filters: [{ Pattern: pattern }] };
}

const ESM_FIELDS = {
  EventSourceArn: "source",
  BatchSize: "batch",
  MaximumBatchingWindowInSeconds: "window",
  StartingPosition: "position",
  "FilterCriteria.Filters": "filter",
  "FilterCriteria.Filters[0].Pattern": "filter",
  ResourceNotFoundException: "source",
};

export async function createMapping(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const source = required(form, "source", "Source");
    const stream = source.split(":")[2] === "kinesis";
    if (text(form, "grant") === "on") await grantSource(name, source);
    const batch = text(form, "batch");
    const window = text(form, "window");
    await send(() =>
      lambda().then((c) =>
        c.send(
          new CreateEventSourceMappingCommand({
            FunctionName: name,
            EventSourceArn: source,
            Enabled: text(form, "enabled") !== "off",
            ...(batch ? { BatchSize: Number(batch) } : {}),
            ...(window ? { MaximumBatchingWindowInSeconds: Number(window) } : {}),
            ...(stream ? { StartingPosition: (text(form, "position") || "LATEST") as "LATEST" | "TRIM_HORIZON" } : {}),
            FunctionResponseTypes: text(form, "partial") === "on" ? ["ReportBatchItemFailures"] : [],
            ...(text(form, "filter") ? { FilterCriteria: filters(form) } : {}),
          }),
        ),
      ),
    );
    return "Trigger added";
  }, { revalidate: [page(name)], fields: ESM_FIELDS });
}

export async function updateMapping(name: string, uuid: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const batch = text(form, "batch");
    const window = text(form, "window");
    await send(() =>
      lambda().then((c) =>
        c.send(
          new UpdateEventSourceMappingCommand({
            UUID: uuid,
            ...(batch ? { BatchSize: Number(batch) } : {}),
            ...(window ? { MaximumBatchingWindowInSeconds: Number(window) } : {}),
            FunctionResponseTypes: text(form, "partial") === "on" ? ["ReportBatchItemFailures"] : [],
            FilterCriteria: filters(form),
          }),
        ),
      ),
    );
    return "Saved";
  }, { revalidate: [page(name)], fields: ESM_FIELDS });
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

// Resource-based policy -----------------------------------------------------

export async function addPermission(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const principal = required(form, "principal", "Principal");
    const sourceArn = text(form, "sourceArn");
    const sourceAccount = text(form, "sourceAccount");
    const auth = text(form, "urlAuth");
    await (await lambda()).send(
      new AddPermissionCommand({
        FunctionName: name,
        Qualifier: text(form, "qualifier") || undefined,
        StatementId: required(form, "sid", "Statement ID"),
        Action: required(form, "action", "Action"),
        Principal: principal,
        ...(sourceArn ? { SourceArn: sourceArn } : {}),
        ...(sourceAccount ? { SourceAccount: sourceAccount } : {}),
        ...(auth ? { FunctionUrlAuthType: auth as FunctionUrlAuthType } : {}),
      }),
    );
    return "Permission added";
  }, { revalidate: [page(name)], fields: { StatementId: "sid", Action: "action", Principal: "principal", SourceArn: "sourceArn", SourceAccount: "sourceAccount", ResourceConflictException: "sid" } });
}

export async function removePermission(name: string, sid: string, qualifier?: string) {
  return act(async () => {
    await (await lambda()).send(new RemovePermissionCommand({ FunctionName: name, StatementId: sid, Qualifier: qualifier }));
    return "Permission removed";
  }, page(name));
}

// Aliases -------------------------------------------------------------------

function routing(form: FormData) {
  const extra = text(form, "extraVersion");
  const weight = Number(text(form, "weight"));
  if (!extra || !weight) return { AdditionalVersionWeights: {} };
  return { AdditionalVersionWeights: { [extra]: weight / 100 } };
}

const ALIAS_FIELDS = { Name: "alias", FunctionVersion: "version", Description: "description", "RoutingConfig.AdditionalVersionWeights": "weight", ResourceConflictException: "alias" };

export async function createAlias(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await lambda()).send(
      new CreateAliasCommand({
        FunctionName: name,
        Name: required(form, "alias", "Alias name"),
        FunctionVersion: required(form, "version", "Version"),
        Description: text(form, "description") || undefined,
        RoutingConfig: routing(form),
      }),
    );
    return "Alias created";
  }, { revalidate: [page(name)], fields: ALIAS_FIELDS });
}

export async function updateAlias(name: string, alias: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await lambda()).send(
      new UpdateAliasCommand({
        FunctionName: name,
        Name: alias,
        FunctionVersion: required(form, "version", "Version"),
        Description: text(form, "description"),
        RoutingConfig: routing(form),
      }),
    );
    return "Saved";
  }, { revalidate: [page(name)], fields: ALIAS_FIELDS });
}

export async function deleteAlias(name: string, alias: string) {
  return act(async () => {
    await (await lambda()).send(new DeleteAliasCommand({ FunctionName: name, Name: alias }));
    return "Alias deleted";
  }, page(name));
}

// Concurrency and asynchronous invocation -----------------------------------

export async function saveConcurrency(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await lambda();
    const reserved = text(form, "reserved");
    if (reserved === "") await client.send(new DeleteFunctionConcurrencyCommand({ FunctionName: name }));
    else await client.send(new PutFunctionConcurrencyCommand({ FunctionName: name, ReservedConcurrentExecutions: Number(reserved) }));
    return "Saved";
  }, { revalidate: [page(name)], fields: { ReservedConcurrentExecutions: "reserved", InvalidParameterValueException: "reserved" } });
}

export async function addProvisioned(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await lambda()).send(
      new PutProvisionedConcurrencyConfigCommand({
        FunctionName: name,
        Qualifier: required(form, "qualifier", "Version or alias"),
        ProvisionedConcurrentExecutions: Number(required(form, "count", "Concurrency")),
      }),
    );
    return "Saved";
  }, { revalidate: [page(name)], fields: { Qualifier: "qualifier", ProvisionedConcurrentExecutions: "count" } });
}

export async function deleteProvisioned(name: string, qualifier: string) {
  return act(async () => {
    await (await lambda()).send(new DeleteProvisionedConcurrencyConfigCommand({ FunctionName: name, Qualifier: qualifier }));
    return "Removed";
  }, page(name));
}

export async function saveAsync(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const success = text(form, "onSuccess");
    const failure = text(form, "onFailure");
    await (await lambda()).send(
      new PutFunctionEventInvokeConfigCommand({
        FunctionName: name,
        MaximumRetryAttempts: Number(text(form, "retries") || "2"),
        MaximumEventAgeInSeconds: Number(text(form, "age") || "21600"),
        DestinationConfig: { ...(success ? { OnSuccess: { Destination: success } } : {}), ...(failure ? { OnFailure: { Destination: failure } } : {}) },
      }),
    );
    return "Saved";
  }, {
    revalidate: [page(name)],
    fields: { MaximumRetryAttempts: "retries", MaximumEventAgeInSeconds: "age", "DestinationConfig.OnSuccess.Destination": "onSuccess", "DestinationConfig.OnFailure.Destination": "onFailure" },
  });
}

export async function deleteAsync(name: string) {
  return act(async () => {
    await (await lambda()).send(new DeleteFunctionEventInvokeConfigCommand({ FunctionName: name }));
    return "Reset to defaults";
  }, page(name));
}

// Tags ----------------------------------------------------------------------

export async function saveTags(name: string, arn: string, current: string[], _: ActionResult | null, form: FormData) {
  return act(async () => {
    const tags = pairs(text(form, "tags"));
    const client = await lambda();
    const gone = current.filter((k) => !(k in tags));
    if (gone.length) await client.send(new UntagResourceCommand({ Resource: arn, TagKeys: gone }));
    if (Object.keys(tags).length) await client.send(new TagResourceCommand({ Resource: arn, Tags: tags }));
    return "Saved";
  }, { revalidate: [page(name), "/lambda"], fields: { Tags: "tags" } });
}

export async function deleteFunction(name: string) {
  return act(async () => {
    await (await lambda()).send(new DeleteFunctionCommand({ FunctionName: name }));
    redirect("/lambda");
  });
}

// Layers --------------------------------------------------------------------

export async function publishLayer(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const LayerName = required(form, "name", "Layer name");
    const file = form.get("zip");
    if (!(file instanceof File) || file.size === 0) throw new FieldError("zip", "Choose a .zip file", "required");
    const ZipFile = new Uint8Array(await file.arrayBuffer());
    try {
      unzipSync(ZipFile);
    } catch {
      throw new FieldError("zip", "Not a .zip archive", "format");
    }
    const runtimes = form.getAll("runtimes").filter((v): v is string => typeof v === "string" && !!v);
    const archs = form.getAll("archs").filter((v): v is string => typeof v === "string" && !!v);
    const out = await (await lambda()).send(
      new PublishLayerVersionCommand({
        LayerName,
        Description: text(form, "description") || undefined,
        Content: { ZipFile },
        ...(runtimes.length ? { CompatibleRuntimes: runtimes as Runtime[] } : {}),
        ...(archs.length ? { CompatibleArchitectures: archs as Architecture[] } : {}),
        LicenseInfo: text(form, "license") || undefined,
      }),
    );
    redirect(`/lambda/layers/${encodeURIComponent(LayerName)}?published=${out.Version}`);
  }, { fields: { LayerName: "name", Description: "description", LicenseInfo: "license" } });
}

export async function deleteLayerVersion(layer: string, version: number) {
  return act(async () => {
    await (await lambda()).send(new DeleteLayerVersionCommand({ LayerName: layer, VersionNumber: version }));
    return `Deleted version ${version}`;
  }, `/lambda/layers/${encodeURIComponent(layer)}`, "/lambda/layers");
}

export async function addLayerPermission(layer: string, version: number, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const org = text(form, "org");
    await (await lambda()).send(
      new AddLayerVersionPermissionCommand({
        LayerName: layer,
        VersionNumber: version,
        StatementId: required(form, "sid", "Statement ID"),
        Action: "lambda:GetLayerVersion",
        Principal: required(form, "principal", "Principal"),
        ...(org ? { OrganizationId: org } : {}),
      }),
    );
    return "Permission added";
  }, { revalidate: [`/lambda/layers/${encodeURIComponent(layer)}`], fields: { StatementId: "sid", Principal: "principal", OrganizationId: "org", ResourceConflictException: "sid" } });
}

export async function removeLayerPermission(layer: string, version: number, sid: string) {
  return act(async () => {
    await (await lambda()).send(new RemoveLayerVersionPermissionCommand({ LayerName: layer, VersionNumber: version, StatementId: sid }));
    return "Permission removed";
  }, `/lambda/layers/${encodeURIComponent(layer)}`);
}
