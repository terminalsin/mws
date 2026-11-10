"use server";

import {
  CreateAppCommand,
  CreateBranchCommand,
  CreateDeploymentCommand,
  CreateDomainAssociationCommand,
  CreateWebhookCommand,
  DeleteAppCommand,
  DeleteBranchCommand,
  DeleteDomainAssociationCommand,
  DeleteJobCommand,
  DeleteWebhookCommand,
  StartDeploymentCommand,
  StartJobCommand,
  StopJobCommand,
  UpdateAppCommand,
  UpdateBranchCommand,
  UpdateDomainAssociationCommand,
  UpdateWebhookCommand,
  type CustomRule,
  type Platform,
  type Stage,
} from "@aws-sdk/client-amplify";
import { act, endpoint, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { strToU8, zipSync } from "fflate";
import { redirect } from "next/navigation";

import { amplify } from "../../lib/clients";

export async function createApp(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await amplify();
    const repository = text(form, "repository");
    // Amplify refuses a repository without a token; say so on the token.
    if (repository && !text(form, "token")) throw new FieldError("token", "Needed to connect the repository", "required");
    const out = await client.send(
      new CreateAppCommand({
        name: required(form, "name", "Name"),
        platform: (text(form, "platform") || "WEB") as Platform,
        repository: repository || undefined,
        accessToken: text(form, "token") || undefined,
        iamServiceRoleArn: text(form, "role") || undefined,
        environmentVariables: env(form, "env"),
      }),
    );
    const appId = out.app!.appId!;
    const branch = text(form, "branch");
    if (branch) await client.send(new CreateBranchCommand({ appId, branchName: branch, stage: "PRODUCTION" }));
    redirect(`/amplify/app?id=${appId}`);
  }, { fields: { repository: "repository", accessToken: "token", iamServiceRoleArn: "role", environmentVariables: "env" } });
}

export async function deleteApp(appId: string) {
  return act(async () => {
    await (await amplify()).send(new DeleteAppCommand({ appId }));
    redirect("/amplify");
  });
}

export async function createBranch(appId: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const branchName = required(form, "name", "Branch");
    try {
      await (await amplify()).send(new CreateBranchCommand({ appId, branchName, stage: (text(form, "stage") || "DEVELOPMENT") as Stage }));
    } catch (e) {
      // Amplify answers a BadRequestException ("Branch x already exists."),
      // not a conflict code: point it at the name so it offers a free one.
      if (e instanceof Error && /^Branch .* already exists/.test(e.message)) throw new FieldError("name", "Already exists", "taken");
      throw e;
    }
    return "Created";
  }, { revalidate: ["/amplify/app"], fields: { branchName: "name" } });
}

export async function deleteBranch(appId: string, branch: string) {
  return act(async () => {
    await (await amplify()).send(new DeleteBranchCommand({ appId, branchName: branch }));
    redirect(`/amplify/app?id=${appId}`);
  });
}

/** Deploy without a repository: a zip, a URL, or an index.html typed in. */
export async function deploy(appId: string, branch: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await amplify();
    const url = text(form, "url");
    if (url) {
      const out = await client.send(new StartDeploymentCommand({ appId, branchName: branch, sourceUrl: url, sourceUrlType: url.startsWith("s3://") && url.endsWith("/") ? "BUCKET_PREFIX" : "ZIP" }));
      return `Job ${out.jobSummary?.jobId}`;
    }
    const file = form.get("zip");
    let zip: Uint8Array;
    if (file instanceof File && file.size > 0) zip = new Uint8Array(await file.arrayBuffer());
    else if (!text(form, "html")) throw new FieldError("html", "Add a zip, a URL or an index.html", "required");
    else zip = zipSync({ "index.html": strToU8(text(form, "html")) });
    const created = await client.send(new CreateDeploymentCommand({ appId, branchName: branch }));
    const put = await fetch(created.zipUploadUrl!, { method: "PUT", body: Buffer.from(zip), headers: { "content-type": "application/zip" } });
    if (!put.ok) throw new Error(`Upload failed: ${put.status} ${await put.text()}`);
    const out = await client.send(new StartDeploymentCommand({ appId, branchName: branch, jobId: created.jobId }));
    return `Job ${out.jobSummary?.jobId}`;
  }, { revalidate: ["/amplify/branch", "/amplify/app"], fields: { sourceUrl: "url" } });
}

export async function build(appId: string, branch: string) {
  return act(async () => {
    const out = await (await amplify()).send(new StartJobCommand({ appId, branchName: branch, jobType: "RELEASE" }));
    return `Job ${out.jobSummary?.jobId}`;
  }, "/amplify/branch");
}

/** Build one commit (MANUAL commit id or a full SHA) with a reason. */
export async function buildCommit(appId: string, branch: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await amplify()).send(
      new StartJobCommand({
        appId,
        branchName: branch,
        jobType: "RELEASE",
        commitId: text(form, "commit") || undefined,
        commitMessage: text(form, "message") || undefined,
        jobReason: text(form, "reason") || undefined,
      }),
    );
    return `Job ${out.jobSummary?.jobId}`;
  }, { revalidate: ["/amplify/branch"], fields: { commitId: "commit", commitMessage: "message", jobReason: "reason" } });
}

export async function retryJob(appId: string, branch: string, jobId: string) {
  return act(async () => {
    const out = await (await amplify()).send(new StartJobCommand({ appId, branchName: branch, jobType: "RETRY", jobId }));
    return `Job ${out.jobSummary?.jobId}`;
  }, "/amplify/branch", "/amplify/job");
}

export async function deleteJob(appId: string, branch: string, jobId: string) {
  return act(async () => {
    await (await amplify()).send(new DeleteJobCommand({ appId, branchName: branch, jobId }));
    redirect(`/amplify/branch?app=${appId}&name=${encodeURIComponent(branch)}`);
  });
}

// Settings ---------------------------------------------------------------------

/** `KEY=value` lines as a map; `undefined` when the field was not on the form. */
function env(form: FormData, field: string): Record<string, string> | undefined {
  if (!form.has(field)) return undefined;
  const out: Record<string, string> = {};
  for (const line of text(form, field).split("\n").map((l) => l.trim()).filter(Boolean)) {
    const i = line.indexOf("=");
    if (i < 1) throw new FieldError(field, `"${line}" is not KEY=value`, "format");
    out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return out;
}

/** Rewrites and redirects, one per line: `source target [status] [condition]`. */
function rules(form: FormData, field: string): CustomRule[] | undefined {
  if (!form.has(field)) return undefined;
  return text(form, field)
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((line) => {
      const [source, target, status, ...condition] = line.split(/\s+/);
      if (!target) throw new FieldError(field, `"${line}" needs a source and a target`, "format");
      return { source, target, status: status || undefined, condition: condition.join(" ") || undefined };
    });
}

/** Basic auth: the checkbox, and `user:password` (blank keeps the current one). */
function basicAuth(form: FormData) {
  const enabled = text(form, "basicAuth") === "on";
  const creds = text(form, "credentials");
  if (enabled && creds && !creds.includes(":")) throw new FieldError("credentials", "Write it as user:password", "format");
  return { enableBasicAuth: enabled, basicAuthCredentials: enabled && creds ? Buffer.from(creds).toString("base64") : undefined };
}

export async function updateApp(appId: string, hadAuth: boolean, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const auth = basicAuth(form);
    if (auth.enableBasicAuth && !auth.basicAuthCredentials && !hadAuth) throw new FieldError("credentials", "Needed to turn basic auth on", "required");
    await (await amplify()).send(
      new UpdateAppCommand({
        appId,
        name: required(form, "name", "Name"),
        description: text(form, "description"),
        platform: (text(form, "platform") || undefined) as Platform | undefined,
        iamServiceRoleArn: text(form, "role"),
        environmentVariables: env(form, "env"),
        buildSpec: text(form, "buildSpec") || undefined,
        customHeaders: text(form, "customHeaders"),
        customRules: rules(form, "rules"),
        enableBranchAutoBuild: text(form, "autoBuild") === "on",
        enableBranchAutoDeletion: text(form, "autoDelete") === "on",
        ...auth,
      }),
    );
    return "Saved";
  }, {
    revalidate: ["/amplify/app"],
    fields: { name: "name", description: "description", iamServiceRoleArn: "role", environmentVariables: "env", buildSpec: "buildSpec", customHeaders: "customHeaders", customRules: "rules", basicAuthCredentials: "credentials" },
  });
}

export async function updateBranch(appId: string, branch: string, hadAuth: boolean, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const auth = basicAuth(form);
    if (auth.enableBasicAuth && !auth.basicAuthCredentials && !hadAuth) throw new FieldError("credentials", "Needed to turn basic auth on", "required");
    await (await amplify()).send(
      new UpdateBranchCommand({
        appId,
        branchName: branch,
        displayName: text(form, "displayName") || undefined,
        description: text(form, "description"),
        stage: (text(form, "stage") || undefined) as Stage | undefined,
        framework: text(form, "framework"),
        enableAutoBuild: text(form, "autoBuild") === "on",
        enablePullRequestPreview: text(form, "previews") === "on",
        environmentVariables: env(form, "env"),
        buildSpec: text(form, "buildSpec") || undefined,
        ttl: text(form, "ttl") || undefined,
        ...auth,
      }),
    );
    return "Saved";
  }, {
    revalidate: ["/amplify/branch"],
    fields: { displayName: "displayName", description: "description", framework: "framework", environmentVariables: "env", buildSpec: "buildSpec", ttl: "ttl", basicAuthCredentials: "credentials" },
  });
}

// Custom domains ---------------------------------------------------------------

/** `prefix=branch` lines (`=main` or `@=main` for the apex). */
function subDomains(form: FormData) {
  const lines = text(form, "subDomains").split("\n").map((l) => l.trim()).filter(Boolean);
  if (!lines.length) throw new FieldError("subDomains", "Map at least one sub-domain to a branch", "required");
  return lines.map((l) => {
    const i = l.indexOf("=");
    if (i < 0) throw new FieldError("subDomains", `"${l}" is not prefix=branch`, "format");
    const prefix = l.slice(0, i).trim();
    return { prefix: prefix === "@" ? "" : prefix, branchName: l.slice(i + 1).trim() };
  });
}

export async function createDomain(appId: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const domainName = required(form, "domain", "Domain").replace(/\.$/, "");
    await (await amplify()).send(
      new CreateDomainAssociationCommand({ appId, domainName, subDomainSettings: subDomains(form), enableAutoSubDomain: text(form, "autoSub") === "on" || undefined }),
    );
    redirect(`/amplify/domain?app=${appId}&name=${encodeURIComponent(domainName)}`);
  }, { fields: { domainName: "domain", subDomainSettings: "subDomains", "subDomainSettings.prefix": "subDomains", "subDomainSettings.branchName": "subDomains" } });
}

export async function updateDomain(appId: string, domainName: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await amplify()).send(new UpdateDomainAssociationCommand({ appId, domainName, subDomainSettings: subDomains(form), enableAutoSubDomain: text(form, "autoSub") === "on" }));
    return "Saved";
  }, { revalidate: ["/amplify/domain"], fields: { subDomainSettings: "subDomains", "subDomainSettings.prefix": "subDomains", "subDomainSettings.branchName": "subDomains" } });
}

export async function deleteDomain(appId: string, domainName: string) {
  return act(async () => {
    await (await amplify()).send(new DeleteDomainAssociationCommand({ appId, domainName }));
    redirect(`/amplify/app?id=${appId}`);
  });
}

// Webhooks -------------------------------------------------------------------------

export async function createWebhook(appId: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await amplify()).send(new CreateWebhookCommand({ appId, branchName: required(form, "branch", "Branch"), description: text(form, "description") || undefined }));
    return { ok: true, message: "Webhook created", detail: out.webhook?.webhookUrl };
  }, { revalidate: ["/amplify/app"], fields: { branchName: "branch", description: "description" } });
}

export async function retargetWebhook(webhookId: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await amplify()).send(new UpdateWebhookCommand({ webhookId, branchName: required(form, "branch", "Branch"), description: text(form, "description") || undefined }));
    return "Saved";
  }, { revalidate: ["/amplify/app"], fields: { branchName: "branch", description: "description" } });
}

export async function deleteWebhook(webhookId: string) {
  return act(async () => {
    await (await amplify()).send(new DeleteWebhookCommand({ webhookId }));
    return "Deleted";
  }, "/amplify/app");
}

/** Call the webhook as a Git host would: it starts a build of its branch. */
export async function triggerWebhook(url: string) {
  return act(async () => {
    // MWS answers the URL's path and query on its own endpoint.
    const u = new URL(url);
    const r = await fetch(`${endpoint()}${u.pathname}${u.search}`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    if (!r.ok) throw new Error(`Webhook answered ${r.status}: ${await r.text()}`);
    return "Build started";
  }, "/amplify/app", "/amplify/branch");
}

export async function stopJob(appId: string, branch: string, jobId: string) {
  return act(async () => {
    await (await amplify()).send(new StopJobCommand({ appId, branchName: branch, jobId }));
    return "Stopping";
  }, "/amplify/branch");
}
