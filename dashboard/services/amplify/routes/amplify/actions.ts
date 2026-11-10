"use server";

import {
  CreateAppCommand,
  CreateBranchCommand,
  CreateDeploymentCommand,
  DeleteAppCommand,
  DeleteBranchCommand,
  StartDeploymentCommand,
  StartJobCommand,
  StopJobCommand,
  type Stage,
} from "@aws-sdk/client-amplify";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
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
        platform: "WEB",
        repository: repository || undefined,
        accessToken: text(form, "token") || undefined,
      }),
    );
    const appId = out.app!.appId!;
    const branch = text(form, "branch");
    if (branch) await client.send(new CreateBranchCommand({ appId, branchName: branch, stage: "PRODUCTION" }));
    redirect(`/amplify/app?id=${appId}`);
  }, { fields: { repository: "repository", accessToken: "token" } });
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

export async function stopJob(appId: string, branch: string, jobId: string) {
  return act(async () => {
    await (await amplify()).send(new StopJobCommand({ appId, branchName: branch, jobId }));
    return "Stopping";
  }, "/amplify/branch");
}
