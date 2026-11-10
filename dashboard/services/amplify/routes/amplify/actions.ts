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
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { strToU8, zipSync } from "fflate";
import { redirect } from "next/navigation";

import { amplify } from "../../lib/clients";

export async function createApp(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await amplify();
    const repository = text(form, "repository");
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
  });
}

export async function deleteApp(appId: string) {
  return act(async () => {
    await (await amplify()).send(new DeleteAppCommand({ appId }));
    redirect("/amplify");
  });
}

export async function createBranch(appId: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await amplify()).send(
      new CreateBranchCommand({ appId, branchName: required(form, "name", "Branch"), stage: (text(form, "stage") || "DEVELOPMENT") as Stage }),
    );
    return "Created";
  }, "/amplify/app");
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
    else zip = zipSync({ "index.html": strToU8(required(form, "html", "A zip, a URL or index.html")) });
    const created = await client.send(new CreateDeploymentCommand({ appId, branchName: branch }));
    const put = await fetch(created.zipUploadUrl!, { method: "PUT", body: Buffer.from(zip), headers: { "content-type": "application/zip" } });
    if (!put.ok) throw new Error(`Upload failed: ${put.status} ${await put.text()}`);
    const out = await client.send(new StartDeploymentCommand({ appId, branchName: branch, jobId: created.jobId }));
    return `Job ${out.jobSummary?.jobId}`;
  }, "/amplify/branch", "/amplify/app");
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
