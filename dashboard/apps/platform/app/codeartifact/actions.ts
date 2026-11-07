"use server";

import {
  AssociateExternalConnectionCommand,
  CreateDomainCommand,
  CreateRepositoryCommand,
  DeleteDomainCommand,
  DeletePackageVersionsCommand,
  DeleteRepositoryCommand,
  UpdatePackageVersionsStatusCommand,
  type PackageFormat,
} from "@aws-sdk/client-codeartifact";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { codeartifact } from "../../lib/clients";

export async function createDomain(_: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await codeartifact()).send(new CreateDomainCommand({ domain: required(form, "name", "Domain name") }));
    return "Created";
  }, "/codeartifact");
}

export async function deleteDomain(domain: string) {
  return act(async () => {
    await (await codeartifact()).send(new DeleteDomainCommand({ domain }));
    return "Deleted";
  }, "/codeartifact");
}

export async function createRepository(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await codeartifact();
    const domain = required(form, "domain", "Domain");
    const repository = required(form, "name", "Repository name");
    const upstream = text(form, "upstream");
    await client.send(
      new CreateRepositoryCommand({
        domain,
        repository,
        description: text(form, "description") || undefined,
        upstreams: upstream ? [{ repositoryName: upstream }] : undefined,
      }),
    );
    const external = text(form, "external");
    if (external) await client.send(new AssociateExternalConnectionCommand({ domain, repository, externalConnection: external }));
    redirect(`/codeartifact/repo?domain=${encodeURIComponent(domain)}&name=${encodeURIComponent(repository)}`);
  });
}

export async function deleteRepository(domain: string, repository: string) {
  return act(async () => {
    await (await codeartifact()).send(new DeleteRepositoryCommand({ domain, repository }));
    redirect("/codeartifact");
  });
}

type PackageRef = { domain: string; repository: string; format: string; namespace?: string; package: string };

export async function setVersionStatus(p: PackageRef, version: string, status: "Published" | "Unlisted" | "Archived") {
  return act(async () => {
    await (await codeartifact()).send(
      new UpdatePackageVersionsStatusCommand({ ...p, format: p.format as PackageFormat, versions: [version], targetStatus: status }),
    );
    return status;
  }, "/codeartifact/package");
}

export async function deleteVersion(p: PackageRef, version: string) {
  return act(async () => {
    await (await codeartifact()).send(new DeletePackageVersionsCommand({ ...p, format: p.format as PackageFormat, versions: [version] }));
    return "Deleted";
  }, "/codeartifact/package");
}
