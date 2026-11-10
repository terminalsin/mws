"use server";

import {
  AssociateExternalConnectionCommand,
  CreateDomainCommand,
  CreatePackageGroupCommand,
  CreateRepositoryCommand,
  DeleteDomainCommand,
  DeleteDomainPermissionsPolicyCommand,
  DeletePackageCommand,
  DeletePackageGroupCommand,
  DeletePackageVersionsCommand,
  DeleteRepositoryCommand,
  DeleteRepositoryPermissionsPolicyCommand,
  DisassociateExternalConnectionCommand,
  DisposePackageVersionsCommand,
  PutDomainPermissionsPolicyCommand,
  PutPackageOriginConfigurationCommand,
  PutRepositoryPermissionsPolicyCommand,
  UpdatePackageGroupCommand,
  UpdatePackageGroupOriginConfigurationCommand,
  UpdatePackageVersionsStatusCommand,
  UpdateRepositoryCommand,
  type AllowPublish,
  type AllowUpstream,
  type PackageFormat,
  type PackageGroupOriginRestrictionMode,
  type PackageGroupOriginRestrictionType,
  type PackageVersionError,
  type PackageVersionStatus,
} from "@aws-sdk/client-codeartifact";
import { act, checkFailures, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { codeartifact } from "../../lib/clients";
import { domainHref, groupHref, packageHref, repoHref, type PackageRef } from "../../lib/refs";

export async function createDomain(_: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await codeartifact()).send(new CreateDomainCommand({ domain: required(form, "name", "Domain name"), encryptionKey: text(form, "key") || undefined }));
    return "Created";
  }, { revalidate: ["/codeartifact"], fields: { domain: "name", encryptionKey: "key" } });
}

export async function deleteDomain(domain: string, then: string) {
  return act(async () => {
    await (await codeartifact()).send(new DeleteDomainCommand({ domain }));
    if (then) redirect(then);
    return "Deleted";
  }, "/codeartifact");
}

export async function createRepository(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await codeartifact();
    const domain = required(form, "domain", "Domain");
    const repository = required(form, "name", "Repository name");
    const upstreams = form.getAll("upstream").map(String).filter(Boolean);
    await client.send(
      new CreateRepositoryCommand({
        domain,
        repository,
        description: text(form, "description") || undefined,
        upstreams: upstreams.length ? upstreams.map((repositoryName) => ({ repositoryName })) : undefined,
      }),
    );
    const external = text(form, "external");
    if (external) await client.send(new AssociateExternalConnectionCommand({ domain, repository, externalConnection: external }));
    redirect(`/codeartifact/repo?domain=${encodeURIComponent(domain)}&name=${encodeURIComponent(repository)}`);
  }, { fields: { repository: "name", domain: "domain", description: "description", repositoryName: "upstream", externalConnection: "external" } });
}

export async function deleteRepository(domain: string, repository: string) {
  return act(async () => {
    await (await codeartifact()).send(new DeleteRepositoryCommand({ domain, repository }));
    redirect("/codeartifact");
  });
}

const versionError = (f: PackageVersionError, version?: string) => `${version}: ${f.errorCode}${f.errorMessage ? ` (${f.errorMessage})` : ""}`;
const pkgArgs = (p: PackageRef) => ({ ...p, format: p.format as PackageFormat });

export async function setVersionStatus(p: PackageRef, version: string, from: PackageVersionStatus, status: "Published" | "Unlisted" | "Archived") {
  return act(async () => {
    const out = await (await codeartifact()).send(new UpdatePackageVersionsStatusCommand({ ...pkgArgs(p), versions: [version], expectedStatus: from, targetStatus: status }));
    checkFailures(out.failedVersions, versionError);
    return status;
  }, "/codeartifact/package", "/codeartifact/version");
}

export async function deleteVersion(p: PackageRef, version: string, back: string) {
  return act(async () => {
    const out = await (await codeartifact()).send(new DeletePackageVersionsCommand({ ...pkgArgs(p), versions: [version] }));
    checkFailures(out.failedVersions, versionError);
    if (back) redirect(back);
    return "Deleted";
  }, "/codeartifact/package");
}

/** Dispose: keep the version record, delete its assets. */
export async function disposeVersion(p: PackageRef, version: string, from: PackageVersionStatus) {
  return act(async () => {
    const out = await (await codeartifact()).send(new DisposePackageVersionsCommand({ ...pkgArgs(p), versions: [version], expectedStatus: from }));
    checkFailures(out.failedVersions, versionError);
    return "Disposed";
  }, "/codeartifact/package", "/codeartifact/version");
}

export async function setOrigin(p: PackageRef, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await codeartifact()).send(
      new PutPackageOriginConfigurationCommand({
        ...pkgArgs(p),
        restrictions: { publish: (text(form, "publish") || "ALLOW") as AllowPublish, upstream: (text(form, "upstream") || "ALLOW") as AllowUpstream },
      }),
    );
    return "Saved";
  }, "/codeartifact/package", "/codeartifact/repo");
}

export async function deletePackage(p: PackageRef) {
  return act(async () => {
    await (await codeartifact()).send(new DeletePackageCommand(pkgArgs(p)));
    redirect(repoHref(p.domain, p.repository, p.domainOwner));
  });
}

// Repositories ----------------------------------------------------------------

export async function updateRepository(domain: string, domainOwner: string | undefined, repository: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      // One upstream per line, in the order CodeArtifact searches them.
      const upstreams = text(form, "upstreams")
        .split(/[\n,]+/)
        .map((u) => u.trim())
        .filter(Boolean);
      if (new Set(upstreams).size !== upstreams.length) throw new FieldError("upstreams", "Each upstream once", "format");
      await (await codeartifact()).send(
        new UpdateRepositoryCommand({ domain, domainOwner, repository, description: text(form, "description"), upstreams: upstreams.map((repositoryName) => ({ repositoryName })) }),
      );
      return "Saved";
    },
    { revalidate: ["/codeartifact/repo"], fields: { description: "description", upstreams: "upstreams", "upstreams.repositoryName": "upstreams", ResourceNotFoundException: "upstreams" } },
  );
}

export async function addExternalConnection(domain: string, domainOwner: string | undefined, repository: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      await (await codeartifact()).send(new AssociateExternalConnectionCommand({ domain, domainOwner, repository, externalConnection: required(form, "external", "Public repository") }));
      return "Connected";
    },
    { revalidate: ["/codeartifact/repo"], fields: { externalConnection: "external" } },
  );
}

export async function removeExternalConnection(domain: string, domainOwner: string | undefined, repository: string, externalConnection: string) {
  return act(async () => {
    await (await codeartifact()).send(new DisassociateExternalConnectionCommand({ domain, domainOwner, repository, externalConnection }));
    return "Disconnected";
  }, "/codeartifact/repo");
}

// Permissions policies ----------------------------------------------------------

export async function savePolicy(kind: "domain" | "repository", domain: string, domainOwner: string | undefined, repository: string | undefined, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const policyDocument = required(form, "policy", "Policy");
      const c = await codeartifact();
      if (kind === "domain") await c.send(new PutDomainPermissionsPolicyCommand({ domain, domainOwner, policyDocument }));
      else await c.send(new PutRepositoryPermissionsPolicyCommand({ domain, domainOwner, repository: repository!, policyDocument }));
      return "Policy saved";
    },
    { revalidate: ["/codeartifact/repo", "/codeartifact/domain"], fields: { policyDocument: "policy", ValidationException: "policy" } },
  );
}

export async function deletePolicy(kind: "domain" | "repository", domain: string, domainOwner: string | undefined, repository: string | undefined) {
  return act(async () => {
    const c = await codeartifact();
    if (kind === "domain") await c.send(new DeleteDomainPermissionsPolicyCommand({ domain, domainOwner }));
    else await c.send(new DeleteRepositoryPermissionsPolicyCommand({ domain, domainOwner, repository: repository! }));
    return "Policy removed";
  }, "/codeartifact/repo", "/codeartifact/domain");
}

// Package groups ------------------------------------------------------------------

export async function createPackageGroup(domain: string, domainOwner: string | undefined, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const packageGroup = required(form, "pattern", "Pattern");
      await (await codeartifact()).send(
        new CreatePackageGroupCommand({ domain, domainOwner, packageGroup, description: text(form, "description") || undefined, contactInfo: text(form, "contact") || undefined }),
      );
      redirect(groupHref(domain, packageGroup, domainOwner));
    },
    { fields: { packageGroup: "pattern", description: "description", contactInfo: "contact" } },
  );
}

export async function updatePackageGroup(domain: string, domainOwner: string | undefined, packageGroup: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      await (await codeartifact()).send(new UpdatePackageGroupCommand({ domain, domainOwner, packageGroup, description: text(form, "description"), contactInfo: text(form, "contact") }));
      return "Saved";
    },
    { revalidate: ["/codeartifact/group"], fields: { description: "description", contactInfo: "contact" } },
  );
}

const RESTRICTIONS: PackageGroupOriginRestrictionType[] = ["PUBLISH", "EXTERNAL_UPSTREAM", "INTERNAL_UPSTREAM"];

/** Origin controls: a mode per restriction, and the repositories an
 * ALLOW_SPECIFIC_REPOSITORIES restriction lets through (`allow_<TYPE>`, one per line). */
export async function setGroupOrigin(domain: string, domainOwner: string | undefined, packageGroup: string, current: Record<string, string[]>, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const restrictions = Object.fromEntries(RESTRICTIONS.map((t) => [t, (text(form, `mode_${t}`) || "INHERIT") as PackageGroupOriginRestrictionMode]));
      const add: { repositoryName: string; originRestrictionType: PackageGroupOriginRestrictionType }[] = [];
      const remove: typeof add = [];
      for (const t of RESTRICTIONS) {
        const wanted = text(form, `allow_${t}`)
          .split(/[\n,]+/)
          .map((r) => r.trim())
          .filter(Boolean);
        for (const r of wanted) if (!(current[t] ?? []).includes(r)) add.push({ repositoryName: r, originRestrictionType: t });
        for (const r of current[t] ?? []) if (!wanted.includes(r)) remove.push({ repositoryName: r, originRestrictionType: t });
      }
      await (await codeartifact()).send(
        new UpdatePackageGroupOriginConfigurationCommand({
          domain,
          domainOwner,
          packageGroup,
          restrictions,
          addAllowedRepositories: add.length ? add : undefined,
          removeAllowedRepositories: remove.length ? remove : undefined,
        }),
      );
      return "Saved";
    },
    { revalidate: ["/codeartifact/group"], fields: { addAllowedRepositories: "allow_PUBLISH", "addAllowedRepositories.repositoryName": "allow_PUBLISH", ResourceNotFoundException: "allow_PUBLISH" } },
  );
}

export async function deletePackageGroup(domain: string, domainOwner: string | undefined, packageGroup: string) {
  return act(async () => {
    await (await codeartifact()).send(new DeletePackageGroupCommand({ domain, domainOwner, packageGroup }));
    redirect(`${domainHref(domain, domainOwner)}&tab=groups`);
  });
}

