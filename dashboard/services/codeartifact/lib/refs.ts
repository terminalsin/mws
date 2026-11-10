// Links between CodeArtifact pages. A domain can belong to another account
// (shared through its domain policy), so every link carries the owner.

export interface PackageRef {
  domain: string;
  domainOwner?: string;
  repository: string;
  format: string;
  namespace?: string;
  package: string;
}

const q = (o: Record<string, string | undefined>) =>
  new URLSearchParams(Object.entries(o).filter(([, v]) => v) as [string, string][]).toString();

export const domainHref = (domain: string, owner?: string) => `/codeartifact/domain?${q({ name: domain, owner })}`;
export const repoHref = (domain: string, repo: string, owner?: string, extra: Record<string, string | undefined> = {}) =>
  `/codeartifact/repo?${q({ domain, name: repo, owner, ...extra })}`;
export const packageHref = (p: PackageRef) =>
  `/codeartifact/package?${q({ domain: p.domain, owner: p.domainOwner, repo: p.repository, format: p.format, namespace: p.namespace, package: p.package })}`;
export const versionHref = (p: PackageRef, version: string) =>
  `/codeartifact/version?${q({ domain: p.domain, owner: p.domainOwner, repo: p.repository, format: p.format, namespace: p.namespace, package: p.package, version })}`;
export const groupHref = (domain: string, pattern: string, owner?: string) => `/codeartifact/group?${q({ domain, owner, pattern })}`;

/** How each ecosystem writes a namespaced name. */
export function packageTitle(format: string, namespace: string | undefined, pkg: string) {
  if (!namespace) return pkg;
  if (format === "npm") return `@${namespace}/${pkg}`;
  if (format === "swift" || format === "generic") return `${namespace}/${pkg}`;
  return `${namespace}:${pkg}`;
}
