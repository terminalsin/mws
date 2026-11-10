import {
  DescribeRepositoryCommand,
  GetRepositoryEndpointCommand,
  GetRepositoryPermissionsPolicyCommand,
  ListPackagesCommand,
  ListRepositoriesInDomainCommand,
  type PackageFormat,
} from "@aws-sdk/client-codeartifact";
import { all, describeError, endpoint, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Field, List, Page, Pill, Section, Segments, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { UpdateRepository } from "@mws-dashboard/ui/model/codeartifact";
import { ArrowUpFromLine, Globe, Package, Pencil, Plus, Trash2, Unplug, User } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { codeartifact, FORMAT_ICONS, ICONS } from "../../../lib/clients";
import { EXTERNAL } from "../../../lib/external";
import { PolicySection } from "../../../lib/policy";
import { domainHref, packageHref, packageTitle, repoHref } from "../../../lib/refs";
import { addExternalConnection, deleteRepository, removeExternalConnection, updateRepository } from "../actions";

export const metadata: Metadata = { title: "Repository" };

type Props = { searchParams: Promise<{ domain?: string; owner?: string; name?: string; format?: string }> };

const FORMATS: [PackageFormat, string][] = [
  ["npm", "npm"],
  ["pypi", "pip"],
  ["maven", "Maven"],
  ["cargo", "Cargo"],
  ["nuget", "NuGet"],
  ["ruby", "RubyGems"],
  ["swift", "Swift"],
];

/** The tool's own configuration for this repository, with the token from the CLI. */
function instructions(format: string, url: string, domain: string, owner: string) {
  const token = `export CODEARTIFACT_AUTH_TOKEN=$(aws codeartifact get-authorization-token --domain ${domain} --domain-owner ${owner} --query authorizationToken --output text --endpoint-url ${endpoint()})`;
  const bare = url.replace(/^https?:/, "");
  const withAuth = url.replace(/^(https?:\/\/)/, "$1aws:${CODEARTIFACT_AUTH_TOKEN}@");
  const body: Record<string, string> = {
    npm: `npm config set registry ${url}\nnpm config set ${bare}:_authToken "\${CODEARTIFACT_AUTH_TOKEN}"`,
    pypi: `pip config set global.index-url ${withAuth}simple/\n\n# twine upload\nexport TWINE_USERNAME=aws TWINE_PASSWORD=$CODEARTIFACT_AUTH_TOKEN TWINE_REPOSITORY_URL=${url}`,
    maven: `<!-- settings.xml -->\n<server>\n  <id>${domain}</id>\n  <username>aws</username>\n  <password>\${env.CODEARTIFACT_AUTH_TOKEN}</password>\n</server>\n\n<!-- pom.xml -->\n<repository>\n  <id>${domain}</id>\n  <url>${url}</url>\n</repository>`,
    cargo: `# .cargo/config.toml\n[registries.${domain}]\nindex = "sparse+${url}"\ncredential-provider = "cargo:token-from-stdout echo Bearer $CODEARTIFACT_AUTH_TOKEN"`,
    nuget: `dotnet nuget add source ${url}v3/index.json --name ${domain} --username aws --password $CODEARTIFACT_AUTH_TOKEN --store-password-in-clear-text`,
    ruby: `gem sources --add ${withAuth}\nbundle config ${url} aws:$CODEARTIFACT_AUTH_TOKEN`,
    swift: `swift package-registry set ${url}\nswift package-registry login ${url}login --token $CODEARTIFACT_AUTH_TOKEN`,
  };
  return `${token}\n\n${body[format] ?? ""}`;
}

export default async function Repository({ searchParams }: Props) {
  const { domain = "", owner, name = "", format = "npm" } = await searchParams;
  const back = { href: "/codeartifact", label: "Repositories" };
  const base = repoHref(domain, name, owner);
  const data = await load(async () => {
    const client = await codeartifact();
    const args = { domain, domainOwner: owner, repository: name };
    const [repo, packages, url, siblings, policy] = await Promise.all([
      client.send(new DescribeRepositoryCommand(args)).then((r) => r.repository!),
      all((nextToken) => client.send(new ListPackagesCommand({ ...args, nextToken })), (r) => r.packages, (r) => r.nextToken),
      client.send(new GetRepositoryEndpointCommand({ ...args, format: format as PackageFormat })).then(
        (r) => ({ ok: true as const, url: r.repositoryEndpoint! }),
        (e: unknown) => ({ ok: false as const, error: describeError(e) }),
      ),
      all((nextToken) => client.send(new ListRepositoriesInDomainCommand({ domain, domainOwner: owner, nextToken })), (r) => r.repositories, (r) => r.nextToken).catch(() => []),
      client.send(new GetRepositoryPermissionsPolicyCommand(args)).then((r) => r.policy?.document, () => undefined),
    ]);
    return { repo, packages, url, siblings, policy };
  });
  if (!data.ok) {
    return (
      <Page title={name} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { repo, packages, url, siblings, policy } = data.value;
  const external = repo.externalConnections ?? [];
  const upstreams = repo.upstreams ?? [];
  const others = siblings.map((r) => r.name!).filter((r) => r !== name);
  const unused = EXTERNAL.filter(([v]) => !external.some((e) => e.externalConnectionName === v));
  const domainOwner = owner ?? repo.domainOwner;
  return (
    <Page
      title={name}
      icon={ICONS.codeartifact}
      back={back}
      subtitle={repo.arn}
      actions={
        <>
          <Sheet title="Edit repository" label="Edit repository" icon={<Pencil size={15} />} testId="edit-repository">
            <ActionForm action={updateRepository.bind(null, domain, owner, name)} submit="Save" testId="edit-repository">
              <Field label="Description" rule={UpdateRepository.description}>
                <input name="description" defaultValue={repo.description} />
              </Field>
              <Field label="Upstream repositories" hint={others.length ? `One per line, searched in order. In ${domain}: ${others.join(", ")}` : "One per line, searched in order"}>
                <textarea name="upstreams" rows={4} defaultValue={upstreams.map((u) => u.repositoryName).join("\n")} spellCheck={false} />
              </Field>
            </ActionForm>
          </Sheet>
          {unused.length > 0 && external.length === 0 && (
            <Sheet title="Connect a public repository" label="Add external connection" icon={<Plus size={15} />} testId="add-external">
              <ActionForm action={addExternalConnection.bind(null, domain, owner, name)} submit="Connect" testId="add-external">
                <Field label="Public repository" member="externalConnection">
                  <select name="external">
                    {unused.map(([v, l]) => (
                      <option key={v} value={v}>
                        {l}
                      </option>
                    ))}
                  </select>
                </Field>
              </ActionForm>
            </Sheet>
          )}
          <ActionForm action={deleteRepository.bind(null, domain, name)} submit="Delete repository" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name}?`} />
        </>
      }
    >
      <Specs
        items={[
          { label: "Domain", icon: <AwsIcon icon={ICONS.codeartifact} size={16} />, value: <Link href={domainHref(domain, owner)}>{domain}</Link> },
          { label: "Owner", icon: <User size={15} />, value: repo.domainOwner },
          external.length > 0 && { label: "Public upstream", icon: <Globe size={15} />, value: external.map((e) => e.externalConnectionName?.replace("public:", "")).join(", ") },
          { label: "Packages", icon: <Package size={15} />, value: packages.length },
        ]}
      />
      {repo.description && <p className="muted">{repo.description}</p>}
      {(upstreams.length > 0 || external.length > 0) && (
        <Section title="Upstreams" count={upstreams.length + external.length} plain>
          <List
            label="Upstreams"
            rows={[
              ...upstreams.map((u, i) => ({
                key: `u/${u.repositoryName}`,
                icon: <ArrowUpFromLine size={18} />,
                title: u.repositoryName,
                href: repoHref(domain, u.repositoryName!, owner),
                meta: <Pill>{i + 1}</Pill>,
              })),
              ...external.map((e) => ({
                key: `e/${e.externalConnectionName}`,
                icon: <Globe size={18} />,
                title: EXTERNAL.find(([v]) => v === e.externalConnectionName)?.[1] ?? e.externalConnectionName,
                subtitle: <code>{e.externalConnectionName}</code>,
                meta: (
                  <>
                    {e.packageFormat && <Pill>{e.packageFormat}</Pill>}
                    <Status tone={e.status === "Available" ? "good" : "warn"}>{e.status?.toLowerCase() ?? ""}</Status>
                  </>
                ),
                actions: (
                  <ActionForm
                    action={removeExternalConnection.bind(null, domain, owner, name, e.externalConnectionName!)}
                    submit={`Disconnect ${e.externalConnectionName}`}
                    icon={<Unplug size={15} />}
                    tone="danger"
                    confirm={`Disconnect ${e.externalConnectionName}?`}
                  />
                ),
              })),
            ]}
          />
        </Section>
      )}
      <Section title="Packages" count={packages.length} plain>
        <List
          label="Packages"
          empty={<Empty icon={ICONS.codeartifact} />}
          rows={packages.map((p) => ({
            key: `${p.format}/${p.namespace ?? ""}/${p.package}`,
            icon: <AwsIcon icon={FORMAT_ICONS[p.format ?? "generic"] ?? FORMAT_ICONS.generic} size={20} />,
            title: packageTitle(p.format ?? "", p.namespace, p.package!),
            href: packageHref({ domain, domainOwner: owner, repository: name, format: p.format!, namespace: p.namespace, package: p.package! }),
            meta: (
              <>
                {p.originConfiguration?.restrictions?.publish === "BLOCK" && <Pill tone="warn">publish blocked</Pill>}
                {p.originConfiguration?.restrictions?.upstream === "BLOCK" && <Pill tone="warn">upstream blocked</Pill>}
              </>
            ),
          }))}
        />
      </Section>
      <Section title="Connection instructions">
        <Segments
          label="Package manager"
          items={FORMATS.map(([f, label]) => ({
            label: (
              <>
                <AwsIcon icon={FORMAT_ICONS[f]} size={14} /> {label}
              </>
            ),
            href: `${base}&format=${f}`,
            active: f === format,
          }))}
        />
        {url.ok ? <CodeBlock value={instructions(format, url.url, domain, domainOwner!)} label="Commands" /> : <ErrorNotice error={url.error} />}
      </Section>
      <PolicySection kind="repository" domain={domain} owner={owner} repository={name} arn={repo.arn} policy={policy} />
    </Page>
  );
}
