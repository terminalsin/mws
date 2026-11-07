import { DescribeRepositoryCommand, GetRepositoryEndpointCommand, ListPackagesCommand, type PackageFormat } from "@aws-sdk/client-codeartifact";
import { collect, endpoint, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, List, Page, Pill, Section, Segments, Specs } from "@mws-dashboard/ui";
import { ArrowUpFromLine, Globe, Package, Trash2, User } from "lucide-react";
import type { Metadata } from "next";

import { codeartifact, FORMAT_ICONS, ICONS } from "../../../lib/clients";
import { deleteRepository } from "../actions";

export const metadata: Metadata = { title: "Repository" };

type Props = { searchParams: Promise<{ domain?: string; name?: string; format?: string }> };

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
  const { domain = "", name = "", format = "npm" } = await searchParams;
  const back = { href: "/codeartifact", label: "Repositories" };
  const base = `/codeartifact/repo?domain=${encodeURIComponent(domain)}&name=${encodeURIComponent(name)}`;
  const data = await load(async () => {
    const client = await codeartifact();
    const [repo, packages, url] = await Promise.all([
      client.send(new DescribeRepositoryCommand({ domain, repository: name })).then((r) => r.repository!),
      collect((nextToken) => client.send(new ListPackagesCommand({ domain, repository: name, nextToken })), (r) => r.packages, (r) => r.nextToken),
      client.send(new GetRepositoryEndpointCommand({ domain, repository: name, format: format as PackageFormat })).then((r) => r.repositoryEndpoint!, () => ""),
    ]);
    return { repo, packages, url };
  });
  if (!data.ok) {
    return (
      <Page title={name} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { repo, packages, url } = data.value;
  const external = repo.externalConnections ?? [];
  return (
    <Page
      title={name}
      icon={ICONS.codeartifact}
      back={back}
      subtitle={repo.arn}
      actions={<ActionForm action={deleteRepository.bind(null, domain, name)} submit="Delete repository" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name}?`} />}
    >
      <Specs
        items={[
          { label: "Domain", icon: <AwsIcon icon={ICONS.codeartifact} size={16} />, value: domain },
          { label: "Owner", icon: <User size={15} />, value: repo.domainOwner },
          (repo.upstreams?.length ?? 0) > 0 && { label: "Upstreams", icon: <ArrowUpFromLine size={15} />, value: repo.upstreams!.map((u) => u.repositoryName).join(", ") },
          external.length > 0 && { label: "Public upstream", icon: <Globe size={15} />, value: external.map((e) => e.externalConnectionName?.replace("public:", "")).join(", ") },
          { label: "Packages", icon: <Package size={15} />, value: packages.length },
        ]}
      />
      <Section title="Packages" count={packages.length} plain>
        <List
          label="Packages"
          empty={<Empty icon={ICONS.codeartifact} />}
          rows={packages.map((p) => ({
            key: `${p.format}/${p.namespace ?? ""}/${p.package}`,
            icon: <AwsIcon icon={FORMAT_ICONS[p.format ?? "generic"] ?? FORMAT_ICONS.generic} size={20} />,
            title: p.namespace ? `${p.format === "npm" ? "@" : ""}${p.namespace}${p.format === "npm" ? "/" : ":"}${p.package}` : p.package,
            href: `/codeartifact/package?domain=${encodeURIComponent(domain)}&repo=${encodeURIComponent(name)}&format=${p.format}&package=${encodeURIComponent(p.package!)}${p.namespace ? `&namespace=${encodeURIComponent(p.namespace)}` : ""}`,
            meta: p.originConfiguration?.restrictions?.upstream === "BLOCK" ? <Pill tone="warn">upstream blocked</Pill> : undefined,
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
        <CodeBlock value={url ? instructions(format, url, domain, repo.domainOwner!) : undefined} label="Commands" />
      </Section>
    </Page>
  );
}
