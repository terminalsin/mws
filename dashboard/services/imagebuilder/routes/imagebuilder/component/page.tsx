import { GetComponentCommand, ListComponentBuildVersionsCommand } from "@aws-sdk/client-imagebuilder";
import { ago, all, load, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, ErrorNotice, Facts, List, Page, Section, Specs } from "@mws-dashboard/ui";
import { Clock, FileText, Puzzle, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, imagebuilder } from "../../../lib/clients";
import { versionOf } from "../../../lib/lists";
import { deleteResource } from "../actions";

export const metadata: Metadata = { title: "Component · Image Builder" };

type Props = { searchParams: Promise<{ arn?: string }> };

export default async function ComponentPage({ searchParams }: Props) {
  const { arn = "" } = await searchParams;
  const back = { href: "/imagebuilder?tab=components", label: "Components" };
  const data = await load(async () => {
    const client = await imagebuilder();
    // The list shows versions (name/x.y.z); GetComponent wants a build (name/x.y.z/n).
    const builds = await all(
      (nextToken) => client.send(new ListComponentBuildVersionsCommand({ componentVersionArn: arn.split("/").length > 3 ? arn.split("/").slice(0, 3).join("/") : arn, nextToken })),
      (r) => r.componentSummaryList,
      (r) => r.nextToken,
    ).catch(() => []);
    const build = arn.split("/").length > 3 ? arn : (builds.at(-1)?.arn ?? `${arn}/1`);
    const c = (await client.send(new GetComponentCommand({ componentBuildVersionArn: build }))).component;
    if (!c) throw new Error(`Component ${arn} not found`);
    return { c, builds };
  });
  if (!data.ok) {
    return (
      <Page title={arn.split("/")[1] ?? "Component"} icon={ICONS.imagebuilder} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { c, builds } = data.value;
  const own = c.owner !== "Amazon" && !c.arn?.includes(":aws:component/");
  return (
    <Page
      title={c.name}
      icon={ICONS.imagebuilder}
      back={back}
      subtitle={c.description}
      actions={own && <ActionForm action={deleteResource.bind(null, "component", c.arn!.split("/").slice(0, 3).join("/"))} submit="Delete component" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${c.name} ${c.version}?`} testId="delete-component" />}
    >
      <Specs
        items={[
          { label: "Version", icon: <FileText size={15} />, value: versionOf(c.arn) },
          { label: "Type", icon: <Puzzle size={15} />, value: c.type?.toLowerCase() },
          { label: "Platform", icon: <AwsIcon icon={ICONS.instance} size={16} />, value: c.platform },
          { label: "Created", icon: <Clock size={15} />, value: <span title={when(c.dateCreated)}>{ago(c.dateCreated)}</span> },
        ]}
      />
      <Section title="Details">
        <Facts
          items={[
            ["ARN", <code key="a">{c.arn}</code>],
            c.owner && ["Owner", c.owner],
            c.changeDescription && ["Change", c.changeDescription],
            (c.supportedOsVersions ?? []).length > 0 && ["OS versions", c.supportedOsVersions!.join(", ")],
            c.encrypted !== undefined && ["Encrypted", c.encrypted ? (c.kmsKeyId ?? "Yes") : "No"],
            c.state?.status && ["State", c.state.status.toLowerCase()],
            ...(c.parameters ?? []).map((p): [string, string] => [`Parameter ${p.name}`, `${p.type}${p.defaultValue?.length ? ` = ${p.defaultValue.join(", ")}` : ""}`]),
          ]}
        />
      </Section>
      {c.data && (
        <Section title="Content">
          <CodeBlock value={c.data} label="Component document" />
        </Section>
      )}
      {builds.length > 1 && (
        <Section title="Builds" count={builds.length} plain>
          <List label="Builds" rows={builds.map((b) => ({ key: b.arn!, title: versionOf(b.arn), meta: <span>{ago(b.dateCreated)}</span> }))} />
        </Section>
      )}
    </Page>
  );
}
