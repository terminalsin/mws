import { ListInstanceProfilesCommand } from "@aws-sdk/client-iam";
import {
  ListComponentsCommand,
  ListImageBuildVersionsCommand,
  ListImagePipelinesCommand,
  ListImageRecipesCommand,
  ListImagesCommand,
  ListInfrastructureConfigurationsCommand,
} from "@aws-sdk/client-imagebuilder";
import { DescribeInstanceTypesCommand } from "@aws-sdk/client-ec2";
import { ago, load } from "@mws-dashboard/aws";
import { AutoPick, ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Section, Sheet, Status, type Rule } from "@mws-dashboard/ui";
import { CreateComponent, CreateImagePipeline, CreateImageRecipe, CreateInfrastructureConfiguration } from "@mws-dashboard/ui/model/imagebuilder";
import { CalendarClock, FlaskConical, Pause, Play, Puzzle, Server, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ec2, iam, ICONS, imagebuilder, tone } from "../../lib/clients";
import { createComponent, createInfrastructure, createPipeline, createRecipe, deleteResource, runPipeline, setPipelineEnabled } from "./actions";

export const metadata: Metadata = { title: "Image Builder" };

type Props = { searchParams: Promise<{ tab?: string }> };

const TABS = { pipelines: "Image pipelines", images: "Images", recipes: "Image recipes", components: "Components", infrastructure: "Infrastructure configurations" } as Record<string, string>;

const SAMPLE = `name: install-nginx
schemaVersion: 1.0
phases:
  - name: build
    steps:
      - name: Install
        action: ExecuteBash
        inputs:
          commands:
            - sudo dnf install -y nginx
  - name: validate
    steps:
      - name: Check
        action: ExecuteBash
        inputs:
          commands:
            - nginx -v
`;

// Image Builder's name pattern reads badly as text; every resource shares it.
const named = (rule: Rule): Rule => ({ ...rule, hint: "Letters, digits, spaces, - and _", generate: "name" });
const NAMES = {
  component: named(CreateComponent.name),
  recipe: named(CreateImageRecipe.name),
  infrastructure: named(CreateInfrastructureConfiguration.name),
  pipeline: named(CreateImagePipeline.name),
};
const SCHEDULE: Rule = { ...CreateImagePipeline.schedule.fields!.scheduleExpression, format: "cron" };

/** "arn:…:image/name/1.2.3/4" → "1.2.3/4". */
const versionOf = (arn: string | undefined) => arn?.split("/").slice(2).join("/");
const osIcon = (platform: string | undefined, os: string | undefined) =>
  /ubuntu/i.test(os ?? "") ? "brand/ubuntu" : platform === "Windows" ? "resource/AmazonEC2AMI" : "brand/linux";

async function Pipelines() {
  const client = await imagebuilder();
  const data = await load(async () => {
    const [pipelines, recipes, infra] = await Promise.all([
      client.send(new ListImagePipelinesCommand({})).then((r) => r.imagePipelineList ?? []),
      client.send(new ListImageRecipesCommand({ owner: "Self" })).then((r) => r.imageRecipeSummaryList ?? []),
      client.send(new ListInfrastructureConfigurationsCommand({})).then((r) => r.infrastructureConfigurationSummaryList ?? []),
    ]);
    return { pipelines, recipes, infra };
  });
  if (!data.ok) return { body: <ErrorNotice error={data.error} />, action: null };
  const { pipelines, recipes, infra } = data.value;
  const action =
    recipes.length ? (
      <Sheet title="Create image pipeline" label="Create image pipeline" testId="create-pipeline">
        <ActionForm action={createPipeline} submit="Create pipeline" testId="create-pipeline">
          <Field label="Name" rule={NAMES.pipeline} taken={pipelines.map((p) => p.name!)} unique>
            <input name="name" required autoFocus />
          </Field>
          <Field label="Recipe">
            <select name="recipe">
              {recipes.map((r) => (
                <option key={r.arn} value={r.arn}>
                  {r.name} {versionOf(r.arn)}
                </option>
              ))}
            </select>
          </Field>
          <AutoPick name="infrastructure" label="Infrastructure configuration" creates="default · EC2InstanceProfileForImageBuilder" options={infra.map((i) => ({ value: i.arn!, label: i.name! }))} testId="pipeline-infrastructure" />
          <Field label="Schedule (cron)" rule={SCHEDULE} member="scheduleExpression">
            <input name="cron" placeholder="0 0 * * ? *  (manual if empty)" spellCheck={false} />
          </Field>
          <label className="check">
            <input type="checkbox" name="tests" defaultChecked /> Run image tests
          </label>
        </ActionForm>
      </Sheet>
    ) : null;
  return {
    action,
    body: (
      <List
        label="Image pipelines"
        empty={<Empty icon={ICONS.imagebuilder}>{!recipes.length ? "Create a recipe first" : !infra.length ? "Create an infrastructure configuration first" : null}</Empty>}
        rows={pipelines.map((p) => {
          const enabled = p.status === "ENABLED";
          return {
            key: p.arn!,
            icon: <AwsIcon icon={ICONS.imagebuilder} size={22} />,
            title: p.name,
            subtitle: p.imageRecipeArn ? `${p.imageRecipeArn.split("/")[1]} ${versionOf(p.imageRecipeArn)}` : p.containerRecipeArn?.split("/")[1],
            meta: (
              <>
                {p.schedule?.scheduleExpression && <CalendarClock size={13} aria-label={p.schedule.scheduleExpression}><title>{p.schedule.scheduleExpression}</title></CalendarClock>}
                {p.imageTestsConfiguration?.imageTestsEnabled && <FlaskConical size={13} aria-label="Image tests"><title>Image tests</title></FlaskConical>}
                {!enabled && <Status tone="neutral">disabled</Status>}
                {p.dateLastRun && <span>{ago(p.dateLastRun)}</span>}
              </>
            ),
            actions: (
              <>
                <ActionForm action={runPipeline.bind(null, p.arn!)} submit={`Run ${p.name}`} icon={<Play size={15} />} />
                <ActionForm action={setPipelineEnabled.bind(null, p.arn!, !enabled)} submit={enabled ? `Disable ${p.name}` : `Enable ${p.name}`} icon={enabled ? <Pause size={15} /> : <Play size={15} />} />
                <ActionForm action={deleteResource.bind(null, "pipeline", p.arn!)} submit={`Delete ${p.name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${p.name}?`} />
              </>
            ),
          };
        })}
      />
    ),
  };
}

async function Images() {
  const client = await imagebuilder();
  const data = await load(async () => {
    const versions = (await client.send(new ListImagesCommand({ owner: "Self" }))).imageVersionList ?? [];
    const builds = await Promise.all(versions.slice(0, 50).map((v) => client.send(new ListImageBuildVersionsCommand({ imageVersionArn: v.arn })).then((r) => r.imageSummaryList ?? [], () => [])));
    return builds.flat().sort((a, b) => (b.dateCreated ?? "").localeCompare(a.dateCreated ?? ""));
  });
  if (!data.ok) return <ErrorNotice error={data.error} />;
  return (
    <List
      label="Images"
      empty={<Empty icon={ICONS.ami} />}
      rows={data.value.map((i) => {
        const amis = i.outputResources?.amis ?? [];
        return {
          key: i.arn!,
          icon: <AwsIcon icon={osIcon(i.platform, i.osVersion)} size={20} />,
          title: i.name,
          subtitle: (
            <>
              <code>{versionOf(i.arn)}</code>
              {amis.length > 0 && (
                <>
                  {" · "}
                  <Link href={"/ec2?tab=images"}>{amis.map((a) => (a.region === amis[0].region ? a.image : `${a.image} (${a.region})`)).join(", ")}</Link>
                </>
              )}
            </>
          ),
          meta: (
            <>
              {i.osVersion && <span>{i.osVersion}</span>}
              <Status tone={tone(i.state?.status)}>{i.state?.status?.toLowerCase()}</Status>
              <span>{ago(i.dateCreated)}</span>
            </>
          ),
        };
      })}
    />
  );
}

async function Recipes() {
  const client = await imagebuilder();
  const data = await load(async () => {
    const [recipes, components, parents] = await Promise.all([
      client.send(new ListImageRecipesCommand({ owner: "Self" })).then((r) => r.imageRecipeSummaryList ?? []),
      Promise.all([
        client.send(new ListComponentsCommand({ owner: "Self" })).then((r) => r.componentVersionList ?? []),
        client.send(new ListComponentsCommand({ owner: "Amazon" })).then((r) => r.componentVersionList ?? []),
      ]).then(([a, b]) => [...a, ...b]),
      client.send(new ListImagesCommand({ owner: "Amazon" })).then((r) => r.imageVersionList ?? []),
    ]);
    return { recipes, components, parents };
  });
  if (!data.ok) return { body: <ErrorNotice error={data.error} />, action: null };
  const { recipes, components, parents } = data.value;
  const action = (
    <Sheet title="Create image recipe" label="Create image recipe" testId="create-recipe">
      <ActionForm action={createRecipe} submit="Create recipe" testId="create-recipe">
        <div className="form-row">
          <Field label="Name" rule={NAMES.recipe}>
            <input name="name" required autoFocus />
          </Field>
          <Field label="Version" rule={CreateImageRecipe.semanticVersion} format="semver" member="semanticVersion" unique>
            <input name="version" required defaultValue="1.0.0" />
          </Field>
        </div>
        <Field label="Base image" member="parentImage">
          <select name="parent">
            {parents.map((p) => (
              <option key={p.arn} value={p.arn}>
                {p.name}
              </option>
            ))}
          </select>
        </Field>
        <fieldset className="checks">
          <legend>Components</legend>
          {components
            .filter((c) => c.type !== "TEST" && c.platform !== "Windows")
            .map((c) => (
              <label key={c.arn} className="check">
                <input type="checkbox" name="component" value={c.arn} defaultChecked={c.name === "update-linux"} /> {c.name}
                {c.owner !== "Amazon" && <Pill>own</Pill>}
              </label>
            ))}
        </fieldset>
      </ActionForm>
    </Sheet>
  );
  return {
    action,
    body: (
      <List
        label="Image recipes"
        empty={<Empty icon={ICONS.imagebuilder} action={action} />}
        rows={recipes.map((r) => ({
          key: r.arn!,
          icon: <AwsIcon icon={osIcon(r.platform, r.parentImage)} size={20} />,
          title: r.name,
          subtitle: r.parentImage?.split("/")[1] ?? r.parentImage,
          meta: (
            <>
              <code>{versionOf(r.arn)}</code>
              <span>{ago(r.dateCreated)}</span>
            </>
          ),
          actions: <ActionForm action={deleteResource.bind(null, "recipe", r.arn!)} submit={`Delete ${r.name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${r.name}?`} />,
        }))}
      />
    ),
  };
}

async function Components() {
  const data = await load(async () => (await (await imagebuilder()).send(new ListComponentsCommand({ owner: "Self" }))).componentVersionList ?? []);
  const action = (
    <Sheet title="Create component" label="Create component" testId="create-component">
      <ActionForm action={createComponent} submit="Create component" testId="create-component">
        <div className="form-row">
          <Field label="Name" rule={NAMES.component}>
            <input name="name" required autoFocus />
          </Field>
          <Field label="Version" rule={CreateComponent.semanticVersion} format="semver" member="semanticVersion" unique>
            <input name="version" required defaultValue="1.0.0" />
          </Field>
        </div>
        <Field label="Document" rule={CreateComponent.data}>
          <textarea name="data" rows={16} className="code-editor" spellCheck={false} defaultValue={SAMPLE} />
        </Field>
      </ActionForm>
    </Sheet>
  );
  if (!data.ok) return { body: <ErrorNotice error={data.error} />, action };
  return {
    action,
    body: (
      <List
        label="Components"
        empty={<Empty icon={ICONS.imagebuilder} action={action} />}
        rows={data.value.map((c) => ({
          key: c.arn!,
          icon: <Puzzle size={18} />,
          title: c.name,
          subtitle: c.description,
          meta: (
            <>
              <Pill tone={c.type === "TEST" ? "info" : "neutral"}>{c.type?.toLowerCase()}</Pill>
              <code>{c.version}</code>
              <span>{ago(c.dateCreated)}</span>
            </>
          ),
          actions: <ActionForm action={deleteResource.bind(null, "component", c.arn!)} submit={`Delete ${c.name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${c.name}?`} />,
        }))}
      />
    ),
  };
}

/** The instance types EC2 offers, so a typo gets a "did you mean". */
async function instanceTypes(): Promise<string[]> {
  const out: string[] = [];
  try {
    const client = await ec2();
    let NextToken: string | undefined;
    do {
      const page = await client.send(new DescribeInstanceTypesCommand({ NextToken, MaxResults: 100 }));
      out.push(...(page.InstanceTypes ?? []).map((t) => t.InstanceType!).filter(Boolean));
      NextToken = page.NextToken;
    } while (NextToken && out.length < 2000);
  } catch {
    return [];
  }
  return out.sort();
}

async function Infrastructure() {
  const data = await load(async () => {
    const [infra, profiles, types] = await Promise.all([
      (await imagebuilder()).send(new ListInfrastructureConfigurationsCommand({})).then((r) => r.infrastructureConfigurationSummaryList ?? []),
      (await iam()).send(new ListInstanceProfilesCommand({})).then((r) => r.InstanceProfiles ?? [], () => []),
      instanceTypes(),
    ]);
    return { infra, profiles, types };
  });
  if (!data.ok) return { body: <ErrorNotice error={data.error} />, action: null };
  const { infra, profiles, types } = data.value;
  const action = (
    <Sheet title="Create infrastructure configuration" label="Create infrastructure configuration" testId="create-infrastructure">
      <ActionForm action={createInfrastructure} submit="Create" testId="create-infrastructure">
        <Field label="Name" rule={NAMES.infrastructure} taken={infra.map((i) => i.name!)} unique>
          <input name="name" required autoFocus />
        </Field>
        <Field label="Instance profile" member="instanceProfileName">
          <select name="profile">
            {profiles.map((p) => (
              <option key={p.Arn} value={p.InstanceProfileName}>
                {p.InstanceProfileName}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Instance type" rule={types.length ? { enum: types } : undefined} member="instanceTypes">
          <input name="type" placeholder="m5.large" spellCheck={false} />
        </Field>
      </ActionForm>
    </Sheet>
  );
  return {
    action,
    body: (
      <List
        label="Infrastructure configurations"
        empty={<Empty icon={ICONS.instance} action={action} />}
        rows={infra.map((i) => ({
          key: i.arn!,
          icon: <Server size={18} />,
          title: i.name,
          subtitle: i.instanceProfileName,
          meta: (
            <>
              {(i.instanceTypes ?? []).map((t) => (
                <Pill key={t}>{t}</Pill>
              ))}
              <span>{ago(i.dateCreated)}</span>
            </>
          ),
          actions: <ActionForm action={deleteResource.bind(null, "infrastructure", i.arn!)} submit={`Delete ${i.name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${i.name}?`} />,
        }))}
      />
    ),
  };
}

export default async function ImageBuilder({ searchParams }: Props) {
  const { tab = "pipelines" } = await searchParams;
  const view =
    tab === "images"
      ? { body: await Images(), action: null }
      : tab === "recipes"
        ? await Recipes()
        : tab === "components"
          ? await Components()
          : tab === "infrastructure"
            ? await Infrastructure()
            : await Pipelines();
  return (
    <Page title={TABS[tab] ?? TABS.pipelines} actions={view.action ?? undefined}>
      <Section plain>{view.body}</Section>
    </Page>
  );
}
