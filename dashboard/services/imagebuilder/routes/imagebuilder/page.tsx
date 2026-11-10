import { ListInstanceProfilesCommand } from "@aws-sdk/client-iam";
import { GetInfrastructureConfigurationCommand } from "@aws-sdk/client-imagebuilder";
import { DescribeInstanceTypesCommand } from "@aws-sdk/client-ec2";
import { ago, all, load } from "@mws-dashboard/aws";
import { AutoPick, ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, More, Page, Pill, Section, Segments, Sheet, Status, type Rule } from "@mws-dashboard/ui";
import { CreateComponent, CreateImagePipeline, CreateImageRecipe, CreateInfrastructureConfiguration } from "@mws-dashboard/ui/model/imagebuilder";
import { CalendarClock, FlaskConical, Pause, Pencil, Play, Puzzle, Server, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ec2, iam, ICONS, imagebuilder, tone } from "../../lib/clients";
import * as lists from "../../lib/lists";
import { versionOf } from "../../lib/lists";
import { createComponent, createInfrastructure, createPipeline, createRecipe, deleteResource, runPipeline, setPipelineEnabled, updateInfrastructure } from "./actions";
import { ContainerRecipes, Distributions, LifecyclePolicies, Workflows } from "./tabs";

export const metadata: Metadata = { title: "Image Builder" };

type Props = { searchParams: Promise<{ tab?: string; page?: string }> };

const TABS: [string, string][] = [
  ["pipelines", "Image pipelines"],
  ["images", "Images"],
  ["recipes", "Image recipes"],
  ["containers", "Container recipes"],
  ["components", "Components"],
  ["workflows", "Image workflows"],
  ["infrastructure", "Infrastructure configurations"],
  ["distribution", "Distribution settings"],
  ["lifecycle", "Lifecycle policies"],
];

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
const PAGE = 50;

const osIcon = (platform: string | undefined, os: string | undefined) =>
  /ubuntu/i.test(os ?? "") ? "brand/ubuntu" : platform === "Windows" ? "resource/AmazonEC2AMI" : "brand/linux";
const enc = encodeURIComponent;

async function Pipelines() {
  const data = await load(async () => {
    const [pipelines, recipes, containers, infra, distributions] = await Promise.all([lists.pipelines(), lists.recipes(), lists.containerRecipes(), lists.infrastructures(), lists.distributions()]);
    return { pipelines, recipes, containers, infra, distributions };
  });
  if (!data.ok) return { body: <ErrorNotice error={data.error} />, action: null };
  const { pipelines, recipes, containers, infra, distributions } = data.value;
  const action =
    recipes.length || containers.length ? (
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
              {containers.map((r) => (
                <option key={r.arn} value={r.arn}>
                  {r.name} {versionOf(r.arn)} (container)
                </option>
              ))}
            </select>
          </Field>
          <AutoPick name="infrastructure" label="Infrastructure configuration" creates="default · EC2InstanceProfileForImageBuilder" options={infra.map((i) => ({ value: i.arn!, label: i.name! }))} testId="pipeline-infrastructure" />
          {distributions.length > 0 && (
            <Field label="Distribution settings">
              <select name="distribution" defaultValue="">
                <option value="">This Region only</option>
                {distributions.map((d) => (
                  <option key={d.arn} value={d.arn}>
                    {d.name} ({(d.regions ?? []).join(", ")})
                  </option>
                ))}
              </select>
            </Field>
          )}
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
        empty={<Empty icon={ICONS.imagebuilder}>{!recipes.length && !containers.length ? "Create a recipe first" : null}</Empty>}
        rows={pipelines.map((p) => {
          const enabled = p.status === "ENABLED";
          return {
            key: p.arn!,
            icon: <AwsIcon icon={ICONS.imagebuilder} size={22} />,
            title: p.name,
            subtitle: [
              p.imageRecipeArn ? `${p.imageRecipeArn.split("/")[1]} ${versionOf(p.imageRecipeArn)}` : p.containerRecipeArn?.split("/")[1],
              p.schedule?.scheduleExpression,
              p.dateNextRun ? `next ${ago(p.dateNextRun)}` : "",
            ]
              .filter(Boolean)
              .join(" · "),
            href: `/imagebuilder/pipeline?arn=${enc(p.arn!)}`,
            meta: (
              <>
                {p.schedule?.scheduleExpression && (
                  <CalendarClock size={13} aria-label={p.schedule.scheduleExpression}>
                    <title>{p.schedule.scheduleExpression}</title>
                  </CalendarClock>
                )}
                {p.imageTestsConfiguration?.imageTestsEnabled && (
                  <FlaskConical size={13} aria-label="Image tests">
                    <title>Image tests</title>
                  </FlaskConical>
                )}
                {!enabled && <Status tone="neutral">disabled</Status>}
                {p.lastRunStatus && <Status tone={tone(p.lastRunStatus)}>{p.lastRunStatus.toLowerCase()}</Status>}
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

async function Images({ page }: { page: number }) {
  const data = await load(() => lists.builds());
  if (!data.ok) return <ErrorNotice error={data.error} />;
  const shown = data.value.slice(page, page + PAGE);
  return (
    <>
      <List
        label="Images"
        empty={<Empty icon={ICONS.ami} />}
        rows={shown.map((i) => {
          const amis = i.outputResources?.amis ?? [];
          const containers = i.outputResources?.containers ?? [];
          return {
            key: i.arn!,
            icon: <AwsIcon icon={i.type === "DOCKER" ? "resource/AmazonElasticContainerRegistryImage" : osIcon(i.platform, i.osVersion)} size={20} />,
            title: i.name,
            subtitle: [versionOf(i.arn), ...amis.map((a) => (a.region === amis[0].region ? a.image : `${a.image} (${a.region})`)), ...containers.flatMap((c) => c.imageUris ?? [])].filter(Boolean).join(" · "),
            href: `/imagebuilder/image?arn=${enc(i.arn!)}`,
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
      <More shown={page + shown.length} noun={`of ${data.value.length} images`} href={page + PAGE < data.value.length ? `/imagebuilder?tab=images&page=${page + PAGE}` : undefined} />
    </>
  );
}

async function Recipes() {
  const data = await load(async () => {
    const [recipes, own, amazon, parents, ownImages] = await Promise.all([lists.recipes(), lists.components("Self"), lists.components("Amazon"), lists.images("Amazon"), lists.images("Self")]);
    return { recipes, components: [...own, ...amazon], parents, ownImages };
  });
  if (!data.ok) return { body: <ErrorNotice error={data.error} />, action: null };
  const { recipes, components, parents, ownImages } = data.value;
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
        <Field label="Base image" rule={CreateImageRecipe.parentImage} member="parentImage" hint="An Image Builder image, an AMI ID or ssm:/parameter" known={[...parents, ...ownImages].map((p) => p.arn!)}>
          <input name="parent" required list="imagebuilder-parents" defaultValue={parents[0]?.arn} spellCheck={false} />
        </Field>
        <datalist id="imagebuilder-parents">
          {[...parents, ...ownImages].map((p) => (
            <option key={p.arn} value={p.arn}>
              {p.name}
            </option>
          ))}
        </datalist>
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
        <Field label="Working directory" rule={CreateImageRecipe.workingDirectory}>
          <input name="workdir" placeholder="/tmp" spellCheck={false} />
        </Field>
        <Field label="User data" rule={CreateImageRecipe.additionalInstanceConfiguration?.fields?.userDataOverride}>
          <textarea name="userData" rows={3} spellCheck={false} placeholder="#!/bin/bash" />
        </Field>
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
  const data = await load(() => lists.components("Self"));
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
          href: `/imagebuilder/component?arn=${enc(c.arn!)}`,
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
  try {
    const client = await ec2();
    const types = await all(
      (NextToken) => client.send(new DescribeInstanceTypesCommand({ NextToken, MaxResults: 100 })),
      (r) => r.InstanceTypes,
      (r) => r.NextToken,
    );
    return types.map((t) => t.InstanceType!).filter(Boolean).sort();
  } catch {
    return [];
  }
}

type Infra = Awaited<ReturnType<typeof lists.infrastructures>>[number];
type InfraDetail = { subnetId?: string; securityGroupIds?: string[]; keyPair?: string; snsTopicArn?: string; logging?: { s3Logs?: { s3BucketName?: string; s3KeyPrefix?: string } }; instanceMetadataOptions?: { httpTokens?: string }; terminateInstanceOnFailure?: boolean; description?: string };

function InfrastructureFields({ profiles, types, i, d }: { profiles: string[]; types: string[]; i?: Infra; d?: InfraDetail }) {
  return (
    <>
      <Field label="Instance profile" member="instanceProfileName">
        <select name="profile" defaultValue={i?.instanceProfileName}>
          {profiles.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Instance types" rule={types.length ? { type: "list", item: { enum: types } } : undefined} member="instanceTypes">
        <input name="type" placeholder="m5.large" spellCheck={false} defaultValue={(i?.instanceTypes ?? []).join(", ")} />
      </Field>
      <div className="form-row">
        <Field label="Subnet" rule={CreateInfrastructureConfiguration.subnetId} member="subnetId">
          <input name="subnet" placeholder="subnet-…" spellCheck={false} defaultValue={d?.subnetId} />
        </Field>
        <Field label="Security groups" member="securityGroupIds">
          <input name="groups" placeholder="sg-…" spellCheck={false} defaultValue={(d?.securityGroupIds ?? []).join(", ")} />
        </Field>
      </div>
      <div className="form-row">
        <Field label="Key pair" rule={CreateInfrastructureConfiguration.keyPair} member="keyPair">
          <input name="keyPair" spellCheck={false} defaultValue={d?.keyPair} />
        </Field>
        <Field label="SNS topic" rule={CreateInfrastructureConfiguration.snsTopicArn} format="arn" member="snsTopicArn">
          <input name="topic" spellCheck={false} defaultValue={d?.snsTopicArn} />
        </Field>
      </div>
      <div className="form-row">
        <Field label="Log bucket" format="bucket">
          <input name="logBucket" spellCheck={false} defaultValue={d?.logging?.s3Logs?.s3BucketName} />
        </Field>
        <Field label="Log prefix">
          <input name="logPrefix" spellCheck={false} defaultValue={d?.logging?.s3Logs?.s3KeyPrefix} />
        </Field>
        <Field label="IMDS">
          <select name="imds" defaultValue={d?.instanceMetadataOptions?.httpTokens ?? "required"}>
            <option value="required">IMDSv2 only</option>
            <option value="optional">IMDSv1 and v2</option>
          </select>
        </Field>
      </div>
      <label className="check">
        <input type="checkbox" name="keep" defaultChecked={d ? d.terminateInstanceOnFailure === false : false} /> Keep the instance when a build fails
      </label>
    </>
  );
}

async function Infrastructure() {
  const data = await load(async () => {
    const client = await imagebuilder();
    const [infra, profiles, types] = await Promise.all([
      lists.infrastructures(),
      iam()
        .then((c) =>
          all(
            (Marker) => c.send(new ListInstanceProfilesCommand({ Marker })),
            (r) => r.InstanceProfiles,
            (r) => (r.IsTruncated ? r.Marker : undefined),
          ),
        )
        .catch(() => []),
      instanceTypes(),
    ]);
    const details = await Promise.all(infra.map((i) => client.send(new GetInfrastructureConfigurationCommand({ infrastructureConfigurationArn: i.arn })).then((r) => r.infrastructureConfiguration as InfraDetail | undefined, () => undefined)));
    return { infra, details, profiles: profiles.map((p) => p.InstanceProfileName!), types };
  });
  if (!data.ok) return { body: <ErrorNotice error={data.error} />, action: null };
  const { infra, details, profiles, types } = data.value;
  const action = (
    <Sheet title="Create infrastructure configuration" label="Create infrastructure configuration" testId="create-infrastructure">
      <ActionForm action={createInfrastructure} submit="Create" testId="create-infrastructure">
        <Field label="Name" rule={NAMES.infrastructure} taken={infra.map((i) => i.name!)} unique>
          <input name="name" required autoFocus />
        </Field>
        <InfrastructureFields profiles={profiles} types={types} />
      </ActionForm>
    </Sheet>
  );
  return {
    action,
    body: (
      <List
        label="Infrastructure configurations"
        empty={<Empty icon={ICONS.instance} action={action} />}
        rows={infra.map((i, n) => {
          const d = details[n];
          return {
            key: i.arn!,
            icon: <Server size={18} />,
            title: i.name,
            subtitle: [i.instanceProfileName, d?.subnetId, d?.keyPair].filter(Boolean).join(" · "),
            meta: (
              <>
                {(i.instanceTypes ?? []).map((t) => (
                  <Pill key={t}>{t}</Pill>
                ))}
                <span>{ago(i.dateCreated)}</span>
              </>
            ),
            actions: (
              <>
                <Sheet title={`Edit ${i.name}`} label={`Edit ${i.name}`} icon={<Pencil size={15} />} testId="edit-infrastructure">
                  <ActionForm action={updateInfrastructure.bind(null, i.arn!)} submit="Save" testId="edit-infrastructure">
                    <InfrastructureFields profiles={profiles} types={types} i={i} d={d} />
                  </ActionForm>
                </Sheet>
                <ActionForm action={deleteResource.bind(null, "infrastructure", i.arn!)} submit={`Delete ${i.name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${i.name}?`} />
              </>
            ),
          };
        })}
      />
    ),
  };
}

export default async function ImageBuilder({ searchParams }: Props) {
  const { tab = "pipelines", page = "0" } = await searchParams;
  const view =
    tab === "images"
      ? { body: await Images({ page: Math.max(0, Number(page) || 0) }), action: null }
      : tab === "recipes"
        ? await Recipes()
        : tab === "containers"
          ? await ContainerRecipes()
          : tab === "components"
            ? await Components()
            : tab === "workflows"
              ? await Workflows()
              : tab === "infrastructure"
                ? await Infrastructure()
                : tab === "distribution"
                  ? await Distributions()
                  : tab === "lifecycle"
                    ? await LifecyclePolicies()
                    : await Pipelines();
  const title = TABS.find(([id]) => id === tab)?.[1] ?? TABS[0][1];
  return (
    <Page title={title} actions={view.action ?? undefined}>
      <Segments label="Image Builder" items={TABS.map(([id, label]) => ({ label, href: id === "pipelines" ? "/imagebuilder" : `/imagebuilder?tab=${id}`, active: id === tab || (id === "pipelines" && !TABS.some(([t]) => t === tab)) }))} />
      <Section plain>{view.body}</Section>
    </Page>
  );
}
