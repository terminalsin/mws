import { ago, load, region } from "@mws-dashboard/aws";
import { roleOptions } from "@mws-dashboard/aws/auto";
import { ActionForm, AutoPick, AwsIcon, Empty, ErrorNotice, Field, List, Pill, Sheet, Status, type Rule } from "@mws-dashboard/ui";
import { CreateContainerRecipe, CreateDistributionConfiguration, CreateLifecyclePolicy, CreateWorkflow } from "@mws-dashboard/ui/model/imagebuilder";
import { Globe, Recycle, Trash2, Workflow } from "lucide-react";

import { ICONS, tone } from "../../lib/clients";
import * as lists from "../../lib/lists";
import { versionOf } from "../../lib/lists";
import { createContainerRecipe, createDistribution, createLifecyclePolicy, createWorkflow, deleteResource } from "./actions";

const named = (rule: Rule): Rule => ({ ...rule, hint: "Letters, digits, spaces, - and _", generate: "name" });


const WORKFLOW_SAMPLE = `name: build-and-wait
description: Build, then wait for approval
schemaVersion: 1.0
steps:
  - name: LaunchBuildInstance
    action: LaunchInstance
    onFailure: Abort
    inputs:
      waitFor: "ssmAgent"
  - name: ApplyBuildComponents
    action: ExecuteComponents
    onFailure: Abort
    inputs:
      instanceId.$: "$.stepOutputs.LaunchBuildInstance.instanceId"
  - name: Approve
    action: WaitForAction
    onFailure: Abort
  - name: CreateOutputAMI
    action: CreateImage
    onFailure: Abort
    inputs:
      instanceId.$: "$.stepOutputs.LaunchBuildInstance.instanceId"
  - name: TerminateBuildInstance
    action: TerminateInstance
    onFailure: Continue
    inputs:
      instanceId.$: "$.stepOutputs.LaunchBuildInstance.instanceId"
outputs:
  - name: "ImageId"
    value: "$.stepOutputs.CreateOutputAMI.imageId"
`;

export async function ContainerRecipes() {
  const data = await load(async () => {
    const [recipes, own, amazon] = await Promise.all([lists.containerRecipes(), lists.components("Self"), lists.components("Amazon")]);
    return { recipes, components: [...own, ...amazon].filter((c) => c.type !== "TEST" && c.platform !== "Windows") };
  });
  if (!data.ok) return { body: <ErrorNotice error={data.error} />, action: null };
  const { recipes, components } = data.value;
  const action = (
    <Sheet title="Create container recipe" label="Create container recipe" testId="create-container-recipe">
      <ActionForm action={createContainerRecipe} submit="Create recipe" testId="create-container-recipe">
        <div className="form-row">
          <Field label="Name" rule={named(CreateContainerRecipe.name)}>
            <input name="name" required />
          </Field>
          <Field label="Version" rule={CreateContainerRecipe.semanticVersion} format="semver" member="semanticVersion" unique>
            <input name="version" required defaultValue="1.0.0" />
          </Field>
        </div>
        <Field label="Base image" rule={CreateContainerRecipe.parentImage} member="parentImage">
          <input name="parent" required defaultValue="amazonlinux:latest" spellCheck={false} />
        </Field>
        <Field label="ECR repository" rule={CreateContainerRecipe.targetRepository?.fields?.repositoryName} member="repositoryName">
          <input name="repository" required spellCheck={false} />
        </Field>
        <fieldset className="checks">
          <legend>Components</legend>
          {components.map((c) => (
            <label key={c.arn} className="check">
              <input type="checkbox" name="component" value={c.arn} defaultChecked={c.name === "update-linux"} /> {c.name}
              {c.owner !== "Amazon" && <Pill>own</Pill>}
            </label>
          ))}
        </fieldset>
        <Field label="Dockerfile template" rule={CreateContainerRecipe.dockerfileTemplateData} member="dockerfileTemplateData">
          <textarea
            name="dockerfile"
            rows={4}
            className="code-editor"
            spellCheck={false}
            defaultValue={"FROM {{{ imagebuilder:parentImage }}}\n{{{ imagebuilder:environments }}}\n{{{ imagebuilder:components }}}"}
          />
        </Field>
      </ActionForm>
    </Sheet>
  );
  return {
    action,
    body: (
      <List
        label="Container recipes"
        empty={<Empty icon="resource/AmazonElasticContainerRegistryImage" action={action} />}
        rows={recipes.map((r) => ({
          key: r.arn!,
          icon: <AwsIcon icon="resource/AmazonElasticContainerRegistryImage" size={20} />,
          title: r.name,
          subtitle: r.parentImage,
          meta: (
            <>
              <Pill>{r.containerType?.toLowerCase()}</Pill>
              <code>{versionOf(r.arn)}</code>
              <span>{ago(r.dateCreated)}</span>
            </>
          ),
          actions: <ActionForm action={deleteResource.bind(null, "container", r.arn!)} submit={`Delete ${r.name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${r.name}?`} />,
        }))}
      />
    ),
  };
}

export async function Distributions() {
  const [data, here] = await Promise.all([load(() => lists.distributions()), region()]);
  const action = (
    <Sheet title="Create distribution settings" label="Create distribution settings" testId="create-distribution">
      <ActionForm action={createDistribution} submit="Create" testId="create-distribution">
        <Field label="Name" rule={named(CreateDistributionConfiguration.name)} taken={data.ok ? data.value.map((d) => d.name!) : []} unique>
          <input name="name" required />
        </Field>
        <Field label="Description" rule={CreateDistributionConfiguration.description}>
          <input name="description" />
        </Field>
        <Field label="Regions" hint="Comma-separated">
          <input name="regions" defaultValue={here} spellCheck={false} />
        </Field>
        <Field label="Output AMI name" hint="Must include {{ imagebuilder:buildDate }} to stay unique">
          <input name="amiName" placeholder="my-app-{{ imagebuilder:buildDate }}" spellCheck={false} />
        </Field>
        <Field label="Share with accounts" format="principal">
          <input name="accounts" placeholder="123456789012" spellCheck={false} />
        </Field>
      </ActionForm>
    </Sheet>
  );
  if (!data.ok) return { body: <ErrorNotice error={data.error} />, action };
  return {
    action,
    body: (
      <List
        label="Distribution settings"
        empty={<Empty icon={ICONS.imagebuilder} action={action} />}
        rows={data.value.map((d) => ({
          key: d.arn!,
          icon: <Globe size={18} aria-hidden />,
          title: d.name,
          subtitle: d.description,
          meta: (
            <>
              {(d.regions ?? []).map((r) => (
                <Pill key={r}>{r}</Pill>
              ))}
              <span>{ago(d.dateCreated)}</span>
            </>
          ),
          actions: <ActionForm action={deleteResource.bind(null, "distribution", d.arn!)} submit={`Delete ${d.name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${d.name}?`} />,
        }))}
      />
    ),
  };
}

export async function Workflows() {
  const data = await load(() => lists.workflows());
  const action = (
    <Sheet title="Create image workflow" label="Create image workflow" testId="create-workflow">
      <ActionForm action={createWorkflow} submit="Create workflow" testId="create-workflow">
        <div className="form-row">
          <Field label="Name" rule={named(CreateWorkflow.name)}>
            <input name="name" required />
          </Field>
          <Field label="Version" rule={CreateWorkflow.semanticVersion} format="semver" member="semanticVersion" unique>
            <input name="version" required defaultValue="1.0.0" />
          </Field>
          <Field label="Type">
            <select name="type" defaultValue="BUILD">
              <option value="BUILD">Build</option>
              <option value="TEST">Test</option>
              <option value="DISTRIBUTION">Distribution</option>
            </select>
          </Field>
        </div>
        <Field label="Description" rule={CreateWorkflow.description}>
          <input name="description" />
        </Field>
        <Field label="Document" rule={CreateWorkflow.data} format="yaml">
          <textarea name="data" rows={16} className="code-editor" spellCheck={false} defaultValue={WORKFLOW_SAMPLE} />
        </Field>
      </ActionForm>
    </Sheet>
  );
  if (!data.ok) return { body: <ErrorNotice error={data.error} />, action };
  return {
    action,
    body: (
      <List
        label="Image workflows"
        empty={<Empty icon={ICONS.imagebuilder} action={action} />}
        rows={data.value.map((w) => ({
          key: w.arn!,
          icon: <Workflow size={18} aria-hidden />,
          title: w.name,
          subtitle: w.description,
          meta: (
            <>
              <Pill>{w.type?.toLowerCase()}</Pill>
              <code>{w.version}</code>
              <span>{ago(w.dateCreated)}</span>
            </>
          ),
          actions: <ActionForm action={deleteResource.bind(null, "workflow", w.arn!)} submit={`Delete ${w.name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${w.name}?`} />,
        }))}
      />
    ),
  };
}

export async function LifecyclePolicies() {
  const [data, recipes, roles] = await Promise.all([load(() => lists.lifecyclePolicies()), lists.recipes().catch(() => []), roleOptions("imagebuilder.amazonaws.com")]);
  const versions = [...new Map(recipes.map((r) => [`${r.name}|${r.arn?.split("/")[2]}`, r])).keys()];
  const action = (
    <Sheet title="Create lifecycle policy" label="Create lifecycle policy" testId="create-lifecycle-policy">
      <ActionForm action={createLifecyclePolicy} submit="Create policy" testId="create-lifecycle-policy">
        <Field label="Name" rule={named(CreateLifecyclePolicy.name)} taken={data.ok ? data.value.map((p) => p.name!) : []} unique>
          <input name="name" required />
        </Field>
        <Field label="Description" rule={CreateLifecyclePolicy.description}>
          <input name="description" />
        </Field>
        <div className="form-row">
          <Field label="Action">
            <select name="action" defaultValue="DELETE">
              <option value="DELETE">Delete</option>
              <option value="DEPRECATE">Deprecate</option>
              <option value="DISABLE">Disable</option>
            </select>
          </Field>
          <Field label="When">
            <select name="by" defaultValue="COUNT">
              <option value="COUNT">More than N images</option>
              <option value="AGE">Older than N days</option>
            </select>
          </Field>
          <Field label="N" rule={{ type: "integer", min: 1, max: 1000 }}>
            <input name="count" type="number" min={1} max={1000} required defaultValue="5" />
          </Field>
        </div>
        <AutoPick name="role" label="Execution role" options={roles} creates="EC2ImageBuilderLifecycleExecutionRole" testId="lifecycle-role" />
        <fieldset className="checks">
          <legend>Recipes</legend>
          {versions.map((v) => (
            <label key={v} className="check">
              <input type="checkbox" name="recipe" value={v} /> {v.replace("|", " ")}
            </label>
          ))}
        </fieldset>
      </ActionForm>
    </Sheet>
  );
  if (!data.ok) return { body: <ErrorNotice error={data.error} />, action };
  return {
    action,
    body: (
      <List
        label="Lifecycle policies"
        empty={<Empty icon={ICONS.imagebuilder} action={recipes.length ? action : undefined} />}
        rows={data.value.map((p) => ({
          key: p.arn!,
          icon: <Recycle size={18} aria-hidden />,
          title: p.name,
          subtitle: p.description,
          meta: (
            <>
              <Pill>{(p.resourceType ?? "").toLowerCase().replace(/_/g, " ")}</Pill>
              <Status tone={tone(p.status)}>{p.status?.toLowerCase()}</Status>
              {p.dateLastRun && <span>{ago(p.dateLastRun)}</span>}
            </>
          ),
          actions: <ActionForm action={deleteResource.bind(null, "lifecycle", p.arn!)} submit={`Delete ${p.name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${p.name}?`} />,
        }))}
      />
    ),
  };
}


