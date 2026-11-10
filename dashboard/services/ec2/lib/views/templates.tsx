import "server-only";

import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, Empty, ErrorNotice, Field, List, Pill, Sheet } from "@mws-dashboard/ui";
import { LayoutTemplate, Trash2 } from "lucide-react";

import { createTemplate, deleteTemplate } from "../../routes/ec2/templates";
import { launchChoices } from "../choices";
import { LINKS } from "../clients";
import { listTemplates } from "../ec2";
import { LaunchFields } from "../launch-fields";
import { TEMPLATE_NAME, VERSION_DESCRIPTION } from "../rules";

export async function CreateTemplateSheet() {
  const choices = await launchChoices();
  return (
    <Sheet title="Create launch template" label="Create launch template" testId="create-launch-template">
      <ActionForm action={createTemplate} submit="Create" testId="create-launch-template">
        <Field label="Name" rule={TEMPLATE_NAME} member="LaunchTemplateName" taken={choices.templates.map((t) => t.name)} unique>
          <input name="name" required autoFocus />
        </Field>
        <Field label="Version description" rule={VERSION_DESCRIPTION} member="VersionDescription">
          <input name="description" />
        </Field>
        <LaunchFields choices={choices} mode="template" />
      </ActionForm>
    </Sheet>
  );
}

export async function TemplatesView() {
  const templates = await load(listTemplates);
  const actions = <CreateTemplateSheet />;
  if (!templates.ok) return { body: <ErrorNotice error={templates.error} />, actions };
  const body = (
    <List
      label="Launch templates"
      empty={<Empty icon="resource/AmazonEC2Instances" />}
      rows={templates.value.map((t) => ({
        key: t.LaunchTemplateId!,
        icon: <LayoutTemplate size={20} aria-hidden />,
        title: t.LaunchTemplateName,
        subtitle: t.LaunchTemplateId,
        href: LINKS.template(t.LaunchTemplateId!),
        meta: (
          <>
            <Pill title="Default version">v{t.DefaultVersionNumber}</Pill>
            {t.LatestVersionNumber !== t.DefaultVersionNumber && (
              <Pill tone="info" title="Latest version">
                latest v{t.LatestVersionNumber}
              </Pill>
            )}
            {t.Operator?.Managed && <Pill>managed</Pill>}
            <span>{ago(t.CreateTime)}</span>
          </>
        ),
        actions: !t.Operator?.Managed && (
          <ActionForm
            action={deleteTemplate.bind(null, t.LaunchTemplateId!, false)}
            submit={`Delete ${t.LaunchTemplateName}`}
            icon={<Trash2 size={15} />}
            tone="danger"
            confirm={`Delete ${t.LaunchTemplateName} and all its versions?`}
          />
        ),
      }))}
    />
  );
  return { body, actions };
}
