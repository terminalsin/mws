import { GetImagePipelineCommand, ListImagePipelineImagesCommand } from "@aws-sdk/client-imagebuilder";
import { ago, all, load, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Facts, List, Page, Section, Specs, Status } from "@mws-dashboard/ui";
import { CalendarClock, Clock, Pause, Play, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, imagebuilder, tone } from "../../../lib/clients";
import { versionOf } from "../../../lib/lists";
import { deleteResource, runPipeline, setPipelineEnabled } from "../actions";

export const metadata: Metadata = { title: "Image pipeline · Image Builder" };

type Props = { searchParams: Promise<{ arn?: string }> };

const enc = encodeURIComponent;
const ref = (arn: string | undefined) => (arn ? `${arn.split("/")[1]} ${versionOf(arn) ?? ""}` : undefined);

export default async function PipelinePage({ searchParams }: Props) {
  const { arn = "" } = await searchParams;
  const back = { href: "/imagebuilder", label: "Image pipelines" };
  const data = await load(async () => {
    const client = await imagebuilder();
    const p = (await client.send(new GetImagePipelineCommand({ imagePipelineArn: arn }))).imagePipeline;
    if (!p) throw new Error(`Pipeline ${arn} not found`);
    const images = await all(
      (nextToken) => client.send(new ListImagePipelineImagesCommand({ imagePipelineArn: arn, nextToken })),
      (r) => r.imageSummaryList,
      (r) => r.nextToken,
    );
    return { p, images: images.sort((a, b) => (b.dateCreated ?? "").localeCompare(a.dateCreated ?? "")) };
  });
  if (!data.ok) {
    return (
      <Page title={arn.split("/")[1] ?? "Pipeline"} icon={ICONS.imagebuilder} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { p, images } = data.value;
  const enabled = p.status === "ENABLED";
  return (
    <Page
      title={p.name}
      icon={ICONS.imagebuilder}
      back={back}
      subtitle={p.description}
      actions={
        <>
          <ActionForm action={runPipeline.bind(null, arn)} submit="Run pipeline" icon={<Play size={16} />} testId="run-pipeline" />
          <ActionForm action={setPipelineEnabled.bind(null, arn, !enabled)} submit={enabled ? "Disable pipeline" : "Enable pipeline"} icon={enabled ? <Pause size={16} /> : <Play size={16} />} testId="toggle-pipeline" />
          <ActionForm action={deleteResource.bind(null, "pipeline", arn)} submit="Delete pipeline" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${p.name}?`} testId="delete-pipeline" />
        </>
      }
    >
      <Specs
        items={[
          { label: "Status", icon: <AwsIcon icon={ICONS.imagebuilder} size={16} />, value: <Status tone={enabled ? "good" : "neutral"}>{p.status?.toLowerCase()}</Status> },
          p.schedule?.scheduleExpression && { label: "Schedule", icon: <CalendarClock size={15} />, value: <code>{p.schedule.scheduleExpression}</code> },
          p.dateLastRun && { label: "Last run", icon: <Clock size={15} />, value: <span title={when(p.dateLastRun)}>{ago(p.dateLastRun)}</span> },
          p.dateNextRun && { label: "Next run", icon: <Clock size={15} />, value: <span title={when(p.dateNextRun)}>{ago(p.dateNextRun)}</span> },
        ]}
      />
      <Section title="Details">
        <Facts
          items={[
            ["ARN", <code key="a">{p.arn}</code>],
            p.imageRecipeArn && ["Image recipe", ref(p.imageRecipeArn)],
            p.containerRecipeArn && ["Container recipe", ref(p.containerRecipeArn)],
            p.infrastructureConfigurationArn && ["Infrastructure", p.infrastructureConfigurationArn.split("/")[1]],
            p.distributionConfigurationArn && ["Distribution", p.distributionConfigurationArn.split("/")[1]],
            p.schedule?.pipelineExecutionStartCondition && ["Start condition", p.schedule.pipelineExecutionStartCondition.toLowerCase().replace(/_/g, " ")],
            p.schedule?.timezone && ["Time zone", p.schedule.timezone],
            ["Tests", p.imageTestsConfiguration?.imageTestsEnabled === false ? "Disabled" : `Enabled · ${p.imageTestsConfiguration?.timeoutMinutes ?? 720} min`],
            p.imageScanningConfiguration && ["Scanning", p.imageScanningConfiguration.imageScanningEnabled ? "Enabled" : "Disabled"],
            ["Enhanced metadata", p.enhancedImageMetadataEnabled === false ? "Disabled" : "Enabled"],
            p.executionRole && ["Execution role", p.executionRole],
            (p.workflows ?? []).length > 0 && ["Workflows", p.workflows!.map((w) => ref(w.workflowArn)).join(", ")],
            ["Created", when(p.dateCreated)],
            p.dateUpdated && ["Updated", when(p.dateUpdated)],
          ]}
        />
      </Section>
      <Section title="Output images" count={images.length} plain>
        <List
          label="Output images"
          empty={<Empty icon={ICONS.ami} />}
          rows={images.map((i) => ({
            key: i.arn!,
            icon: <AwsIcon icon={i.type === "DOCKER" ? "resource/AmazonElasticContainerRegistryImage" : ICONS.ami} size={20} />,
            title: `${i.name} ${versionOf(i.arn)}`,
            subtitle: (i.outputResources?.amis ?? []).map((a) => a.image).join(" · "),
            href: `/imagebuilder/image?arn=${enc(i.arn!)}`,
            meta: (
              <>
                <Status tone={tone(i.state?.status)}>{i.state?.status?.toLowerCase()}</Status>
                <span>{ago(i.dateCreated)}</span>
              </>
            ),
          }))}
        />
      </Section>
      {p.tags && Object.keys(p.tags).length > 0 && (
        <Section title="Tags">
          <CodeBlock value={JSON.stringify(p.tags, null, 2)} label="Tags" />
        </Section>
      )}
    </Page>
  );
}
