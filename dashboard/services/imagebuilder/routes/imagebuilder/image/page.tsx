import {
  GetImageCommand,
  ListImagePackagesCommand,
  ListWaitingWorkflowStepsCommand,
  ListWorkflowExecutionsCommand,
  ListWorkflowStepExecutionsCommand,
  type ImagePackage,
  type WorkflowExecutionMetadata,
  type WorkflowStepExecution,
  type WorkflowStepMetadata,
} from "@aws-sdk/client-imagebuilder";
import { ago, all, load, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, ErrorNotice, Facts, List, Page, Pill, Section, Segments, Specs, Status } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { Ban, Clock, FileText, OctagonX, Play, RotateCcw, ShieldOff, Trash2 } from "lucide-react";
import Link from "next/link";
import type { Metadata } from "next";

import { ICONS, imagebuilder, tone } from "../../../lib/clients";
import { versionOf } from "../../../lib/lists";
import { cancelImage, deleteResource, retryImage, setImageState, workflowStepAction } from "../actions";

export const metadata: Metadata = { title: "Image · Image Builder" };

type Props = { searchParams: Promise<{ arn?: string; tab?: string }> };

const BUSY = ["PENDING", "CREATING", "BUILDING", "TESTING", "DISTRIBUTING", "INTEGRATING"];
const enc = encodeURIComponent;
const nameOf = (arn: string | undefined) => arn?.split("/")[1];

function duration(start?: string, end?: string) {
  if (!start) return "";
  const ms = (end ? Date.parse(end) : Date.now()) - Date.parse(start);
  if (!Number.isFinite(ms) || ms < 0) return "";
  const s = Math.round(ms / 1000);
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
}

export default async function ImagePage({ searchParams }: Props) {
  const { arn = "", tab = "workflows" } = await searchParams;
  const back = { href: "/imagebuilder?tab=images", label: "Images" };
  const data = await load(async () => {
    const client = await imagebuilder();
    const image = (await client.send(new GetImageCommand({ imageBuildVersionArn: arn }))).image;
    if (!image) throw new Error(`Image ${arn} not found`);
    const executions = await all(
      (nextToken) => client.send(new ListWorkflowExecutionsCommand({ imageBuildVersionArn: arn, nextToken })),
      (r) => r.workflowExecutions,
      (r) => r.nextToken,
    ).catch(() => [] as WorkflowExecutionMetadata[]);
    const steps = new Map<string, WorkflowStepMetadata[]>();
    if (tab === "workflows") {
      await Promise.all(
        executions.map(async (e) =>
          steps.set(
            e.workflowExecutionId!,
            await all(
              (nextToken) => client.send(new ListWorkflowStepExecutionsCommand({ workflowExecutionId: e.workflowExecutionId, nextToken })),
              (r) => r.steps,
              (r) => r.nextToken,
            ).catch(() => []),
          ),
        ),
      );
    }
    const waiting = await all(
      (nextToken) => client.send(new ListWaitingWorkflowStepsCommand({ nextToken })),
      (r) => r.steps,
      (r) => r.nextToken,
    )
      .then((s) => s.filter((w) => w.imageBuildVersionArn === arn))
      .catch(() => [] as WorkflowStepExecution[]);
    const packages =
      tab === "packages"
        ? await all(
            (nextToken) => client.send(new ListImagePackagesCommand({ imageBuildVersionArn: arn, nextToken })),
            (r) => r.imagePackageList,
            (r) => r.nextToken,
          ).catch(() => [] as ImagePackage[])
        : [];
    return { image, executions, steps, waiting, packages };
  });
  if (!data.ok) {
    return (
      <Page title={nameOf(arn) ?? "Image"} icon={ICONS.ami} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { image: i, executions, steps, waiting, packages } = data.value;
  const status = i.state?.status ?? "";
  const busy = BUSY.includes(status);
  const amis = i.outputResources?.amis ?? [];
  const containers = i.outputResources?.containers ?? [];
  const recipe = i.imageRecipe ?? i.containerRecipe;
  const logGroup = `/aws/imagebuilder/${recipe?.name ?? i.name}`;
  const base = `/imagebuilder/image?arn=${enc(arn)}`;

  let body: React.ReactNode;
  if (tab === "output") {
    body = (
      <List
        label="Output resources"
        rows={[
          ...amis.map((a) => ({
            key: `${a.region}-${a.image}`,
            icon: <AwsIcon icon={ICONS.ami} size={20} />,
            title: a.image,
            subtitle: [a.name, a.description, a.accountId].filter(Boolean).join(" · "),
            href: a.image ? `/ec2/image?id=${enc(a.image)}` : undefined,
            meta: (
              <>
                <Pill>{a.region}</Pill>
                {a.state?.status && <Status tone={tone(a.state.status)}>{a.state.status.toLowerCase()}</Status>}
              </>
            ),
          })),
          ...containers.flatMap((c) =>
            (c.imageUris ?? []).map((u) => ({
              key: u,
              icon: <AwsIcon icon="resource/AmazonElasticContainerRegistryImage" size={20} />,
              title: u,
              href: `/ecr/repo?name=${enc(u.split("/").slice(1).join("/").split(":")[0])}`,
              meta: <Pill>{c.region}</Pill>,
            })),
          ),
        ]}
      />
    );
  } else if (tab === "packages") {
    body = (
      <List
        label="Packages"
        rows={packages.map((p) => ({
          key: `${p.packageName}-${p.packageVersion}`,
          title: p.packageName,
          meta: <code>{p.packageVersion}</code>,
        }))}
      />
    );
  } else if (tab === "json") {
    body = <CodeBlock value={JSON.stringify(i, null, 2)} label="Image JSON" />;
  } else {
    body = executions.length ? (
      executions.map((e) => (
        <Section
          key={e.workflowExecutionId}
          title={`${nameOf(e.workflowBuildVersionArn) ?? e.type} ${versionOf(e.workflowBuildVersionArn) ?? ""}`}
          count={e.totalStepCount}
          plain
          actions={
            <>
              <Pill>{e.type?.toLowerCase()}</Pill>
              <Status tone={tone(e.status)}>{e.status?.toLowerCase()}</Status>
            </>
          }
        >
          {e.message && <div className={`banner${e.status === "FAILED" ? " error" : ""}`}>{e.message}</div>}
          <List
            label={`Steps of ${e.workflowExecutionId}`}
            rows={(steps.get(e.workflowExecutionId!) ?? []).map((s) => {
              const wait = waiting.find((w) => w.stepExecutionId === s.stepExecutionId);
              return {
                key: s.stepExecutionId!,
                title: s.name,
                subtitle: [s.action, s.message].filter(Boolean).join(" · "),
                meta: (
                  <>
                    {s.rollbackStatus && s.rollbackStatus !== "SKIPPED" && <Pill tone="warn">rollback {s.rollbackStatus.toLowerCase()}</Pill>}
                    <Status tone={tone(s.status)}>{s.status?.toLowerCase()}</Status>
                    {s.startTime && <span>{duration(s.startTime, s.endTime)}</span>}
                  </>
                ),
                actions: wait && (
                  <>
                    <ActionForm action={workflowStepAction.bind(null, s.stepExecutionId!, arn, "RESUME")} submit={`Resume ${s.name}`} icon={<Play size={15} />} testId="resume-step" />
                    <ActionForm action={workflowStepAction.bind(null, s.stepExecutionId!, arn, "STOP")} submit={`Stop ${s.name}`} icon={<OctagonX size={15} />} tone="danger" testId="stop-step" />
                  </>
                ),
              };
            })}
          />
        </Section>
      ))
    ) : (
      <p className="muted">No workflow executions</p>
    );
  }

  return (
    <Page
      title={i.name}
      icon={i.type === "DOCKER" ? "resource/AmazonElasticContainerRegistryImage" : ICONS.ami}
      back={back}
      subtitle={i.arn}
      actions={
        <>
          {busy && <ActionForm action={cancelImage.bind(null, arn)} submit="Cancel image creation" icon={<Ban size={16} />} tone="danger" confirm="Cancel this build?" testId="cancel-image" />}
          {(status === "FAILED" || status === "CANCELLED") && <ActionForm action={retryImage.bind(null, arn)} submit="Retry image" icon={<RotateCcw size={16} />} testId="retry-image" />}
          {status === "AVAILABLE" && <ActionForm action={setImageState.bind(null, arn, "DEPRECATED")} submit="Deprecate image" icon={<ShieldOff size={16} />} confirm="Deprecate this image?" testId="deprecate-image" />}
          {status === "AVAILABLE" && <ActionForm action={setImageState.bind(null, arn, "DISABLED")} submit="Disable image" icon={<ShieldOff size={16} />} confirm="Disable this image?" testId="disable-image" />}
          {!busy && <ActionForm action={deleteResource.bind(null, "image", arn)} submit="Delete image" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${i.name} ${i.version}?`} testId="delete-image" />}
        </>
      }
    >
      {busy && <LiveRefresh />}
      {i.state?.reason && <div className={`banner${status === "FAILED" ? " error" : ""}`}>{i.state.reason}</div>}
      {waiting.length > 0 && (
        <div className="banner" data-testid="waiting-steps">
          {waiting.map((w) => w.name).join(", ")} waiting for action
        </div>
      )}
      <Specs
        items={[
          { label: "Status", icon: <AwsIcon icon={ICONS.imagebuilder} size={16} />, value: <Status tone={tone(status)}>{status.toLowerCase()}</Status> },
          { label: "Version", icon: <FileText size={15} />, value: versionOf(i.arn) },
          { label: "Created", icon: <Clock size={15} />, value: <span title={when(i.dateCreated)}>{ago(i.dateCreated)}</span> },
          amis[0]?.image && { label: "AMI", icon: <AwsIcon icon={ICONS.ami} size={16} />, value: <Link href={`/ec2/image?id=${enc(amis[0].image)}`}>{amis[0].image}</Link> },
        ]}
      />
      <Section title="Details">
        <Facts
          items={[
            ["Type", i.type],
            i.platform && ["Platform", i.platform],
            i.osVersion && ["OS", i.osVersion],
            i.buildType && ["Build type", i.buildType.toLowerCase()],
            i.imageSource && ["Source", i.imageSource.toLowerCase().replace(/_/g, " ")],
            i.sourcePipelineArn && ["Pipeline", <Link key="p" href={`/imagebuilder/pipeline?arn=${enc(i.sourcePipelineArn)}`}>{i.sourcePipelineName ?? nameOf(i.sourcePipelineArn)}</Link>],
            recipe && ["Recipe", `${recipe.name} ${recipe.version ?? ""}`],
            (i.imageRecipe?.parentImage ?? i.containerRecipe?.parentImage) && ["Parent image", <code key="pi">{i.imageRecipe?.parentImage ?? i.containerRecipe?.parentImage}</code>],
            i.infrastructureConfiguration?.name && ["Infrastructure", i.infrastructureConfiguration.name],
            i.infrastructureConfiguration?.instanceTypes?.length && ["Instance types", i.infrastructureConfiguration.instanceTypes.join(", ")],
            i.distributionConfiguration?.name && ["Distribution", i.distributionConfiguration.name],
            i.executionRole && ["Execution role", i.executionRole],
            i.imageTestsConfiguration && ["Tests", i.imageTestsConfiguration.imageTestsEnabled === false ? "Disabled" : `Enabled · ${i.imageTestsConfiguration.timeoutMinutes ?? 720} min`],
            i.imageScanningConfiguration?.imageScanningEnabled && ["Scanning", i.scanState?.status?.toLowerCase() ?? "enabled"],
            i.enhancedImageMetadataEnabled !== undefined && ["Enhanced metadata", i.enhancedImageMetadataEnabled ? "Enabled" : "Disabled"],
            i.deprecationTime && ["Deprecated", when(i.deprecationTime)],
            ["Logs", <Link key="l" href={`/logs/group?name=${enc(logGroup)}`}>{logGroup}</Link>],
          ]}
        />
      </Section>
      <Segments
        label="Image"
        items={[
          { label: "Workflows", href: `${base}&tab=workflows`, active: tab === "workflows" },
          { label: "Output resources", href: `${base}&tab=output`, active: tab === "output" },
          { label: "Packages", href: `${base}&tab=packages`, active: tab === "packages" },
          { label: "JSON", href: `${base}&tab=json`, active: tab === "json" },
        ]}
      />
      {body}
    </Page>
  );
}
