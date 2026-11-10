import { GetBranchCommand, ListJobsCommand } from "@aws-sdk/client-amplify";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, Empty, ErrorNotice, Field, List, Page, Pill, Section, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { Clock, ExternalLink, GitBranch, GitCommitVertical, Hammer, Layers, Square, Trash2, Upload } from "lucide-react";
import type { Metadata } from "next";

import { siteUrl } from "../../../lib/amplify";
import { amplify, ICONS, tone } from "../../../lib/clients";
import { SOURCE_URL } from "../../../lib/rules";
import { build, deleteBranch, deploy, stopJob } from "../actions";

export const metadata: Metadata = { title: "Branch" };

type Props = { searchParams: Promise<{ app?: string; name?: string }> };

function duration(start?: Date, end?: Date) {
  if (!start || !end) return undefined;
  const s = Math.round((end.getTime() - start.getTime()) / 1000);
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
}

export default async function Branch({ searchParams }: Props) {
  const { app = "", name = "" } = await searchParams;
  const back = { href: `/amplify/app?id=${app}`, label: "App" };
  const data = await load(async () => {
    const client = await amplify();
    const [branch, jobs] = await Promise.all([
      client.send(new GetBranchCommand({ appId: app, branchName: name })).then((r) => r.branch!),
      client.send(new ListJobsCommand({ appId: app, branchName: name, maxResults: 25 })).then((r) => r.jobSummaries ?? []),
    ]);
    return { branch, jobs };
  });
  if (!data.ok) {
    return (
      <Page title={name} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { branch, jobs } = data.value;
  const live = jobs.find((j) => j.status === "SUCCEED");
  return (
    <Page
      title={branch.displayName ?? name}
      back={back}
      subtitle={branch.branchArn}
      actions={
        <>
          {live && (
            <a className="icon-button plain" href={siteUrl(app, name)} aria-label="Visit deployed URL" title="Visit">
              <ExternalLink size={16} />
            </a>
          )}
          {branch.enableAutoBuild !== false && jobs.some((j) => j.jobType !== "MANUAL") && <ActionForm action={build.bind(null, app, name)} submit="Run build" icon={<Hammer size={16} />} />}
          <Sheet title="Deploy" label="Deploy updates" icon={<Upload size={15} />} testId="deploy">
            <ActionForm action={deploy.bind(null, app, name)} submit="Save and deploy" testId="deploy">
              <Field label="Zip">
                <input name="zip" type="file" accept=".zip" />
              </Field>
              <Field label="Or a URL" rule={SOURCE_URL} member="sourceUrl">
                <input name="url" placeholder="s3://bucket/site.zip or https://…" />
              </Field>
              <Field label="Or index.html">
                <textarea name="html" rows={5} className="code-editor" placeholder="<h1>Hello</h1>" spellCheck={false} />
              </Field>
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteBranch.bind(null, app, name)} submit="Delete branch" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name}?`} />
        </>
      }
    >
      <Specs
        items={[
          { label: "Stage", icon: <Layers size={15} />, value: branch.stage?.toLowerCase().replace("_", " ") },
          branch.framework && { label: "Framework", icon: <GitBranch size={15} />, value: branch.framework },
          live && { label: "Deployed", icon: <Clock size={15} />, value: ago(live.endTime) },
          live && { label: "Site", icon: <ExternalLink size={15} />, value: <a href={siteUrl(app, name)}>{new URL(siteUrl(app, name)).host}</a> },
        ]}
      />
      <Section title="Deployments" count={jobs.length} plain>
        <List
          label="Deployments"
          empty={<Empty icon={ICONS.amplify} />}
          rows={jobs.map((j) => ({
            key: j.jobId!,
            icon: <GitCommitVertical size={18} />,
            title: `#${j.jobId}`,
            subtitle: j.commitMessage || j.commitId?.slice(0, 7),
            meta: (
              <>
                <Pill>{j.jobType?.toLowerCase().replace("_", " ")}</Pill>
                {duration(j.startTime, j.endTime) && <span>{duration(j.startTime, j.endTime)}</span>}
                <Status tone={tone(j.status)}>{j.status?.toLowerCase()}</Status>
                <span>{ago(j.startTime)}</span>
              </>
            ),
            actions:
              j.status === "RUNNING" || j.status === "PENDING" ? (
                <ActionForm action={stopJob.bind(null, app, name, j.jobId!)} submit={`Stop job ${j.jobId}`} icon={<Square size={14} />} tone="danger" />
              ) : undefined,
          }))}
        />
      </Section>
    </Page>
  );
}
