import { GetArtifactUrlCommand, GetJobCommand, ListArtifactsCommand } from "@aws-sdk/client-amplify";
import { ago, all, load, when } from "@mws-dashboard/aws";
import { ActionForm, Empty, ErrorNotice, Facts, List, Page, Pill, Section, Specs, Status } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { Clock, Download, FileText, GitCommitVertical, RefreshCw, RotateCw, Square, Timer, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { duration, RUNNING } from "../../../lib/amplify";
import { amplify, ICONS, tone } from "../../../lib/clients";
import { deleteJob, retryJob, stopJob } from "../actions";

export const metadata: Metadata = { title: "Job" };

type Props = { searchParams: Promise<{ app?: string; branch?: string; id?: string; step?: string }> };

/** A step's log, read on the server (the URL is MWS's, short-lived). */
async function readLog(url: string | undefined): Promise<string | undefined> {
  if (!url) return undefined;
  try {
    const r = await fetch(url, { cache: "no-store" });
    return r.ok ? await r.text() : `Log answered ${r.status}`;
  } catch (e) {
    return `Could not read the log: ${e instanceof Error ? e.message : String(e)}`;
  }
}

export default async function Job({ searchParams }: Props) {
  const { app = "", branch = "", id = "", step } = await searchParams;
  const branchHref = `/amplify/branch?app=${app}&name=${encodeURIComponent(branch)}`;
  const back = { href: branchHref, label: branch };
  const data = await load(async () => {
    const client = await amplify();
    const [job, artifacts] = await Promise.all([
      client.send(new GetJobCommand({ appId: app, branchName: branch, jobId: id })).then((r) => r.job!),
      all((nextToken) => client.send(new ListArtifactsCommand({ appId: app, branchName: branch, jobId: id, nextToken })), (r) => r.artifacts, (r) => r.nextToken).catch(() => []),
    ]);
    // Download links are short-lived: made on each render.
    const links = await Promise.all(artifacts.map((a) => client.send(new GetArtifactUrlCommand({ artifactId: a.artifactId })).then((r) => r.artifactUrl, () => undefined)));
    return { job, artifacts: artifacts.map((a, i) => ({ ...a, url: links[i] })) };
  });
  if (!data.ok) {
    return (
      <Page title={`#${id}`} icon={ICONS.amplify} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { job, artifacts } = data.value;
  const s = job.summary!;
  const steps = job.steps ?? [];
  const running = RUNNING.test(s.status ?? "");
  // The chosen step, else the first that failed, else the last with a log.
  const shown = steps.find((x) => x.stepName === step) ?? steps.find((x) => x.status === "FAILED" && x.logUrl) ?? [...steps].reverse().find((x) => x.logUrl);
  const log = await readLog(shown?.logUrl);
  const self = `/amplify/job?app=${app}&branch=${encodeURIComponent(branch)}&id=${id}`;
  return (
    <Page
      title={`#${s.jobId}`}
      icon={ICONS.amplify}
      back={back}
      subtitle={s.jobArn}
      actions={
        <>
          <Link className="icon-button plain" href={`${self}${shown ? `&step=${encodeURIComponent(shown.stepName!)}` : ""}`} aria-label="Refresh" title="Refresh" prefetch={false}>
            <RefreshCw size={16} />
          </Link>
          {(s.status === "RUNNING" || s.status === "PENDING") && <ActionForm action={stopJob.bind(null, app, branch, id)} submit="Stop job" icon={<Square size={15} />} tone="danger" />}
          {s.status === "FAILED" && <ActionForm action={retryJob.bind(null, app, branch, id)} submit="Retry" icon={<RotateCw size={16} />} />}
          {!running && <ActionForm action={deleteJob.bind(null, app, branch, id)} submit="Delete job" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete job ${id}?`} />}
        </>
      }
    >
      <LiveRefresh when={running} />
      <Specs
        items={[
          { label: "Status", icon: <GitCommitVertical size={15} />, value: <Status tone={tone(s.status)}>{s.status?.toLowerCase() ?? ""}</Status> },
          { label: "Type", icon: <GitCommitVertical size={15} />, value: s.jobType?.toLowerCase().replace("_", " ") },
          { label: "Started", icon: <Clock size={15} />, value: ago(s.startTime) },
          duration(s.startTime, s.endTime) && { label: "Duration", icon: <Timer size={15} />, value: duration(s.startTime, s.endTime) },
        ]}
      />
      <Section>
        <Facts
          items={[
            s.commitId && ["Commit", <code key="c">{s.commitId}</code>],
            s.commitMessage && ["Message", s.commitMessage],
            s.sourceUrl && ["Source", <code key="s">{s.sourceUrl}</code>],
            ["Started", when(s.startTime)],
            s.endTime && ["Ended", when(s.endTime)],
          ]}
        />
      </Section>
      <Section title="Steps" count={steps.length} plain>
        <List
          label="Steps"
          empty={<Empty icon={ICONS.amplify} />}
          rows={steps.map((x) => ({
            key: x.stepName!,
            icon: <FileText size={18} />,
            title: x.stepName,
            subtitle: x.statusReason ?? x.context,
            href: x.logUrl ? `${self}&step=${encodeURIComponent(x.stepName!)}` : undefined,
            meta: (
              <>
                {x === shown && <Pill tone="info">log</Pill>}
                {duration(x.startTime, x.endTime) && <span>{duration(x.startTime, x.endTime)}</span>}
                <Status tone={tone(x.status)}>{x.status?.toLowerCase() ?? ""}</Status>
              </>
            ),
            actions: x.artifactsUrl ? (
              <a className="icon-button plain" href={x.artifactsUrl} aria-label={`Download ${x.stepName} artifacts`} title="Artifacts">
                <Download size={15} />
              </a>
            ) : undefined,
          }))}
        />
      </Section>
      {shown && (
        <Section
          title={`${shown.stepName} log`}
          actions={
            shown.logUrl ? (
              <a className="icon-button plain" href={shown.logUrl} aria-label="Download log" title="Download log">
                <Download size={15} />
              </a>
            ) : undefined
          }
        >
          <pre className="code" aria-label="Job log" data-testid="job-log">
            {log || (running ? "Waiting for the log…" : "")}
          </pre>
        </Section>
      )}
      {!shown && running && <p className="muted">Logs appear when the job finishes.</p>}
      {artifacts.length > 0 && (
        <Section title="Artifacts" count={artifacts.length} plain>
          <List
            label="Artifacts"
            rows={artifacts.map((a) => ({
              key: a.artifactId!,
              icon: <FileText size={18} />,
              title: a.artifactFileName,
              href: a.url,
              external: true,
            }))}
          />
        </Section>
      )}
      {Object.keys(shown?.screenshots ?? {}).length > 0 && (
        <Section title="Screenshots">
          <Facts items={Object.entries(shown!.screenshots!).map(([k, v]) => [k, <a key={k} href={v}>{k}</a>])} />
        </Section>
      )}
    </Page>
  );
}
