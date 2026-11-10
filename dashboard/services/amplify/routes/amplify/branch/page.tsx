import { GetAppCommand, GetBranchCommand, ListJobsCommand } from "@aws-sdk/client-amplify";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Facts, Field, List, More, Page, Pill, Section, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { MoreFields } from "@mws-dashboard/ui/presets";
import { UpdateBranch } from "@mws-dashboard/ui/model/amplify";
import { Clock, ExternalLink, GitBranch, GitCommitVertical, Hammer, Layers, Lock, RotateCw, Settings2, Square, Trash2, Upload } from "lucide-react";
import type { Metadata } from "next";

import { duration, envText, RUNNING, siteUrl } from "../../../lib/amplify";
import { amplify, ICONS, tone } from "../../../lib/clients";
import { frameworkIcon } from "../../../lib/presets";
import { SOURCE_URL } from "../../../lib/rules";
import { build, buildCommit, deleteBranch, deploy, retryJob, stopJob, updateBranch } from "../actions";

export const metadata: Metadata = { title: "Branch" };

type Props = { searchParams: Promise<{ app?: string; name?: string; token?: string }> };

const STAGES = ["PRODUCTION", "BETA", "DEVELOPMENT", "EXPERIMENTAL", "PULL_REQUEST"];

export default async function Branch({ searchParams }: Props) {
  const { app = "", name = "", token } = await searchParams;
  const back = { href: `/amplify/app?id=${app}`, label: "App" };
  const data = await load(async () => {
    const client = await amplify();
    const [branch, page, application] = await Promise.all([
      client.send(new GetBranchCommand({ appId: app, branchName: name })).then((r) => r.branch!),
      client.send(new ListJobsCommand({ appId: app, branchName: name, maxResults: 25, nextToken: token })),
      client.send(new GetAppCommand({ appId: app })).then((r) => r.app!),
    ]);
    return { branch, jobs: page.jobSummaries ?? [], next: page.nextToken, application };
  });
  if (!data.ok) {
    return (
      <Page title={name} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { branch, jobs, next, application } = data.value;
  const live = jobs.find((j) => j.status === "SUCCEED");
  const latest = jobs[0];
  const env = branch.environmentVariables ?? {};
  const busy = jobs.some((j) => RUNNING.test(j.status ?? ""));
  // A connected repository builds on request, even before its first job.
  const buildable = !!application.repository;
  const jobHref = (id: string) => `/amplify/job?app=${app}&branch=${encodeURIComponent(name)}&id=${id}`;
  return (
    <Page
      title={branch.displayName ?? name}
      back={{ ...back, label: application.name ?? "App" }}
      subtitle={branch.branchArn}
      actions={
        <>
          {live && (
            <a className="icon-button plain" href={siteUrl(app, name)} aria-label="Visit deployed URL" title="Visit">
              <ExternalLink size={16} />
            </a>
          )}
          {buildable && !busy && <ActionForm action={build.bind(null, app, name)} submit="Run build" icon={<Hammer size={16} />} testId="run-build" />}
          {buildable && (
            <Sheet title="Build a commit" label="Build a commit" icon={<GitCommitVertical size={15} />} testId="build-commit">
              <ActionForm action={buildCommit.bind(null, app, name)} submit="Run build" testId="build-commit">
                <Field label="Commit" hint="The branch head when empty">
                  <input name="commit" placeholder="a1b2c3d" />
                </Field>
                <Field label="Message">
                  <input name="message" />
                </Field>
                <Field label="Reason">
                  <input name="reason" />
                </Field>
              </ActionForm>
            </Sheet>
          )}
          {latest?.status === "FAILED" && <ActionForm action={retryJob.bind(null, app, name, latest.jobId!)} submit="Retry" icon={<RotateCw size={16} />} />}
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
          <Sheet title="Branch settings" label="Edit branch settings" icon={<Settings2 size={15} />} testId="edit-branch">
            <ActionForm action={updateBranch.bind(null, app, name, !!branch.enableBasicAuth)} submit="Save" testId="edit-branch">
              <Field label="Stage" rule={UpdateBranch.stage}>
                <select name="stage" defaultValue={branch.stage}>
                  {STAGES.map((s) => (
                    <option key={s} value={s}>
                      {s[0] + s.slice(1).toLowerCase().replace("_", " ")}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Environment variables" format="env" hint="Override the app's for this branch">
                <textarea name="env" rows={4} defaultValue={envText(env)} placeholder="API_URL=https://staging.example.com" />
              </Field>
              <MoreFields>
                <div className="form-row">
                  <Field label="Display name" rule={UpdateBranch.displayName}>
                    <input name="displayName" defaultValue={branch.displayName} />
                  </Field>
                  <Field label="Framework" rule={UpdateBranch.framework}>
                    <input name="framework" defaultValue={branch.framework} placeholder="React" />
                  </Field>
                </div>
                <Field label="Description" rule={UpdateBranch.description}>
                  <input name="description" defaultValue={branch.description} />
                </Field>
                <Field label="Build specification" format="yaml" rule={UpdateBranch.buildSpec} hint="Overrides the app's">
                  <textarea name="buildSpec" rows={6} className="code-editor" spellCheck={false} defaultValue={branch.buildSpec} />
                </Field>
                <label className="check">
                  <input type="checkbox" name="basicAuth" defaultChecked={!!branch.enableBasicAuth} /> Password protect
                </label>
                <Field label="Credentials" hint={branch.enableBasicAuth ? "user:password; blank keeps the current one" : "user:password"}>
                  <input name="credentials" autoComplete="off" />
                </Field>
                <div className="form-row">
                  <label className="check">
                    <input type="checkbox" name="autoBuild" defaultChecked={branch.enableAutoBuild !== false} /> Build on push
                  </label>
                  <label className="check">
                    <input type="checkbox" name="previews" defaultChecked={!!branch.enablePullRequestPreview} /> Pull request previews
                  </label>
                </div>
                <Field label="Cache TTL (seconds)" rule={UpdateBranch.ttl}>
                  <input name="ttl" defaultValue={branch.ttl} inputMode="numeric" />
                </Field>
              </MoreFields>
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteBranch.bind(null, app, name)} submit="Delete branch" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name}?`} />
        </>
      }
    >
      <LiveRefresh when={busy} />
      <Specs
        items={[
          { label: "Stage", icon: <Layers size={15} />, value: branch.stage?.toLowerCase().replace("_", " ") },
          branch.framework && { label: "Framework", icon: frameworkIcon(branch.framework) ? <AwsIcon icon={frameworkIcon(branch.framework)!} size={15} /> : <GitBranch size={15} />, value: branch.framework },
          branch.enableBasicAuth && { label: "Basic auth", icon: <Lock size={15} />, value: "on" },
          live && { label: "Deployed", icon: <Clock size={15} />, value: ago(live.endTime) },
          live && { label: "Site", icon: <ExternalLink size={15} />, value: <a href={siteUrl(app, name)}>{new URL(siteUrl(app, name)).host}</a> },
        ]}
      />
      <Section title="Deployments" count={token ? undefined : jobs.length} plain>
        <List
          label="Deployments"
          empty={<Empty icon={ICONS.amplify} action={buildable ? <ActionForm action={build.bind(null, app, name)} submit="Run build" testId="run-first-build" /> : undefined} />}
          rows={jobs.map((j) => ({
            key: j.jobId!,
            icon: <GitCommitVertical size={18} />,
            title: `#${j.jobId}`,
            subtitle: j.commitMessage || j.commitId?.slice(0, 7),
            href: jobHref(j.jobId!),
            meta: (
              <>
                <Pill>{j.jobType?.toLowerCase().replace("_", " ")}</Pill>
                {duration(j.startTime, j.endTime) && <span>{duration(j.startTime, j.endTime)}</span>}
                <Status tone={tone(j.status)}>{j.status?.toLowerCase() ?? ""}</Status>
                <span>{ago(j.startTime)}</span>
              </>
            ),
            actions:
              j.status === "RUNNING" || j.status === "PENDING" ? (
                <ActionForm action={stopJob.bind(null, app, name, j.jobId!)} submit={`Stop job ${j.jobId}`} icon={<Square size={14} />} tone="danger" />
              ) : undefined,
          }))}
        />
        <More shown={jobs.length} noun="jobs" href={next ? `/amplify/branch?app=${app}&name=${encodeURIComponent(name)}&token=${encodeURIComponent(next)}` : undefined} />
      </Section>
      {Object.keys(env).length > 0 && (
        <Section title="Environment variables" count={Object.keys(env).length}>
          <Facts items={Object.entries(env).map(([k, v]) => [<code key={k}>{k}</code>, <code key={`${k}=`}>{v}</code>])} />
        </Section>
      )}
      {branch.buildSpec && (
        <Section title="Build specification">
          <CodeBlock value={branch.buildSpec} label="Build specification" />
        </Section>
      )}
      {branch.backendEnvironmentArn && (
        <Section>
          <Facts items={[["Backend environment", <code key="b">{branch.backendEnvironmentArn.split("/").pop()}</code>]]} />
        </Section>
      )}
    </Page>
  );
}
