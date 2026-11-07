import { GetAppCommand, ListBranchesCommand, ListDomainAssociationsCommand, ListJobsCommand } from "@aws-sdk/client-amplify";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { Clock, ExternalLink, GitBranch, Globe, Plus, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { siteUrl } from "../../../lib/amplify";
import { amplify, ICONS, tone } from "../../../lib/clients";
import { createBranch, deleteApp } from "../actions";

export const metadata: Metadata = { title: "App" };

type Props = { searchParams: Promise<{ id?: string }> };

const STAGE_TONE = { PRODUCTION: "info", BETA: "warn" } as Record<string, "info" | "warn">;

export default async function App({ searchParams }: Props) {
  const id = (await searchParams).id ?? "";
  const back = { href: "/amplify", label: "All apps" };
  const data = await load(async () => {
    const client = await amplify();
    const [app, branches, domains] = await Promise.all([
      client.send(new GetAppCommand({ appId: id })).then((r) => r.app!),
      client.send(new ListBranchesCommand({ appId: id, maxResults: 50 })).then((r) => r.branches ?? []),
      client.send(new ListDomainAssociationsCommand({ appId: id })).then((r) => r.domainAssociations ?? [], () => []),
    ]);
    const jobs = await Promise.all(branches.map((b) => client.send(new ListJobsCommand({ appId: id, branchName: b.branchName, maxResults: 1 })).then((r) => r.jobSummaries?.[0], () => undefined)));
    return { app, branches: branches.map((b, i) => ({ ...b, job: jobs[i] })), domains };
  });
  if (!data.ok) {
    return (
      <Page title={id} icon={ICONS.amplify} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { app, branches, domains } = data.value;
  const production = branches.find((b) => b.stage === "PRODUCTION") ?? branches[0];
  const env = app.environmentVariables ?? {};
  return (
    <Page
      title={app.name!}
      icon={ICONS.amplify}
      back={back}
      subtitle={app.appArn}
      actions={
        <>
          {production?.job && (
            <a className="icon-button plain" href={siteUrl(id, production.branchName!)} aria-label="Visit deployed URL" title="Visit">
              <ExternalLink size={16} />
            </a>
          )}
          <ActionForm action={deleteApp.bind(null, id)} submit="Delete app" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${app.name}?`} />
        </>
      }
    >
      <Specs
        items={[
          { label: "Domain", icon: <Globe size={15} />, value: app.defaultDomain },
          app.repository && { label: "Repository", icon: <GitBranch size={15} />, value: <a href={app.repository}>{app.repository.replace(/^https:\/\/(github\.com\/)?/, "")}</a> },
          { label: "Updated", icon: <Clock size={15} />, value: ago(app.updateTime) },
        ]}
      />
      <Section
        title="Branches"
        count={branches.length}
        plain
        actions={
          <Sheet title="Connect branch" label="Connect branch" icon={<Plus size={15} />} testId="create-branch">
            <ActionForm action={createBranch.bind(null, id)} submit="Save" testId="create-branch">
              <Field label="Branch">
                <input name="name" required autoFocus />
              </Field>
              <Field label="Stage">
                <select name="stage" defaultValue="DEVELOPMENT">
                  {["PRODUCTION", "BETA", "DEVELOPMENT", "EXPERIMENTAL", "PULL_REQUEST"].map((s) => (
                    <option key={s} value={s}>
                      {s[0] + s.slice(1).toLowerCase().replace("_", " ")}
                    </option>
                  ))}
                </select>
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        <List
          label="Branches"
          empty={<Empty icon={ICONS.amplify} />}
          rows={branches.map((b) => ({
            key: b.branchName!,
            icon: <GitBranch size={18} />,
            title: b.displayName ?? b.branchName,
            subtitle: b.job ? `${b.job.jobType?.toLowerCase().replace("_", " ")} #${b.job.jobId}${b.job.commitMessage ? ` · ${b.job.commitMessage}` : ""}` : undefined,
            href: `/amplify/branch?app=${id}&name=${encodeURIComponent(b.branchName!)}`,
            meta: (
              <>
                {STAGE_TONE[b.stage ?? ""] && <Pill tone={STAGE_TONE[b.stage!]}>{b.stage!.toLowerCase()}</Pill>}
                {b.job ? <Status tone={tone(b.job.status)}>{b.job.status?.toLowerCase()}</Status> : <Status tone="neutral">not deployed</Status>}
                {b.job && <span>{ago(b.job.endTime ?? b.job.startTime)}</span>}
              </>
            ),
            actions: b.job?.status === "SUCCEED" ? (
              <a className="icon-button plain" href={siteUrl(id, b.branchName!)} aria-label={`Visit ${b.branchName}`} title="Visit">
                <ExternalLink size={15} />
              </a>
            ) : undefined,
          }))}
        />
      </Section>
      {domains.length > 0 && (
        <Section title="Custom domains" count={domains.length} plain>
          <List
            label="Domains"
            rows={domains.map((d) => ({
              key: d.domainName!,
              icon: <AwsIcon icon="service/AmazonRoute53" size={22} />,
              title: d.domainName,
              subtitle: (d.subDomains ?? []).map((s) => `${s.subDomainSetting?.prefix || "@"} → ${s.subDomainSetting?.branchName}`).join(" · "),
              meta: <Status tone={tone(d.domainStatus)}>{d.domainStatus?.toLowerCase().replace(/_/g, " ")}</Status>,
            }))}
          />
        </Section>
      )}
      {Object.keys(env).length > 0 && (
        <Section title="Environment variables" count={Object.keys(env).length}>
          <Facts items={Object.entries(env).map(([k, v]) => [<code key={k}>{k}</code>, <code key={`${k}=`}>{v}</code>])} />
        </Section>
      )}
    </Page>
  );
}
