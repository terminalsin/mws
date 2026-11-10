import { GetAppCommand, ListBranchesCommand, ListDomainAssociationsCommand, ListJobsCommand, ListWebhooksCommand } from "@aws-sdk/client-amplify";
import { ago, all, describeError, load } from "@mws-dashboard/aws";
import { roleOptions } from "@mws-dashboard/aws/auto";
import { ActionForm, AwsIcon, CodeBlock, CopyButton, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { UpdateApp } from "@mws-dashboard/ui/model/amplify";
import { Clock, ExternalLink, GitBranch, Globe, Lock, Pencil, Play, Plus, Settings2, Trash2, Webhook } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { RUNNING, rulesText, siteUrl, envText } from "../../../lib/amplify";
import { amplify, ICONS, tone } from "../../../lib/clients";
import { BRANCH, CreateBranch } from "../../../lib/rules";
import { createBranch, createDomain, createWebhook, deleteApp, deleteWebhook, retargetWebhook, triggerWebhook, updateApp } from "../actions";

export const metadata: Metadata = { title: "App" };

type Props = { searchParams: Promise<{ id?: string }> };

const STAGE_TONE = { PRODUCTION: "info", BETA: "warn" } as Record<string, "info" | "warn">;

export default async function App({ searchParams }: Props) {
  const id = (await searchParams).id ?? "";
  const back = { href: "/amplify", label: "All apps" };
  const data = await load(async () => {
    const client = await amplify();
    const [app, branches, domains, webhooks] = await Promise.all([
      client.send(new GetAppCommand({ appId: id })).then((r) => r.app!),
      all((nextToken) => client.send(new ListBranchesCommand({ appId: id, maxResults: 50, nextToken })), (r) => r.branches, (r) => r.nextToken),
      all((nextToken) => client.send(new ListDomainAssociationsCommand({ appId: id, nextToken })), (r) => r.domainAssociations, (r) => r.nextToken).then(
        (list) => ({ list, error: undefined as string | undefined }),
        (e: unknown) => ({ list: [], error: describeError(e) }),
      ),
      all((nextToken) => client.send(new ListWebhooksCommand({ appId: id, nextToken })), (r) => r.webhooks, (r) => r.nextToken).catch(() => []),
    ]);
    // A failed lookup is shown as such, not as "not deployed".
    const jobs = await Promise.all(
      branches.map((b) =>
        client.send(new ListJobsCommand({ appId: id, branchName: b.branchName, maxResults: 1 })).then(
          (r) => ({ job: r.jobSummaries?.[0], error: undefined }),
          (e: unknown) => ({ job: undefined, error: describeError(e) }),
        ),
      ),
    );
    return { app, branches: branches.map((b, i) => ({ ...b, ...jobs[i] })), domains, webhooks };
  });
  if (!data.ok) {
    return (
      <Page title={id} icon={ICONS.amplify} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { app, branches, domains, webhooks } = data.value;
  const roles = await roleOptions("amplify.amazonaws.com");
  // The app's production branch, as Amplify names it; a PRODUCTION-stage branch otherwise.
  const production = branches.find((b) => b.branchName === app.productionBranch?.branchName) ?? branches.find((b) => b.stage === "PRODUCTION");
  const env = app.environmentVariables ?? {};
  const rules = app.customRules ?? [];
  const running = branches.some((b) => RUNNING.test(b.job?.status ?? "")) || domains.list.some((d) => /PENDING|IN_PROGRESS|CREATING|REQUESTING|AWAITING|UPDATING/.test(d.domainStatus ?? ""));
  const edit = (
    <Sheet title="App settings" label="Edit app settings" icon={<Settings2 size={15} />} testId="edit-app">
      <ActionForm action={updateApp.bind(null, id, !!app.enableBasicAuth)} submit="Save" testId="edit-app">
        <div className="form-row">
          <Field label="Name" rule={UpdateApp.name}>
            <input name="name" required defaultValue={app.name} />
          </Field>
          <Field label="Platform" rule={UpdateApp.platform}>
            <select name="platform" defaultValue={app.platform}>
              <option value="WEB">Static (WEB)</option>
              <option value="WEB_COMPUTE">SSR (WEB_COMPUTE)</option>
              <option value="WEB_DYNAMIC">WEB_DYNAMIC</option>
            </select>
          </Field>
        </div>
        <Field label="Description" rule={UpdateApp.description}>
          <input name="description" defaultValue={app.description} />
        </Field>
        <Field label="Service role">
          <select name="role" defaultValue={app.iamServiceRoleArn ?? ""}>
            <option value="">None</option>
            {[...roles, ...(app.iamServiceRoleArn && !roles.some((r) => r.value === app.iamServiceRoleArn) ? [{ value: app.iamServiceRoleArn, label: app.iamServiceRoleArn.split("/").pop()! }] : [])].map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Environment variables" format="env">
          <textarea name="env" rows={4} defaultValue={envText(env)} placeholder="API_URL=https://api.example.com" />
        </Field>
        <Field label="Rewrites and redirects" hint="One per line: source target status, e.g. /old /new 301 or /<*> /index.html 404-200">
          <textarea name="rules" rows={4} className="code-editor" spellCheck={false} defaultValue={rulesText(rules)} />
        </Field>
        <Field label="Build specification" format="yaml" rule={UpdateApp.buildSpec}>
          <textarea name="buildSpec" rows={6} className="code-editor" spellCheck={false} defaultValue={app.buildSpec} />
        </Field>
        <Field label="Custom headers" format="yaml" rule={UpdateApp.customHeaders}>
          <textarea name="customHeaders" rows={4} className="code-editor" spellCheck={false} defaultValue={app.customHeaders} placeholder={"customHeaders:\n  - pattern: '**/*'\n    headers:\n      - key: X-Frame-Options\n        value: DENY"} />
        </Field>
        <label className="check">
          <input type="checkbox" name="basicAuth" defaultChecked={!!app.enableBasicAuth} /> Password protect every branch
        </label>
        <Field label="Credentials" hint={app.enableBasicAuth ? "user:password; blank keeps the current one" : "user:password"}>
          <input name="credentials" autoComplete="off" />
        </Field>
        <label className="check">
          <input type="checkbox" name="autoBuild" defaultChecked={app.enableBranchAutoBuild !== false} /> Build branches on push
        </label>
        <label className="check">
          <input type="checkbox" name="autoDelete" defaultChecked={!!app.enableBranchAutoDeletion} /> Delete branches removed from Git
        </label>
      </ActionForm>
    </Sheet>
  );
  return (
    <Page
      title={app.name!}
      icon={ICONS.amplify}
      back={back}
      subtitle={app.appArn}
      actions={
        <>
          {production?.job?.status === "SUCCEED" && (
            <a className="icon-button plain" href={siteUrl(id, production.branchName!)} aria-label="Visit deployed URL" title="Visit">
              <ExternalLink size={16} />
            </a>
          )}
          {edit}
          <ActionForm action={deleteApp.bind(null, id)} submit="Delete app" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${app.name}?`} />
        </>
      }
    >
      <LiveRefresh when={running} />
      <Specs
        items={[
          { label: "Domain", icon: <Globe size={15} />, value: app.defaultDomain },
          app.repository && { label: "Repository", icon: <GitBranch size={15} />, value: /^https?:/.test(app.repository) ? <a href={app.repository}>{app.repository.replace(/^https:\/\/(github\.com\/)?/, "")}</a> : <code>{app.repository}</code> },
          app.platform && app.platform !== "WEB" && { label: "Platform", icon: <Settings2 size={15} />, value: app.platform },
          app.enableBasicAuth && { label: "Basic auth", icon: <Lock size={15} />, value: "on" },
          { label: "Updated", icon: <Clock size={15} />, value: ago(app.updateTime) },
        ]}
      />
      {app.description && <p className="muted">{app.description}</p>}
      <Section
        title="Branches"
        count={branches.length}
        plain
        actions={
          <Sheet title="Connect branch" label="Connect branch" icon={<Plus size={15} />} testId="create-branch">
            <ActionForm action={createBranch.bind(null, id)} submit="Save" testId="create-branch">
              <Field label="Branch" rule={BRANCH} member="branchName" taken={branches.map((b) => b.branchName!)} unique>
                <input name="name" required autoFocus />
              </Field>
              <Field label="Stage" rule={CreateBranch.stage}>
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
            subtitle: b.job ? `${b.job.jobType?.toLowerCase().replace("_", " ")} #${b.job.jobId}${b.job.commitMessage ? ` · ${b.job.commitMessage}` : ""}` : b.error,
            href: `/amplify/branch?app=${id}&name=${encodeURIComponent(b.branchName!)}`,
            meta: (
              <>
                {b.branchName === production?.branchName && <Pill tone="info">production</Pill>}
                {b.branchName !== production?.branchName && STAGE_TONE[b.stage ?? ""] && <Pill tone={STAGE_TONE[b.stage!]}>{b.stage!.toLowerCase()}</Pill>}
                {b.job ? <Status tone={tone(b.job.status)}>{b.job.status?.toLowerCase()}</Status> : b.error ? <Status tone="bad">unknown</Status> : <Status tone="neutral">not deployed</Status>}
                {b.job && <span>{ago(b.job.endTime ?? b.job.startTime)}</span>}
              </>
            ),
            actions:
              b.job?.status === "SUCCEED" ? (
                <a className="icon-button plain" href={siteUrl(id, b.branchName!)} aria-label={`Visit ${b.branchName}`} title="Visit">
                  <ExternalLink size={15} />
                </a>
              ) : undefined,
          }))}
        />
      </Section>
      <Section
        title="Custom domains"
        count={domains.list.length}
        plain
        actions={
          branches.length > 0 ? (
            <Sheet title="Add domain" label="Add domain" icon={<Plus size={15} />} testId="create-domain">
              <ActionForm action={createDomain.bind(null, id)} submit="Add domain" testId="create-domain">
                <Field label="Domain" format="domain">
                  <input name="domain" required autoFocus placeholder="example.com" />
                </Field>
                <Field label="Sub-domains" hint="One per line: prefix=branch (@ for the apex)">
                  <textarea name="subDomains" rows={3} defaultValue={production ? `@=${production.branchName}\nwww=${production.branchName}` : ""} required />
                </Field>
                <label className="check">
                  <input type="checkbox" name="autoSub" /> Sub-domain per new branch
                </label>
              </ActionForm>
            </Sheet>
          ) : undefined
        }
      >
        {domains.error ? (
          <ErrorNotice error={domains.error} />
        ) : (
          <List
            label="Domains"
            rows={domains.list.map((d) => ({
              key: d.domainName!,
              icon: <AwsIcon icon="service/AmazonRoute53" size={22} />,
              title: d.domainName,
              subtitle: (d.subDomains ?? []).map((s) => `${s.subDomainSetting?.prefix || "@"} → ${s.subDomainSetting?.branchName}`).join(" · "),
              href: `/amplify/domain?app=${id}&name=${encodeURIComponent(d.domainName!)}`,
              meta: <Status tone={tone(d.domainStatus)}>{d.domainStatus?.toLowerCase().replace(/_/g, " ") ?? ""}</Status>,
            }))}
          />
        )}
      </Section>
      {branches.length > 0 && (
        <Section
          title="Webhooks"
          count={webhooks.length}
          plain
          actions={
            <Sheet title="Create webhook" label="Create webhook" icon={<Webhook size={15} />} testId="create-webhook">
              <ActionForm action={createWebhook.bind(null, id)} submit="Create" testId="create-webhook">
                <Field label="Branch">
                  <select name="branch" defaultValue={production?.branchName}>
                    {branches.map((b) => (
                      <option key={b.branchName}>{b.branchName}</option>
                    ))}
                  </select>
                </Field>
                <Field label="Name">
                  <input name="description" placeholder="ci-trigger" />
                </Field>
              </ActionForm>
            </Sheet>
          }
        >
          <List
            label="Webhooks"
            rows={webhooks.map((w) => ({
              key: w.webhookId!,
              icon: <Webhook size={18} />,
              title: w.description || w.webhookId,
              subtitle: (
                <span className="inline-icon">
                  <code className="clip">{w.webhookUrl}</code>
                  <CopyButton value={w.webhookUrl!} label="Copy webhook URL" />
                </span>
              ),
              meta: (
                <>
                  <Pill icon={<GitBranch size={11} />}>{w.branchName}</Pill>
                  <span>{ago(w.createTime)}</span>
                </>
              ),
              actions: (
                <>
                  <ActionForm action={triggerWebhook.bind(null, w.webhookUrl!)} submit={`Trigger ${w.description || w.webhookId}`} icon={<Play size={15} />} />
                  <Sheet title="Edit webhook" label={`Edit ${w.description || w.webhookId}`} icon={<Pencil size={15} />} testId="edit-webhook">
                    <ActionForm action={retargetWebhook.bind(null, w.webhookId!)} submit="Save" testId="edit-webhook">
                      <Field label="Branch">
                        <select name="branch" defaultValue={w.branchName}>
                          {branches.map((b) => (
                            <option key={b.branchName}>{b.branchName}</option>
                          ))}
                        </select>
                      </Field>
                      <Field label="Name">
                        <input name="description" defaultValue={w.description} />
                      </Field>
                    </ActionForm>
                  </Sheet>
                  <ActionForm action={deleteWebhook.bind(null, w.webhookId!)} submit={`Delete ${w.description || w.webhookId}`} icon={<Trash2 size={15} />} tone="danger" confirm="Delete this webhook?" />
                </>
              ),
            }))}
          />
        </Section>
      )}
      {rules.length > 0 && (
        <Section title="Rewrites and redirects" count={rules.length} plain>
          <List
            label="Rewrites and redirects"
            rows={rules.map((r, i) => ({
              key: String(i),
              icon: <Pill>{r.status ?? "200"}</Pill>,
              title: (
                <code>
                  {r.source} → {r.target}
                </code>
              ),
              subtitle: r.condition,
            }))}
          />
        </Section>
      )}
      {Object.keys(env).length > 0 && (
        <Section title="Environment variables" count={Object.keys(env).length}>
          <Facts items={Object.entries(env).map(([k, v]) => [<code key={k}>{k}</code>, <code key={`${k}=`}>{v}</code>])} />
        </Section>
      )}
      {app.buildSpec && (
        <Section title="Build specification">
          <CodeBlock value={app.buildSpec} label="Build specification" />
        </Section>
      )}
      {app.customHeaders && (
        <Section title="Custom headers">
          <CodeBlock value={app.customHeaders} label="Custom headers" />
        </Section>
      )}
      {app.iamServiceRoleArn && (
        <Section>
          <Facts
            items={[
              app.iamServiceRoleArn && ["Service role", <Link key="r" href={`/iam/roles/${encodeURIComponent(app.iamServiceRoleArn.split("/").pop()!)}`}>{app.iamServiceRoleArn.split("/").pop()}</Link>],
            ]}
          />
        </Section>
      )}
    </Page>
  );
}
