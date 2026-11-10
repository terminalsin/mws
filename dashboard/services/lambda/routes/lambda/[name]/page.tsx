import {
  GetFunctionCommand,
  GetFunctionEventInvokeConfigCommand,
  GetFunctionUrlConfigCommand,
  ListProvisionedConcurrencyConfigsCommand,
} from "@aws-sdk/client-lambda";
import { ago, all, bytes, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, FileIcon, List, Page, Section, Segments, Sheet, Specs, Status, runtimeIcon } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { strFromU8, unzipSync } from "fflate";
import { CircleAlert, Clock, Cpu, GitCommitVertical, Globe, MemoryStick, Timer, Trash2, Upload } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, lambda, urlOnMws } from "../../../lib/clients";
import { ALIAS_DESCRIPTION } from "../../../lib/rules";
import { Aliases, Versions } from "../../../lib/function/aliases";
import { Configuration } from "../../../lib/function/config";
import { Permissions } from "../../../lib/function/permissions";
import { Triggers } from "../../../lib/function/triggers";
import { aliases, eventSources, lambdaRoles, mappings, policy, pushTriggers, versions } from "../../../lib/lambda";
import { deleteFunction, invoke, publishVersion, saveCode, uploadCode } from "../actions";

type Props = { params: Promise<{ name: string }>; searchParams: Promise<{ tab?: string; file?: string; qualifier?: string }> };

const TABS = ["code", "test", "config", "triggers", "permissions", "aliases", "versions"] as const;

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  return { title: decodeURIComponent((await params).name) };
}

async function packageFiles(location: string | undefined) {
  if (!location) return null;
  try {
    const zip = new Uint8Array(await (await fetch(location, { cache: "no-store" })).arrayBuffer());
    return unzipSync(zip);
  } catch {
    return null;
  }
}

const notFound = <T,>(fallback: T) => (e: unknown) => {
  if (e instanceof Error && e.name === "ResourceNotFoundException") return fallback;
  throw e;
};

export default async function LambdaFunction({ params, searchParams }: Props) {
  const name = decodeURIComponent((await params).name);
  const sp = await searchParams;
  const tab = (TABS as readonly string[]).includes(sp.tab ?? "") ? sp.tab! : "code";
  const base = `/lambda/${encodeURIComponent(name)}`;
  const back = { href: "/lambda", label: "Functions" };
  const data = await load(async () => {
    const client = await lambda();
    const [fn, esms, url, vers, als, pol] = await Promise.all([
      client.send(new GetFunctionCommand({ FunctionName: name })),
      mappings(name),
      client.send(new GetFunctionUrlConfigCommand({ FunctionName: name })).then((r) => r as typeof r | undefined, notFound(undefined)),
      versions(name).then((v) => v.filter((x) => x.Version !== "$LATEST")),
      aliases(name),
      policy(name),
    ]);
    return { fn, esms, url, versions: vers, aliases: als, policy: pol };
  });
  if (!data.ok) {
    return (
      <Page title={name} icon={ICONS.fn} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { fn, esms, url, versions: vers, aliases: als, policy: pol } = data.value;
  const c = fn.Configuration!;
  const logGroup = c.LoggingConfig?.LogGroup ?? `/aws/lambda/${c.FunctionName}`;
  const logo = runtimeIcon(c.Runtime ?? (c.PackageType === "Image" ? "image" : undefined));
  const roleName = c.Role?.split("/").pop();
  const versionNumbers = vers.map((v) => v.Version!);
  const qualifiers = [...versionNumbers, ...als.map((a) => a.Name!)];
  const mwsUrl = url?.FunctionUrl ? urlOnMws(url.FunctionUrl) : undefined;
  const push = pol.statements.length;
  const changing = c.State === "Pending" || c.LastUpdateStatus === "InProgress";

  let body;
  if (tab === "code") {
    const files = c.PackageType === "Zip" ? await packageFiles(fn.Code?.Location) : null;
    const names = Object.keys(files ?? {}).filter((f) => !f.endsWith("/")).sort();
    const handlerFile = names.find((n) => n.replace(/\.[^.]+$/, "") === c.Handler?.split(".").slice(0, -1).join(".")) ?? names[0];
    const current = sp.file && names.includes(sp.file) ? sp.file : handlerFile;
    const content = current && files ? files[current] : undefined;
    const editable = content && content.length < 256 * 1024 && !content.slice(0, 1024).includes(0);
    const upload = (
      <Sheet title={c.PackageType === "Image" ? "Deploy new image" : "Upload .zip"} label={c.PackageType === "Image" ? "Deploy new image" : "Upload .zip file"} icon={<Upload size={15} aria-hidden />} testId="upload-code">
        <ActionForm action={uploadCode.bind(null, name)} submit="Deploy" testId="upload-code">
          {c.PackageType === "Image" ? (
            <Field label="Image URI">
              <input name="image" required defaultValue={fn.Code?.ImageUri} spellCheck={false} />
            </Field>
          ) : (
            <Field label=".zip file">
              <input type="file" name="zip" accept=".zip,application/zip" required />
            </Field>
          )}
        </ActionForm>
      </Sheet>
    );
    body = (
      <Section title={c.PackageType === "Image" ? "Image" : "Code source"} plain actions={upload}>
        {!files ? (
          <Empty icon={logo ?? ICONS.fn}>{c.PackageType === "Image" ? <code>{fn.Code?.ImageUri}</code> : null}</Empty>
        ) : (
          <div className="split">
            {names.length > 1 && (
              <List
                label="Files"
                rows={names.map((n) => ({
                  key: n,
                  icon: <FileIcon name={n} size={18} />,
                  title: n === current ? <strong>{n}</strong> : n,
                  href: `${base}?file=${encodeURIComponent(n)}`,
                  meta: <span>{bytes(files[n].length)}</span>,
                }))}
              />
            )}
            {editable ? (
              <ActionForm action={saveCode.bind(null, name, current!)} submit="Deploy" testId="save-code">
                {current!.endsWith(".json") ? (
                  <Field label={current!} format="json">
                    <textarea name="code" className="code-editor" rows={Math.min(40, strFromU8(content).split("\n").length + 4)} spellCheck={false} defaultValue={strFromU8(content).replace(/\n$/, "")} />
                  </Field>
                ) : (
                  <textarea name="code" className="code-editor" rows={Math.min(40, strFromU8(content).split("\n").length + 4)} aria-label="Code" spellCheck={false} defaultValue={strFromU8(content).replace(/\n$/, "")} />
                )}
              </ActionForm>
            ) : (
              <Empty>{current}</Empty>
            )}
          </div>
        )}
      </Section>
    );
  } else if (tab === "config") {
    const client = await lambda();
    const [roles, provisioned, asyncConfig, destinations] = await Promise.all([
      lambdaRoles().catch(() => []),
      all((Marker) => client.send(new ListProvisionedConcurrencyConfigsCommand({ FunctionName: name, Marker })), (r) => r.ProvisionedConcurrencyConfigs, (r) => r.NextMarker).catch(() => []),
      client.send(new GetFunctionEventInvokeConfigCommand({ FunctionName: name })).then((r) => r as typeof r | undefined, notFound(undefined)),
      eventSources().catch(() => [] as string[]),
    ]);
    body = (
      <Configuration
        name={name}
        c={c}
        account={c.FunctionArn?.split(":")[4]}
        roles={roles.map((r) => r.Arn!)}
        url={url}
        mwsUrl={mwsUrl}
        reserved={fn.Concurrency?.ReservedConcurrentExecutions}
        provisioned={provisioned}
        asyncConfig={asyncConfig}
        tags={fn.Tags ?? {}}
        qualifiers={qualifiers}
        destinations={destinations.filter((d) => d.split(":")[2] === "sqs")}
      />
    );
  } else if (tab === "triggers") {
    const sources = await eventSources().catch(() => [] as string[]);
    body = <Triggers name={name} arn={c.FunctionArn!} mappings={esms} statements={pol.statements} sources={sources} />;
  } else if (tab === "permissions") {
    const sources = await eventSources().catch(() => [] as string[]);
    body = <Permissions name={name} role={c.Role} statements={pol.statements} qualifiers={qualifiers} sources={sources} />;
  } else if (tab === "aliases") {
    body = <Aliases name={name} base={base} aliases={als} versions={versionNumbers} />;
  } else if (tab === "versions") {
    body = <Versions base={base} versions={vers} aliases={als} />;
  } else {
    const qualifier = sp.qualifier && qualifiers.includes(sp.qualifier) ? sp.qualifier : "";
    body = (
      <Section>
        <ActionForm action={invoke.bind(null, name)} submit="Invoke" testId="invoke">
          <div className="form-row">
            {qualifiers.length > 0 && (
              <Field label="Version or alias">
                <select name="qualifier" defaultValue={qualifier}>
                  <option value="">$LATEST</option>
                  {qualifiers.map((q) => (
                    <option key={q}>{q}</option>
                  ))}
                </select>
              </Field>
            )}
            <Field label="Invocation type">
              <select name="type" defaultValue="RequestResponse">
                <option>RequestResponse</option>
                <option>Event</option>
                <option>DryRun</option>
              </select>
            </Field>
          </div>
          <Field label="Event" format="json">
            <textarea name="payload" rows={8} className="code-editor" spellCheck={false} defaultValue={'{\n  "hello": "world"\n}'} />
          </Field>
        </ActionForm>
      </Section>
    );
  }

  return (
    <Page
      title={name}
      icon={ICONS.fn}
      back={back}
      subtitle={c.FunctionArn}
      actions={
        <>
          <a className="icon-button plain" href={`/logs/group?name=${encodeURIComponent(logGroup)}`} aria-label="View logs" title="Logs">
            <AwsIcon icon="service/AmazonCloudWatch" size={18} />
          </a>
          <Sheet title="Publish version" label="Publish version" icon={<GitCommitVertical size={16} />} testId="publish-version">
            <ActionForm action={publishVersion.bind(null, name)} submit="Publish" testId="publish-version">
              <Field label="Description" rule={ALIAS_DESCRIPTION}>
                <input name="description" autoFocus />
              </Field>
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteFunction.bind(null, name)} submit="Delete function" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name}?`} testId="delete-function" />
        </>
      }
    >
      <LiveRefresh when={changing} />
      <Specs
        items={[
          { label: "Runtime", icon: <AwsIcon icon={logo ?? ICONS.fn} size={16} />, value: c.Runtime ?? c.PackageType },
          c.State && c.State !== "Active" && { label: "State", icon: <CircleAlert size={15} />, value: <Status tone={c.State === "Failed" ? "bad" : "warn"}>{c.StateReason ?? c.State}</Status> },
          c.LastUpdateStatus && c.LastUpdateStatus !== "Successful" && {
            label: "Last update",
            icon: <CircleAlert size={15} />,
            value: <Status tone={c.LastUpdateStatus === "Failed" ? "bad" : "info"}>{c.LastUpdateStatus === "Failed" ? (c.LastUpdateStatusReason ?? "Update failed") : "Updating"}</Status>,
          },
          { label: "Memory", icon: <MemoryStick size={15} />, value: `${c.MemorySize} MB` },
          { label: "Timeout", icon: <Timer size={15} />, value: `${c.Timeout} s` },
          { label: "Architecture", icon: <Cpu size={15} />, value: c.Architectures?.[0] ?? "x86_64" },
          url?.FunctionUrl && mwsUrl && {
            label: "Function URL",
            icon: <Globe size={15} />,
            value: (
              <a href={mwsUrl} target="_blank" rel="noreferrer" title={url.FunctionUrl}>
                {new URL(url.FunctionUrl).host}
              </a>
            ),
          },
          { label: "Execution role", icon: <AwsIcon icon="resource/AWSIdentityAccessManagementRole" size={16} />, value: <Link href={`/iam/roles/${encodeURIComponent(roleName ?? "")}`}>{roleName}</Link> },
          { label: "Last modified", icon: <Clock size={15} />, value: ago(c.LastModified) },
        ]}
      />
      <Segments
        items={[
          { label: "Code", href: base, active: tab === "code" },
          { label: "Test", href: `${base}?tab=test`, active: tab === "test" },
          { label: "Configuration", href: `${base}?tab=config`, active: tab === "config" },
          { label: "Triggers", href: `${base}?tab=triggers`, active: tab === "triggers", count: esms.length + pushTriggers(pol.statements).length || undefined },
          { label: "Permissions", href: `${base}?tab=permissions`, active: tab === "permissions", count: push || undefined },
          { label: "Aliases", href: `${base}?tab=aliases`, active: tab === "aliases", count: als.length || undefined },
          { label: "Versions", href: `${base}?tab=versions`, active: tab === "versions", count: vers.length || undefined },
        ]}
      />
      {body}
    </Page>
  );
}
