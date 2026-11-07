import { GetFunctionCommand, GetFunctionUrlConfigCommand, ListEventSourceMappingsCommand, ListVersionsByFunctionCommand } from "@aws-sdk/client-lambda";
import { ago, bytes, load } from "@mws-dashboard/aws";
import {
  ActionForm,
  AwsIcon,
  Empty,
  ErrorNotice,
  Facts,
  Field,
  FileIcon,
  List,
  Page,
  Pill,
  Section,
  Segments,
  Sheet,
  Specs,
  Status,
  SERVICES,
  runtimeIcon,
  zoneHref,
} from "@mws-dashboard/ui";
import { unzipSync, strFromU8 } from "fflate";
import { CircleAlert, Clock, Cpu, GitCommitVertical, Globe, MemoryStick, Pause, Play, Settings2, Timer, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, lambda } from "../../../lib/clients";
import { createUrl, deleteFunction, deleteMapping, invoke, publishVersion, saveCode, saveConfiguration, setMapping } from "../actions";

type Props = { params: Promise<{ name: string }>; searchParams: Promise<{ tab?: string; file?: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  return { title: decodeURIComponent((await params).name) };
}

/** The service an event source ARN belongs to, for its icon. */
function sourceIcon(arn: string | undefined) {
  const svc = arn?.split(":")[2] ?? "";
  return SERVICES.find((s) => s.id === svc || s.endpoints.includes(svc))?.icon ?? ICONS.lambda;
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

export default async function LambdaFunction({ params, searchParams }: Props) {
  const name = decodeURIComponent((await params).name);
  const { tab = "code", file } = await searchParams;
  const base = `/lambda/${encodeURIComponent(name)}`;
  const back = { href: "/lambda", label: "Functions" };
  const data = await load(async () => {
    const client = await lambda();
    const [fn, mappings, url, versions] = await Promise.all([
      client.send(new GetFunctionCommand({ FunctionName: name })),
      client.send(new ListEventSourceMappingsCommand({ FunctionName: name })).then((r) => r.EventSourceMappings ?? []),
      client.send(new GetFunctionUrlConfigCommand({ FunctionName: name })).then((r) => r.FunctionUrl, () => undefined),
      client.send(new ListVersionsByFunctionCommand({ FunctionName: name })).then((r) => (r.Versions ?? []).filter((v) => v.Version !== "$LATEST"), () => []),
    ]);
    return { fn, mappings, url, versions };
  });
  if (!data.ok) {
    return (
      <Page title={name} icon={ICONS.fn} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { fn, mappings, url, versions } = data.value;
  const c = fn.Configuration!;
  const logGroup = c.LoggingConfig?.LogGroup ?? `/aws/lambda/${c.FunctionName}`;
  const env = c.Environment?.Variables ?? {};
  const logo = runtimeIcon(c.Runtime ?? (c.PackageType === "Image" ? "image" : undefined));
  const roleName = c.Role?.split("/").pop();

  let body;
  if (tab === "code" || (tab !== "test" && tab !== "config" && tab !== "triggers")) {
    const files = c.PackageType === "Zip" ? await packageFiles(fn.Code?.Location) : null;
    const names = Object.keys(files ?? {}).filter((f) => !f.endsWith("/")).sort();
    const handlerFile = names.find((n) => n.replace(/\.[^.]+$/, "") === c.Handler?.split(".").slice(0, -1).join(".")) ?? names[0];
    const current = file && names.includes(file) ? file : handlerFile;
    const content = current && files ? files[current] : undefined;
    const editable = content && content.length < 256 * 1024 && !content.slice(0, 1024).includes(0);
    body = !files ? (
      <Empty icon={logo ?? ICONS.fn}>{c.PackageType === "Image" ? fn.Code?.ImageUri : null}</Empty>
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
            <textarea name="code" className="code-editor" rows={Math.min(40, strFromU8(content).split("\n").length + 4)} aria-label="Code" spellCheck={false} defaultValue={strFromU8(content).replace(/\n$/, "")} />
          </ActionForm>
        ) : (
          <Empty>{current}</Empty>
        )}
      </div>
    );
  } else if (tab === "config") {
    body = (
      <>
        <Section
          title="Environment"
          count={Object.keys(env).length}
          actions={
            <Sheet title="Configuration" label="Edit configuration" icon={<Settings2 size={16} />} testId="edit-config">
              <ActionForm action={saveConfiguration.bind(null, name)} submit="Save" testId="edit-config">
                <Field label="Memory (MB)">
                  <input name="memory" type="number" min={128} max={10240} defaultValue={c.MemorySize} />
                </Field>
                <Field label="Timeout (s)">
                  <input name="timeout" type="number" min={1} max={900} defaultValue={c.Timeout} />
                </Field>
                <Field label="Handler">
                  <input name="handler" defaultValue={c.Handler} />
                </Field>
                <Field label="Execution role">
                  <input name="role" defaultValue={c.Role} />
                </Field>
                <textarea name="env" rows={6} aria-label="Environment variables" placeholder="KEY=value" defaultValue={Object.entries(env).map(([k, v]) => `${k}=${v}`).join("\n")} />
              </ActionForm>
            </Sheet>
          }
        >
          {Object.keys(env).length ? <Facts items={Object.entries(env).map(([k, v]) => [<code key={k}>{k}</code>, <code key={`${k}=`}>{v}</code>])} /> : <span className="muted">—</span>}
        </Section>
        <Section title="Settings">
          <Facts
            items={[
              ["Handler", <code key="h">{c.Handler}</code>],
              ["Architecture", c.Architectures?.join(", ")],
              ["Code size", bytes(c.CodeSize)],
              ["Ephemeral storage", c.EphemeralStorage?.Size && c.EphemeralStorage.Size !== 512 ? `${c.EphemeralStorage.Size} MB` : null],
              c.Layers?.length && ["Layers", c.Layers.map((l) => l.Arn?.split(":").slice(-2).join(":")).join(", ")],
              c.VpcConfig?.VpcId && ["VPC", c.VpcConfig.VpcId],
              c.DeadLetterConfig?.TargetArn && ["Dead-letter", c.DeadLetterConfig.TargetArn.split(":").pop()],
              ["Log group", <a key="l" href={`${zoneHref("observability", "/logs/group")}?name=${encodeURIComponent(logGroup)}`}>{logGroup}</a>],
            ]}
          />
        </Section>
        {versions.length > 0 && (
          <Section title="Versions" count={versions.length} plain>
            <List
              label="Versions"
              rows={versions.map((v) => ({ key: v.Version!, icon: <GitCommitVertical size={18} />, title: v.Version, subtitle: v.Description, meta: ago(v.LastModified) }))}
            />
          </Section>
        )}
      </>
    );
  } else if (tab === "triggers") {
    body = (
      <List
        label="Triggers"
        empty={<Empty icon={ICONS.fn} />}
        rows={mappings.map((m) => {
          const enabled = m.State === "Enabled" || m.State === "Enabling";
          return {
            key: m.UUID!,
            icon: <AwsIcon icon={sourceIcon(m.EventSourceArn)} size={24} />,
            title: m.EventSourceArn?.split(":").pop(),
            subtitle: m.FilterCriteria?.Filters?.length ? `${m.FilterCriteria.Filters.length} filter${m.FilterCriteria.Filters.length > 1 ? "s" : ""}` : undefined,
            meta: (
              <>
                {m.BatchSize && <Pill>×{m.BatchSize}</Pill>}
                <Status tone={enabled ? "good" : "neutral"}>{m.State}</Status>
              </>
            ),
            actions: (
              <>
                <ActionForm action={setMapping.bind(null, name, m.UUID!, !enabled)} submit={enabled ? "Disable trigger" : "Enable trigger"} icon={enabled ? <Pause size={15} /> : <Play size={15} />} />
                <ActionForm action={deleteMapping.bind(null, name, m.UUID!)} submit="Delete trigger" icon={<Trash2 size={15} />} tone="danger" confirm="Delete this trigger?" />
              </>
            ),
          };
        })}
      />
    );
  } else {
    body = (
      <Section>
        <ActionForm action={invoke.bind(null, name)} submit="Invoke" testId="invoke">
          <textarea name="payload" rows={8} aria-label="Event" className="code-editor" spellCheck={false} defaultValue={'{\n  "hello": "world"\n}'} />
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
          <a
            className="icon-button plain"
            href={`${zoneHref("observability", "/logs/group")}?name=${encodeURIComponent(logGroup)}`}
            aria-label="View logs"
            title="Logs"
          >
            <AwsIcon icon="service/AmazonCloudWatch" size={18} />
          </a>
          {!url && <ActionForm action={createUrl.bind(null, name)} submit="Create function URL" icon={<Globe size={16} />} />}
          <ActionForm action={publishVersion.bind(null, name)} submit="Publish version" icon={<GitCommitVertical size={16} />} />
          <ActionForm action={deleteFunction.bind(null, name)} submit="Delete function" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name}?`} testId="delete-function" />
        </>
      }
    >
      <Specs
        items={[
          { label: "Runtime", icon: <AwsIcon icon={logo ?? ICONS.fn} size={16} />, value: c.Runtime ?? c.PackageType },
          c.State && c.State !== "Active" && { label: "State", icon: <CircleAlert size={15} />, value: <Status tone={c.State === "Failed" ? "bad" : "warn"}>{c.StateReason ?? c.State}</Status> },
          { label: "Memory", icon: <MemoryStick size={15} />, value: `${c.MemorySize} MB` },
          { label: "Timeout", icon: <Timer size={15} />, value: `${c.Timeout} s` },
          { label: "Architecture", icon: <Cpu size={15} />, value: c.Architectures?.[0] ?? "x86_64" },
          url && { label: "Function URL", icon: <Globe size={15} />, value: <a href={url}>{new URL(url).host}</a> },
          { label: "Execution role", icon: <AwsIcon icon="resource/AWSIdentityAccessManagementRole" size={16} />, value: <a href={zoneHref("security", `/iam/roles/${encodeURIComponent(roleName ?? "")}`)}>{roleName}</a> },
          { label: "Last modified", icon: <Clock size={15} />, value: ago(c.LastModified) },
        ]}
      />
      <Segments
        items={[
          { label: "Code", href: base, active: tab === "code" },
          { label: "Test", href: `${base}?tab=test`, active: tab === "test" },
          { label: "Configuration", href: `${base}?tab=config`, active: tab === "config" },
          { label: "Triggers", href: `${base}?tab=triggers`, active: tab === "triggers", count: mappings.length || undefined },
        ]}
      />
      {body}
    </Page>
  );
}
