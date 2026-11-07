import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, FileIcon, List, Page, Pill, Sheet, type Row } from "@mws-dashboard/ui";
import { Eye, EyeOff, Lock, Pencil, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS } from "../../lib/clients";
import { listParameters } from "../../lib/ssm";
import { deleteParameter, putParameter } from "./actions";

export const metadata: Metadata = { title: "Parameter Store" };

type Props = { searchParams: Promise<{ path?: string; reveal?: string }> };

function form(defaults: { name?: string; value?: string; type?: string; overwrite?: boolean }, testId?: string) {
  return (
    <ActionForm action={putParameter} submit="Save" testId={testId}>
      <Field label="Name">
        <input name="name" required defaultValue={defaults.name} readOnly={defaults.overwrite} placeholder="/app/prod/db-host" />
      </Field>
      <textarea name="value" rows={4} aria-label="Value" required defaultValue={defaults.value} />
      <Field label="Type">
        <select name="type" defaultValue={defaults.type ?? "String"}>
          <option>String</option>
          <option>StringList</option>
          <option>SecureString</option>
        </select>
      </Field>
      {defaults.overwrite && <input type="hidden" name="overwrite" value="on" />}
    </ActionForm>
  );
}

export default async function Parameters({ searchParams }: Props) {
  const { path = "", reveal } = await searchParams;
  const params = await load(() => listParameters(path, !!reveal));
  const href = (extra: Record<string, string>) => {
    const q = new URLSearchParams({ ...(path ? { path } : {}), ...extra });
    return `/ssm${q.size ? `?${q}` : ""}`;
  };
  const create = (
    <Sheet title="New parameter" label="Create parameter" testId="put-parameter">
      {form({ name: path && path.endsWith("/") ? path : undefined }, "put-parameter")}
    </Sheet>
  );
  const crumbs = path
    .split("/")
    .filter(Boolean)
    .map((part, i, all) => ({ label: part, path: `/${all.slice(0, i + 1).join("/")}/` }));
  if (!params.ok) {
    return (
      <Page title="Parameter Store" actions={create}>
        <ErrorNotice error={params.error} />
      </Page>
    );
  }
  // One level of the hierarchy at a time: folders for deeper paths, rows for parameters here.
  const folders = new Map<string, number>();
  const here: typeof params.value = [];
  for (const p of params.value) {
    const rest = p.meta.Name!.slice(path.length);
    const slash = rest.indexOf("/", rest.startsWith("/") ? 1 : 0);
    if (path === "" && !p.meta.Name!.startsWith("/")) here.push(p);
    else if (slash > 0) {
      const folder = path + rest.slice(0, slash + 1);
      folders.set(folder, (folders.get(folder) ?? 0) + 1);
    } else here.push(p);
  }
  const flatten = params.value.length <= 8;
  const rows: Row[] = [
    ...(flatten
      ? []
      : [...folders].map(([folder, count]) => ({
          key: `f:${folder}`,
          icon: <FileIcon name={folder} folder size={22} />,
          title: folder.slice(path.length).replace(/^\/|\/$/g, ""),
          href: `/ssm?path=${encodeURIComponent(folder)}`,
          meta: <span>{count}</span>,
        }))),
    ...(flatten ? params.value : here).map(({ meta, value }) => {
      const secure = meta.Type === "SecureString";
      return {
        key: meta.Name!,
        icon: secure ? <Lock size={18} aria-label="SecureString" /> : <AwsIcon icon={ICONS.parameter} size={22} />,
        title: flatten ? meta.Name : meta.Name!.slice(path.length),
        subtitle: secure && !reveal ? "••••••" : <code className="clip">{value}</code>,
        meta: (
          <>
            {(meta.Version ?? 1) > 1 && <Pill>v{meta.Version}</Pill>}
            {meta.Tier === "Advanced" && <Pill tone="info">advanced</Pill>}
            <span>{ago(meta.LastModifiedDate)}</span>
          </>
        ),
        actions: (
          <>
            <Sheet title={meta.Name!} label={`Edit ${meta.Name}`} icon={<Pencil size={15} />}>
              {form({ name: meta.Name, value: secure && !reveal ? "" : value, type: meta.Type, overwrite: true })}
            </Sheet>
            <ActionForm action={deleteParameter.bind(null, meta.Name!)} submit={`Delete ${meta.Name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${meta.Name}?`} />
          </>
        ),
      };
    }),
  ];
  const anySecure = params.value.some((p) => p.meta.Type === "SecureString");
  return (
    <Page
      title="Parameter Store"
      icon={ICONS.ssm}
      actions={
        <>
          {anySecure && (
            <Link className="icon-button plain" href={reveal ? href({}) : href({ reveal: "1" })} aria-label={reveal ? "Hide values" : "Reveal values"} title={reveal ? "Hide" : "Reveal"}>
              {reveal ? <EyeOff size={16} /> : <Eye size={16} />}
            </Link>
          )}
          {create}
        </>
      }
    >
      {crumbs.length > 0 && (
        <nav className="crumbs path" aria-label="Path">
          <Link href="/ssm">/</Link>
          {crumbs.map((c) => (
            <Link key={c.path} href={`/ssm?path=${encodeURIComponent(c.path)}`}>
              {c.label}
            </Link>
          ))}
        </nav>
      )}
      <List label="Parameters" rows={rows} empty={<Empty icon={ICONS.parameter} />} />
    </Page>
  );
}
