import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, FileIcon, List, Page, Pill, Sheet, type Row } from "@mws-dashboard/ui";
import { Eye, EyeOff, FolderX, Lock, Pencil, ShieldAlert, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS } from "../../lib/clients";
import { SsmNav } from "../../lib/nav";
import { ParameterForm } from "../../lib/parameter-form";
import { kmsAliases, listParameters, policyJson } from "../../lib/ssm";
import { deleteMany, deleteParameter } from "./actions";

export const metadata: Metadata = { title: "Parameter Store" };

type Props = { searchParams: Promise<{ path?: string; reveal?: string }> };

export default async function Parameters({ searchParams }: Props) {
  const { path = "", reveal } = await searchParams;
  const [params, keys] = await Promise.all([load(() => listParameters(path, !!reveal)), kmsAliases()]);
  const href = (extra: Record<string, string>) => {
    const q = new URLSearchParams({ ...(path ? { path } : {}), ...extra });
    return `/ssm${q.size ? `?${q}` : ""}`;
  };
  const create = (
    <Sheet title="New parameter" label="Create parameter" testId="put-parameter">
      <ParameterForm
        keys={keys}
        testId="put-parameter"
        defaults={{ name: path && path.endsWith("/") ? path : undefined, path: path.endsWith("/") ? path : undefined, taken: params.ok ? params.value.map((p) => p.meta.Name!) : [] }}
      />
    </Sheet>
  );
  const crumbs = path
    .split("/")
    .filter(Boolean)
    .map((part, i, all) => ({ label: part, path: `/${all.slice(0, i + 1).join("/")}/` }));
  if (!params.ok) {
    return (
      <Page title="Parameter Store" icon={ICONS.ssm} actions={create}>
        <SsmNav active="parameters" />
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
    ...(flatten ? params.value : here).map(({ meta, value, error }) => {
      const secure = meta.Type === "SecureString";
      return {
        key: meta.Name!,
        icon: secure ? <Lock size={18} aria-label="SecureString" /> : <AwsIcon icon={ICONS.parameter} size={22} />,
        title: flatten ? meta.Name : meta.Name!.slice(path.length),
        href: `/ssm/parameter?name=${encodeURIComponent(meta.Name!)}`,
        subtitle: error ? (
          <span className="tone-bad" title={error}>
            <ShieldAlert size={13} aria-hidden /> {error}
          </span>
        ) : secure && !reveal ? (
          "••••••"
        ) : (
          <code className="clip">{value}</code>
        ),
        meta: (
          <>
            {(meta.Version ?? 1) > 1 && <Pill>v{meta.Version}</Pill>}
            {meta.Tier === "Advanced" && <Pill tone="info">advanced</Pill>}
            {meta.Policies?.length ? <Pill>{meta.Policies.length} policies</Pill> : null}
            <span>{ago(meta.LastModifiedDate)}</span>
          </>
        ),
        actions: (
          <>
            <Sheet title={meta.Name!} label={`Edit ${meta.Name}`} icon={<Pencil size={15} />}>
              <ParameterForm
                keys={keys}
                defaults={{
                  name: meta.Name,
                  value: secure && !reveal ? "" : value,
                  keepValue: secure && (!reveal || value === undefined),
                  type: meta.Type,
                  tier: meta.Tier,
                  keyId: meta.KeyId,
                  description: meta.Description,
                  allowedPattern: meta.AllowedPattern,
                  dataType: meta.DataType,
                  policies: policyJson(meta.Policies),
                  overwrite: true,
                }}
              />
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
          {path && params.value.length > 0 && (
            <ActionForm
              action={deleteMany.bind(null, params.value.map((p) => p.meta.Name!))}
              submit={`Delete all ${params.value.length} parameters under ${path}`}
              icon={<FolderX size={16} />}
              tone="danger"
              confirm={`Delete all ${params.value.length} parameters under ${path}?`}
            />
          )}
          {create}
        </>
      }
    >
      <SsmNav active="parameters" />
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

