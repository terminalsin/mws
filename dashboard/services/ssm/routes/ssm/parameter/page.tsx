import { DescribeParametersCommand, GetParameterCommand, GetParameterHistoryCommand, ListTagsForResourceCommand } from "@aws-sdk/client-ssm";
import { ago, all, load, when } from "@mws-dashboard/aws";
import { ActionForm, CodeBlock, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Segments, Sheet, Tags } from "@mws-dashboard/ui";
import { LabelParameterVersion } from "@mws-dashboard/ui/model/ssm";
import { Eye, EyeOff, Lock, Pencil, Tag, Trash2, X } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, ssm } from "../../../lib/clients";
import { ParameterForm } from "../../../lib/parameter-form";
import { folderOf, kmsAliases, policyJson } from "../../../lib/ssm";
import { deleteAndLeave, labelVersion, saveTags, unlabel } from "../actions";

export const metadata: Metadata = { title: "Parameter" };

type Props = { searchParams: Promise<{ name?: string; reveal?: string; tab?: string }> };

const LABELS = { ...LabelParameterVersion.Labels, hint: "Comma-separated, like prod, stable" };

export default async function Parameter({ searchParams }: Props) {
  const { name = "", reveal, tab = "overview" } = await searchParams;
  const folder = folderOf(name);
  const back = { href: folder && folder !== "/" ? `/ssm?path=${encodeURIComponent(folder)}` : "/ssm", label: "Parameter Store" };
  const data = await load(async () => {
    const client = await ssm();
    const [meta, current] = await Promise.all([
      client.send(new DescribeParametersCommand({ ParameterFilters: [{ Key: "Name", Option: "Equals", Values: [name] }] })).then((r) => r.Parameters?.[0]),
      load(() => client.send(new GetParameterCommand({ Name: name, WithDecryption: !!reveal })).then((r) => r.Parameter!)),
    ]);
    if (!meta) throw new Error(`ParameterNotFound: ${name}`);
    const [history, tags, keys] = await Promise.all([
      load(() => all((NextToken) => client.send(new GetParameterHistoryCommand({ Name: name, WithDecryption: !!reveal, NextToken, MaxResults: 50 })), (r) => r.Parameters, (r) => r.NextToken)),
      client.send(new ListTagsForResourceCommand({ ResourceType: "Parameter", ResourceId: name })).then((r) => r.TagList ?? [], () => []),
      kmsAliases(),
    ]);
    return { meta, current, history, tags, keys };
  });
  if (!data.ok) {
    return (
      <Page title={name || "Parameter"} icon={ICONS.parameter} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { meta, current, history, tags, keys } = data.value;
  const secure = meta.Type === "SecureString";
  const self = `/ssm/parameter?name=${encodeURIComponent(name)}`;
  const withReveal = (extra: string) => `${self}${extra}${reveal ? "&reveal=1" : ""}`;
  const value = current.ok ? current.value.Value : undefined;
  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "history", label: "History", count: history.ok ? history.value.length : undefined },
    { id: "tags", label: "Tags", count: tags.length || undefined },
  ];
  const active = tabs.some((t) => t.id === tab) ? tab : "overview";
  const keyHref = meta.KeyId ? `/kms/key?id=${encodeURIComponent(meta.KeyId)}` : undefined;

  let body: React.ReactNode = null;
  if (active === "overview") {
    body = (
      <>
        <Section
          title="Value"
          actions={
            secure && (
              <Link className="icon-button plain" href={reveal ? self : `${self}&reveal=1`} aria-label={reveal ? "Hide value" : "Reveal value"} title={reveal ? "Hide" : "Reveal"}>
                {reveal ? <EyeOff size={16} /> : <Eye size={16} />}
              </Link>
            )
          }
        >
          {!current.ok ? <ErrorNotice error={current.error} /> : secure && !reveal ? <span className="muted" aria-label="Hidden">••••••••••••</span> : <CodeBlock value={value} label="Parameter value" />}
        </Section>
        {meta.Policies && meta.Policies.length > 0 && (
          <Section title="Policies" count={meta.Policies.length} plain>
            <List
              label="Policies"
              rows={meta.Policies.map((p, i) => ({
                key: String(i),
                title: p.PolicyType,
                subtitle: <code className="clip">{p.PolicyText}</code>,
                meta: <Pill tone={p.PolicyStatus === "Finished" ? "neutral" : p.PolicyStatus === "Failed" ? "bad" : "info"}>{p.PolicyStatus?.toLowerCase()}</Pill>,
              }))}
            />
          </Section>
        )}
      </>
    );
  } else if (active === "history") {
    body = history.ok ? (
      <Section title="History" count={history.value.length} plain>
        <List
          label="Versions"
          rows={[...history.value].reverse().map((h) => ({
            key: String(h.Version),
            icon: <span className="pill">v{h.Version}</span>,
            title: secure && !reveal ? "••••••" : <code className="clip">{h.Value}</code>,
            subtitle: [when(h.LastModifiedDate), h.LastModifiedUser?.split("/").pop(), h.Tier !== meta.Tier ? h.Tier : null, h.Type !== meta.Type ? h.Type : null, h.Description && h.Description !== meta.Description ? h.Description : null]
              .filter(Boolean)
              .join(" · "),
            meta: (
              <>
                {h.Version === meta.Version && <Pill tone="good">current</Pill>}
                {h.Labels?.map((l) => (
                  <span key={l} className="tag">
                    <span>{l}</span>
                    <ActionForm action={unlabel.bind(null, name, h.Version!, l)} submit={`Remove label ${l}`} icon={<X size={12} />} tone="plain" />
                  </span>
                ))}
              </>
            ),
            actions: (
              <Sheet title={`Label version ${h.Version}`} label={`Label version ${h.Version}`} icon={<Tag size={15} />} testId={`label-${h.Version}`}>
                <ActionForm action={labelVersion.bind(null, name, h.Version!)} submit="Add labels" testId={`label-${h.Version}`}>
                  <Field label="Labels" rule={LABELS}>
                    <input name="labels" required placeholder="prod" />
                  </Field>
                </ActionForm>
              </Sheet>
            ),
          }))}
        />
      </Section>
    ) : (
      <ErrorNotice error={history.error} />
    );
  } else {
    body = (
      <Section
        title="Tags"
        actions={
          <Sheet title="Tags" label="Edit tags" icon={<Tag size={16} />} testId="edit-tags">
            <ActionForm action={saveTags.bind(null, "Parameter", name, tags.map((t) => t.Key!), "/ssm/parameter")} submit="Save" testId="edit-tags">
              <Field label="Tags" format="tags">
                <textarea name="tags" rows={6} placeholder="team=payments" defaultValue={tags.map((t) => `${t.Key}=${t.Value ?? ""}`).join("\n")} />
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        {tags.length ? <Tags tags={tags} /> : <Empty>No tags</Empty>}
      </Section>
    );
  }

  return (
    <Page
      title={name}
      icon={ICONS.parameter}
      back={back}
      subtitle={meta.ARN}
      actions={
        <>
          <Sheet title={name} label="Edit parameter" icon={<Pencil size={16} />} testId="edit-parameter">
            <ParameterForm
              keys={keys}
              testId="edit-parameter"
              defaults={{
                name,
                value: secure && !reveal ? "" : value,
                keepValue: secure && !reveal,
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
          <ActionForm action={deleteAndLeave.bind(null, name)} submit="Delete parameter" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name}?`} testId="delete-parameter" />
        </>
      }
    >
      <Facts
        items={[
          ["Type", secure ? <span key="t"><Lock size={13} aria-hidden /> SecureString</span> : meta.Type],
          ["Version", meta.Version],
          ["Tier", meta.Tier],
          meta.DataType && meta.DataType !== "text" && ["Data type", meta.DataType],
          secure && ["KMS key", keyHref ? <Link key="k" href={keyHref}>{meta.KeyId}</Link> : "alias/aws/ssm"],
          meta.Description && ["Description", meta.Description],
          meta.AllowedPattern && ["Allowed pattern", <code key="p">{meta.AllowedPattern}</code>],
          ["Modified", `${ago(meta.LastModifiedDate)}${meta.LastModifiedUser ? ` by ${meta.LastModifiedUser.split(/[:/]/).pop()}` : ""}`],
        ]}
      />
      <Segments label="Parameter" items={tabs.map((t) => ({ label: t.label, href: t.id === "overview" ? withReveal("") : withReveal(`&tab=${t.id}`), active: t.id === active, count: t.count }))} />
      {body}
    </Page>
  );
}
