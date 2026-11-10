import { GetLayerVersionCommand, GetLayerVersionPolicyCommand, ListLayerVersionsCommand } from "@aws-sdk/client-lambda";
import { ago, all, bytes, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Segments } from "@mws-dashboard/ui";
import { Layers, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { lambda } from "../../../../lib/clients";
import { listFunctions } from "../../../../lib/lambda";
import { PublishLayer } from "../../../../lib/layers";
import { LAYER_PRINCIPAL, LAYER_STATEMENT, ORG_ID } from "../../../../lib/rules";
import { addLayerPermission, deleteLayerVersion, removeLayerPermission } from "../../actions";

type Props = { params: Promise<{ layer: string }>; searchParams: Promise<{ version?: string; published?: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  return { title: decodeURIComponent((await params).layer) };
}

interface LayerStatement {
  Sid?: string;
  Principal?: string | { AWS?: string };
  Condition?: { StringEquals?: Record<string, string> };
}

export default async function Layer({ params, searchParams }: Props) {
  const layer = decodeURIComponent((await params).layer);
  const sp = await searchParams;
  const back = { href: "/lambda/layers", label: "Layers" };
  const data = await load(async () => {
    const client = await lambda();
    const versions = await all((Marker) => client.send(new ListLayerVersionsCommand({ LayerName: layer, Marker })), (r) => r.LayerVersions, (r) => r.NextMarker);
    return { versions };
  });
  if (!data.ok) {
    return (
      <Page title={layer} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { versions } = data.value;
  if (!versions.length) {
    return (
      <Page title={layer} back={back}>
        <Empty icon="service/AWSLambda" action={<PublishLayer name={layer} />} />
      </Page>
    );
  }
  const wanted = Number(sp.version ?? sp.published);
  const current = versions.find((v) => v.Version === wanted) ?? versions[0];
  const client = await lambda();
  const [detail, policy, users] = await Promise.all([
    load(() => client.send(new GetLayerVersionCommand({ LayerName: layer, VersionNumber: current.Version! }))),
    client
      .send(new GetLayerVersionPolicyCommand({ LayerName: layer, VersionNumber: current.Version! }))
      .then((r) => (JSON.parse(r.Policy ?? "{}").Statement ?? []) as LayerStatement[])
      .catch(() => [] as LayerStatement[]),
    listFunctions().catch(() => []),
  ]);
  const using = users.filter((f) => f.Layers?.some((l) => l.Arn === current.LayerVersionArn));
  const base = `/lambda/layers/${encodeURIComponent(layer)}`;
  const d = detail.ok ? detail.value : undefined;
  return (
    <Page
      title={layer}
      back={back}
      subtitle={current.LayerVersionArn}
      actions={
        <>
          <PublishLayer name={layer} />
          <ActionForm
            action={deleteLayerVersion.bind(null, layer, current.Version!)}
            submit={`Delete version ${current.Version}`}
            icon={<Trash2 size={16} aria-hidden />}
            tone="danger"
            confirm={`Delete version ${current.Version} of ${layer}? Functions using it keep their copy.`}
          />
        </>
      }
    >
      {versions.length > 1 && (
        <Segments
          label="Versions"
          items={versions.map((v) => ({ label: `v${v.Version}`, href: `${base}?version=${v.Version}`, active: v.Version === current.Version }))}
        />
      )}
      <Section>
        <Facts
          items={[
            current.Description && ["Description", current.Description],
            ["Version", current.Version],
            d?.Content?.CodeSize !== undefined && ["Size", bytes(d.Content.CodeSize)],
            d?.Content?.CodeSha256 && ["SHA-256", <code key="s">{d.Content.CodeSha256}</code>],
            current.CompatibleRuntimes?.length && ["Runtimes", current.CompatibleRuntimes.map((r) => <Pill key={r}>{r}</Pill>)],
            current.CompatibleArchitectures?.length && ["Architectures", current.CompatibleArchitectures.join(", ")],
            current.LicenseInfo && ["License", current.LicenseInfo],
            ["Created", ago(current.CreatedDate)],
          ]}
        />
      </Section>
      <Section title="Functions using this version" count={using.length} plain>
        <List
          label="Functions"
          empty={<Empty icon="resource/AWSLambdaLambdaFunction" />}
          rows={using.map((f) => ({
            key: f.FunctionArn!,
            icon: <AwsIcon icon="resource/AWSLambdaLambdaFunction" size={22} />,
            title: <Link href={`/lambda/${encodeURIComponent(f.FunctionName!)}`}>{f.FunctionName}</Link>,
            meta: f.Runtime,
          }))}
        />
      </Section>
      <Section
        title="Permissions"
        count={policy.length}
        plain
        actions={
          <ActionForm action={addLayerPermission.bind(null, layer, current.Version!)} submit="Add permission" inline testId="add-layer-permission">
            <Field label="Statement ID" rule={LAYER_STATEMENT} taken={policy.map((s) => s.Sid ?? "")} unique>
              <input name="sid" required spellCheck={false} />
            </Field>
            <Field label="Principal" rule={LAYER_PRINCIPAL}>
              <input name="principal" required placeholder="123456789012 or *" spellCheck={false} />
            </Field>
            <Field label="Organization ID" rule={{ ...ORG_ID, required: false }}>
              <input name="org" placeholder="o-…" spellCheck={false} />
            </Field>
          </ActionForm>
        }
      >
        <List
          label="Layer permissions"
          rows={policy.map((s) => ({
            key: s.Sid ?? "",
            icon: <Layers size={18} aria-hidden />,
            title: s.Sid,
            subtitle: [typeof s.Principal === "string" ? s.Principal : s.Principal?.AWS, s.Condition?.StringEquals?.["aws:PrincipalOrgID"]].filter(Boolean).join(" · "),
            actions: s.Sid ? (
              <ActionForm action={removeLayerPermission.bind(null, layer, current.Version!, s.Sid)} submit={`Remove ${s.Sid}`} icon={<Trash2 size={15} aria-hidden />} tone="danger" />
            ) : undefined,
          }))}
        />
      </Section>
    </Page>
  );
}
