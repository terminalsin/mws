import { GetInferenceProfileCommand } from "@aws-sdk/client-bedrock";
import { ago, load, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, ErrorNotice, Facts, List, Page, Pill, Section, Specs } from "@mws-dashboard/ui";
import { Clock, Globe, MessageSquareText, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { bedrock, ICONS } from "../../../lib/clients";
import { TagsSection } from "../../../lib/tags";
import { deleteProfile } from "../actions";

export const metadata: Metadata = { title: "Inference profile" };

type Props = { searchParams: Promise<{ id?: string }> };

export default async function Profile({ searchParams }: Props) {
  const id = (await searchParams).id ?? "";
  const data = await load(async () => (await bedrock()).send(new GetInferenceProfileCommand({ inferenceProfileIdentifier: id })));
  const back = { href: data.ok && data.value.type === "APPLICATION" ? "/bedrock/profiles?tab=application" : "/bedrock/profiles", label: "Inference profiles" };
  if (!data.ok) {
    return (
      <Page title={id.split("/").pop()} icon={ICONS.bedrock} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const p = data.value;
  const app = p.type === "APPLICATION";
  const target = app ? p.inferenceProfileArn! : p.inferenceProfileId!;
  return (
    <Page
      title={p.inferenceProfileName}
      icon={ICONS.bedrock}
      back={back}
      subtitle={p.inferenceProfileArn}
      actions={
        <>
          <Link className="icon-button plain" href={`/bedrock/playground?model=${encodeURIComponent(target)}`} aria-label="Open in playground" title="Playground">
            <MessageSquareText size={16} />
          </Link>
          {app && <ActionForm action={deleteProfile.bind(null, p.inferenceProfileArn!, "/bedrock/profiles?tab=application")} submit="Delete profile" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${p.inferenceProfileName}?`} />}
        </>
      }
    >
      <Specs
        items={[
          { label: "Type", icon: <Globe size={15} />, value: app ? "Application" : "Cross-Region" },
          { label: "Regions", icon: <Globe size={15} />, value: new Set((p.models ?? []).map((m) => m.modelArn?.split(":")[3])).size },
          p.updatedAt && { label: "Updated", icon: <Clock size={15} />, value: ago(p.updatedAt) },
        ]}
      />
      {(p.description || !app) && (
        <Section>
          <Facts items={[p.description && ["Description", p.description], !app && ["Inference profile ID", <code key="i">{p.inferenceProfileId}</code>], p.createdAt && ["Created", when(p.createdAt)]]} />
        </Section>
      )}
      <Section title="Models" count={p.models?.length ?? 0} plain>
        <List
          label="Models"
          rows={(p.models ?? []).map((m) => ({
            key: m.modelArn!,
            icon: <AwsIcon icon={ICONS.model} size={20} />,
            title: <code>{m.modelArn?.split("/").pop()}</code>,
            meta: <Pill icon={<Globe size={11} />}>{m.modelArn?.split(":")[3] || "any"}</Pill>,
          }))}
        />
      </Section>
      {app && <TagsSection arn={p.inferenceProfileArn!} path="/bedrock/profile" />}
    </Page>
  );
}
