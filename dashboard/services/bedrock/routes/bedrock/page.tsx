import { ListFoundationModelsCommand, type FoundationModelSummary } from "@aws-sdk/client-bedrock";
import { load } from "@mws-dashboard/aws";
import { AwsIcon, Curated, Empty, ErrorNotice, Page, Pill, Segments } from "@mws-dashboard/ui";
import { AudioLines, Binary, FileText, FlaskConical, Gauge, Image as ImageIcon, Layers, MessageSquareText, Radio, Video } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { bedrock, ICONS, providerIcon } from "../../lib/clients";

export const metadata: Metadata = { title: "Model catalog" };

type Props = { searchParams: Promise<{ output?: string }> };

const MODALITY = {
  TEXT: { label: "Text", Icon: MessageSquareText },
  IMAGE: { label: "Image", Icon: ImageIcon },
  EMBEDDING: { label: "Embeddings", Icon: Binary },
  VIDEO: { label: "Video", Icon: Video },
  SPEECH: { label: "Speech", Icon: AudioLines },
  DOCUMENT: { label: "Document", Icon: FileText },
} as Record<string, { label: string; Icon: typeof FileText }>;

function Modalities({ list }: { list: string[] | undefined }) {
  return (
    <span className="chips" aria-label="Input">
      {(list ?? []).map((m) => {
        const x = MODALITY[m];
        return x ? <x.Icon key={m} size={14} aria-label={x.label}><title>{x.label}</title></x.Icon> : null;
      })}
    </span>
  );
}

export default async function Models({ searchParams }: Props) {
  const { output = "TEXT" } = await searchParams;
  const models = await load(async () => ((await (await bedrock()).send(new ListFoundationModelsCommand({}))).modelSummaries ?? []));
  if (!models.ok) {
    return (
      <Page title="Model catalog">
        <ErrorNotice error={models.error} />
      </Page>
    );
  }
  const byOutput = (o: string) => models.value.filter((m) => m.outputModalities?.includes(o as never));
  const shown = byOutput(output);
  const providers = [...new Set(shown.map((m) => m.providerName ?? "Other"))].sort();
  const links = (
    <>
      <Link className="icon-button plain" href="/bedrock/custom-models" aria-label="Custom models" title="Custom models">
        <FlaskConical size={16} />
      </Link>
      <Link className="icon-button plain" href="/bedrock/provisioned" aria-label="Provisioned Throughput" title="Provisioned Throughput">
        <Gauge size={16} />
      </Link>
      <Link className="icon-button plain" href="/bedrock/batch" aria-label="Batch inference" title="Batch inference">
        <Layers size={16} />
      </Link>
    </>
  );
  return (
    <Page title="Model catalog" actions={links}>
      <Segments
        label="Output"
        items={["TEXT", "IMAGE", "EMBEDDING", "VIDEO"]
          .filter((o) => byOutput(o).length > 0)
          .map((o) => ({ label: MODALITY[o].label, href: `/bedrock?output=${o}`, active: o === output, count: byOutput(o).length }))}
      />
      <Curated<FoundationModelSummary>
        label="Models"
        empty={<Empty icon={ICONS.bedrock} />}
        sections={providers.map((p) => ({ id: p, title: p, items: shown.filter((m) => (m.providerName ?? "Other") === p) }))}
        row={(m) => {
          const legacy = m.modelLifecycle?.status === "LEGACY";
          const playable = m.outputModalities?.includes("TEXT") && !m.outputModalities.includes("EMBEDDING");
          return {
            key: m.modelId!,
            icon: <AwsIcon icon={providerIcon(m.providerName) ?? ICONS.model} size={22} />,
            title: m.modelName,
            subtitle: <code>{m.modelId}</code>,
            meta: (
              <>
                <Modalities list={m.inputModalities} />
                {m.responseStreamingSupported && <Radio size={13} aria-label="Streaming"><title>Streaming</title></Radio>}
                {m.inferenceTypesSupported?.includes("PROVISIONED") && (
                  <Link href={`/bedrock/provisioned?model=${encodeURIComponent(m.modelArn!)}`} title="Purchase Provisioned Throughput">
                    <Pill>PT</Pill>
                  </Link>
                )}
                {legacy && <Pill tone="warn">legacy</Pill>}
              </>
            ),
            actions: playable ? (
              <Link className="icon-button plain" href={`/bedrock/playground?model=${encodeURIComponent(m.modelId!)}`} aria-label={`Open ${m.modelName} in playground`} title="Playground">
                <MessageSquareText size={15} />
              </Link>
            ) : undefined,
          };
        }}
      />
    </Page>
  );
}
