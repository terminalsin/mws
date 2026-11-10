import { ListFoundationModelsCommand, ListInferenceProfilesCommand } from "@aws-sdk/client-bedrock";
import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Section, Segments, Sheet } from "@mws-dashboard/ui";
import { Globe, MessageSquareText, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { bedrock, ICONS, providerIcon } from "../../../lib/clients";
import { createProfile, deleteProfile } from "../actions";

export const metadata: Metadata = { title: "Inference profiles" };

type Props = { searchParams: Promise<{ tab?: string }> };

/** "us.anthropic.claude-…" → its geography. */
const GEO: Record<string, string> = { us: "US", eu: "EU", apac: "APAC", global: "Global", jp: "Japan", au: "Australia", ca: "Canada" };

export default async function Profiles({ searchParams }: Props) {
  const { tab = "system" } = await searchParams;
  const client = await bedrock();
  const data = await load(async () => {
    const [profiles, models] = await Promise.all([
      client.send(new ListInferenceProfilesCommand({ typeEquals: tab === "application" ? "APPLICATION" : "SYSTEM_DEFINED", maxResults: 1000 })).then((r) => r.inferenceProfileSummaries ?? []),
      client.send(new ListFoundationModelsCommand({ byOutputModality: "TEXT" })).then((r) => r.modelSummaries ?? []),
    ]);
    return { profiles, models };
  });
  const create = data.ok && (
    <Sheet title="Create inference profile" label="Create inference profile" testId="create-profile">
      <ActionForm action={createProfile} submit="Create" testId="create-profile">
        <Field label="Name">
          <input name="name" required autoFocus />
        </Field>
        <Field label="Model">
          <select name="source">
            {data.value.models
              .filter((m) => m.inferenceTypesSupported?.includes("ON_DEMAND"))
              .map((m) => (
                <option key={m.modelArn} value={m.modelArn}>
                  {m.providerName} {m.modelName}
                </option>
              ))}
          </select>
        </Field>
        <Field label="Cost center">
          <input name="costCenter" />
        </Field>
      </ActionForm>
    </Sheet>
  );
  const modelOf = (arn: string | undefined) => data.ok && data.value.models.find((m) => arn?.endsWith(`/${m.modelId}`));
  return (
    <Page title="Inference profiles" actions={create || undefined}>
      <Segments
        items={[
          { label: "Cross-Region", href: "/bedrock/profiles", active: tab !== "application" },
          { label: "Application", href: "/bedrock/profiles?tab=application", active: tab === "application" },
        ]}
      />
      {data.ok ? (
        <Section plain>
          <List
            label="Inference profiles"
            empty={<Empty icon={ICONS.bedrock} action={tab === "application" ? create : undefined} />}
            rows={data.value.profiles.map((p) => {
              const model = modelOf(p.models?.[0]?.modelArn);
              const geo = GEO[p.inferenceProfileId?.split(".")[0] ?? ""];
              const regions = new Set((p.models ?? []).map((m) => m.modelArn?.split(":")[3]).filter(Boolean));
              return {
                key: p.inferenceProfileArn!,
                icon: <AwsIcon icon={providerIcon(model ? model.providerName : p.inferenceProfileId) ?? ICONS.model} size={22} />,
                title: p.inferenceProfileName,
                subtitle: <code>{p.type === "APPLICATION" ? p.inferenceProfileArn?.split("/").pop() : p.inferenceProfileId}</code>,
                meta: (
                  <>
                    {geo && <Pill icon={<Globe size={11} />}>{geo}</Pill>}
                    {regions.size > 1 && <span title={[...regions].join(", ")}>{regions.size} Regions</span>}
                  </>
                ),
                actions: (
                  <>
                    <Link className="icon-button plain" href={`/bedrock/playground?model=${encodeURIComponent(model ? model.modelId! : "")}`} aria-label={`Open ${p.inferenceProfileName} in playground`} title="Playground">
                      <MessageSquareText size={15} />
                    </Link>
                    {p.type === "APPLICATION" && (
                      <ActionForm action={deleteProfile.bind(null, p.inferenceProfileArn!)} submit={`Delete ${p.inferenceProfileName}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${p.inferenceProfileName}?`} />
                    )}
                  </>
                ),
              };
            })}
          />
        </Section>
      ) : (
        <ErrorNotice error={data.error} />
      )}
    </Page>
  );
}
