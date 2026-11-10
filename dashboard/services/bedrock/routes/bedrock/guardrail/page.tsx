import { GetGuardrailCommand, ListGuardrailsCommand } from "@aws-sdk/client-bedrock";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, ErrorNotice, Field, List, Page, Pill, Section, Specs } from "@mws-dashboard/ui";
import { Ban, Clock, EyeOff, GitCommitVertical, MessageSquareOff, ShieldAlert, Trash2, Upload } from "lucide-react";
import type { Metadata } from "next";

import { bedrock, ICONS } from "../../../lib/clients";
import { deleteGuardrail, publishGuardrail, testGuardrail } from "../actions";

export const metadata: Metadata = { title: "Guardrail" };

type Props = { searchParams: Promise<{ id?: string }> };

const STRENGTH_TONE = { NONE: "neutral", LOW: "info", MEDIUM: "warn", HIGH: "bad" } as Record<string, "neutral" | "info" | "warn" | "bad">;

export default async function Guardrail({ searchParams }: Props) {
  const id = (await searchParams).id ?? "";
  const back = { href: "/bedrock/guardrails", label: "Guardrails" };
  const data = await load(async () => {
    const client = await bedrock();
    const [g, versions] = await Promise.all([
      client.send(new GetGuardrailCommand({ guardrailIdentifier: id })),
      client.send(new ListGuardrailsCommand({ guardrailIdentifier: id })).then((r) => (r.guardrails ?? []).filter((v) => v.version !== "DRAFT")),
    ]);
    return { g, versions };
  });
  if (!data.ok) {
    return (
      <Page title={id} icon={ICONS.guardrail} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { g, versions } = data.value;
  const filters = g.contentPolicy?.filters ?? [];
  const topics = g.topicPolicy?.topics ?? [];
  const words = g.wordPolicy?.words ?? [];
  const managed = g.wordPolicy?.managedWordLists ?? [];
  const pii = g.sensitiveInformationPolicy?.piiEntities ?? [];
  const regexes = g.sensitiveInformationPolicy?.regexes ?? [];
  return (
    <Page
      title={g.name!}
      icon={ICONS.guardrail}
      back={back}
      subtitle={g.guardrailArn}
      actions={
        <>
          <ActionForm action={publishGuardrail.bind(null, id)} submit="Create version" icon={<Upload size={16} />} testId="publish-guardrail" />
          <ActionForm action={deleteGuardrail.bind(null, id)} submit="Delete guardrail" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${g.name}?`} />
        </>
      }
    >
      <Specs
        items={[
          { label: "Content filters", icon: <ShieldAlert size={15} />, value: filters.length || "off" },
          topics.length > 0 && { label: "Denied topics", icon: <MessageSquareOff size={15} />, value: topics.length },
          words.length + managed.length > 0 && { label: "Word filters", icon: <Ban size={15} />, value: words.length + managed.length },
          pii.length + regexes.length > 0 && { label: "Sensitive information", icon: <EyeOff size={15} />, value: pii.length + regexes.length },
          versions.length > 0 && { label: "Versions", icon: <GitCommitVertical size={15} />, value: versions.length },
          { label: "Updated", icon: <Clock size={15} />, value: ago(g.updatedAt) },
        ]}
      />
      <Section title="Test">
        <ActionForm action={testGuardrail.bind(null, id)} submit="Test" testId="test-guardrail">
          <div className="form-row">
            <Field label="Source">
              <select name="source" defaultValue="INPUT">
                <option value="INPUT">Prompt</option>
                <option value="OUTPUT">Response</option>
              </select>
            </Field>
            {versions.length > 0 && (
              <Field label="Version">
                <select name="version" defaultValue="DRAFT">
                  <option value="DRAFT">Working draft</option>
                  {versions.map((v) => (
                    <option key={v.version} value={v.version}>
                      {v.version}
                    </option>
                  ))}
                </select>
              </Field>
            )}
          </div>
          <Field label="Text">
            <textarea name="text" rows={3} required />
          </Field>
        </ActionForm>
      </Section>
      {filters.length > 0 && (
        <Section title="Content filters" count={filters.length} plain>
          <List
            label="Content filters"
            rows={filters.map((f) => ({
              key: f.type!,
              icon: <ShieldAlert size={18} />,
              title: f.type!.toLowerCase().replace(/_/g, " "),
              meta: (
                <>
                  <Pill tone={STRENGTH_TONE[f.inputStrength ?? "NONE"]} title="Prompts">
                    ↓ {f.inputStrength?.toLowerCase()}
                  </Pill>
                  <Pill tone={STRENGTH_TONE[f.outputStrength ?? "NONE"]} title="Responses">
                    ↑ {f.outputStrength?.toLowerCase()}
                  </Pill>
                </>
              ),
            }))}
          />
        </Section>
      )}
      {topics.length > 0 && (
        <Section title="Denied topics" count={topics.length} plain>
          <List label="Denied topics" rows={topics.map((t) => ({ key: t.name!, icon: <MessageSquareOff size={18} />, title: t.name, subtitle: t.definition }))} />
        </Section>
      )}
      {words.length + managed.length > 0 && (
        <Section title="Word filters">
          <span className="chips">
            {managed.map((m) => (
              <Pill key={m.type} tone="warn">
                {m.type?.toLowerCase()}
              </Pill>
            ))}
            {words.map((w) => (
              <span key={w.text} className="tag">
                {w.text}
              </span>
            ))}
          </span>
        </Section>
      )}
      {pii.length + regexes.length > 0 && (
        <Section title="Sensitive information" count={pii.length + regexes.length} plain>
          <List
            label="Sensitive information"
            rows={[
              ...pii.map((p) => ({ key: p.type!, icon: <EyeOff size={18} />, title: p.type!.toLowerCase().replace(/_/g, " "), meta: <Pill tone={p.action === "BLOCK" ? "bad" : "info"}>{p.action?.toLowerCase()}</Pill> })),
              ...regexes.map((r) => ({ key: r.name!, icon: <EyeOff size={18} />, title: r.name, subtitle: <code>{r.pattern}</code>, meta: <Pill tone={r.action === "BLOCK" ? "bad" : "info"}>{r.action?.toLowerCase()}</Pill> })),
            ]}
          />
        </Section>
      )}
      <Section title="Messages">
        <List
          label="Blocked messages"
          rows={[
            { key: "in", icon: <AwsIcon icon={ICONS.bedrock} size={18} />, title: g.blockedInputMessaging, meta: <Pill>prompt</Pill> },
            { key: "out", icon: <AwsIcon icon={ICONS.bedrock} size={18} />, title: g.blockedOutputsMessaging, meta: <Pill>response</Pill> },
          ]}
        />
      </Section>
    </Page>
  );
}
