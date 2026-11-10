import { ListFoundationModelsCommand, ListGuardrailsCommand, ListInferenceProfilesCommand, ListPromptRoutersCommand, ListProvisionedModelThroughputsCommand } from "@aws-sdk/client-bedrock";
import { load } from "@mws-dashboard/aws";
import { ActionForm, ErrorNotice, Field, Page, Section } from "@mws-dashboard/ui";
import { Converse } from "@mws-dashboard/ui/model/bedrock-runtime";
import { ruleAt } from "@mws-dashboard/ui/validation";
import { MoreFields } from "@mws-dashboard/ui/presets";
import type { Metadata } from "next";

import { bedrock } from "../../../lib/clients";
import { converse } from "../actions";

const TEMPERATURE = ruleAt(Converse, "inferenceConfig.temperature");
const MAX_TOKENS = ruleAt(Converse, "inferenceConfig.maxTokens");

export const metadata: Metadata = { title: "Playground" };

type Props = { searchParams: Promise<{ model?: string }> };

export default async function Playground({ searchParams }: Props) {
  const { model } = await searchParams;
  const client = await bedrock();
  const data = await load(async () => {
    const [models, profiles, guardrails, provisioned, routers] = await Promise.all([
      client.send(new ListFoundationModelsCommand({ byOutputModality: "TEXT" })).then((r) => r.modelSummaries ?? []),
      client.send(new ListInferenceProfilesCommand({ maxResults: 1000 })).then((r) => r.inferenceProfileSummaries ?? [], () => []),
      client.send(new ListGuardrailsCommand({})).then((r) => r.guardrails ?? [], () => []),
      client.send(new ListProvisionedModelThroughputsCommand({ statusEquals: "InService" })).then((r) => r.provisionedModelSummaries ?? [], () => []),
      client.send(new ListPromptRoutersCommand({})).then((r) => r.promptRouterSummaries ?? [], () => []),
    ]);
    return { models, profiles, guardrails, provisioned, routers };
  });
  if (!data.ok) {
    return (
      <Page title="Playground">
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { models, profiles, guardrails, provisioned, routers } = data.value;
  // Models only reachable through a cross-Region profile are offered as that profile.
  const direct = models.filter((m) => m.inferenceTypesSupported?.includes("ON_DEMAND") && !m.outputModalities?.includes("EMBEDDING"));
  const providers = [...new Set(direct.map((m) => m.providerName ?? "Other"))].sort();
  const preferred = profiles.find((p) => p.inferenceProfileId?.endsWith(`.${model}`))?.inferenceProfileId;
  // Anything the page was opened for (a profile, a Provisioned Throughput, a router) is offered as itself.
  const offered = [
    ...direct.map((m) => m.modelId),
    ...profiles.map((p) => (p.type === "APPLICATION" ? p.inferenceProfileArn : p.inferenceProfileId)),
    ...provisioned.map((p) => p.provisionedModelArn),
    ...routers.map((r) => r.promptRouterArn),
  ];
  const selected = model && offered.includes(model) ? model : (preferred ?? direct.find((m) => m.providerName === "Anthropic")?.modelId);
  return (
    <Page title="Chat playground">
      <Section>
        <ActionForm action={converse} submit="Run" testId="converse">
          <div className="form-row">
            <Field label="Model">
              <select name="model" defaultValue={selected}>
                {providers.map((p) => (
                  <optgroup key={p} label={p}>
                    {direct
                      .filter((m) => (m.providerName ?? "Other") === p)
                      .map((m) => (
                        <option key={m.modelId} value={m.modelId}>
                          {m.modelName}
                        </option>
                      ))}
                  </optgroup>
                ))}
                {provisioned.length > 0 && (
                  <optgroup label="Provisioned Throughput">
                    {provisioned.map((p) => (
                      <option key={p.provisionedModelArn} value={p.provisionedModelArn}>
                        {p.provisionedModelName}
                      </option>
                    ))}
                  </optgroup>
                )}
                {routers.length > 0 && (
                  <optgroup label="Prompt routers">
                    {routers.map((r) => (
                      <option key={r.promptRouterArn} value={r.promptRouterArn}>
                        {r.promptRouterName}
                      </option>
                    ))}
                  </optgroup>
                )}
                {profiles.length > 0 && (
                  <optgroup label="Inference profiles">
                    {profiles.map((p) => (
                      <option key={p.inferenceProfileArn} value={p.type === "APPLICATION" ? p.inferenceProfileArn : p.inferenceProfileId}>
                        {p.inferenceProfileName}
                      </option>
                    ))}
                  </optgroup>
                )}
              </select>
            </Field>
          </div>
          <Field label="Prompt">
            <textarea name="prompt" rows={6} placeholder="Ask anything" required />
          </Field>
          <MoreFields>
          <div className="form-row">
            <Field label="Temperature" rule={TEMPERATURE}>
              <input name="temperature" type="number" min={0} max={1} step={0.1} defaultValue={0.7} />
            </Field>
            <Field label="Max tokens" rule={MAX_TOKENS}>
              <input name="maxTokens" type="number" min={1} defaultValue={512} />
            </Field>
            {guardrails.length > 0 && (
              <Field label="Guardrail">
                <select name="guardrail" defaultValue="">
                  <option value="">None</option>
                  {guardrails.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.name}
                    </option>
                  ))}
                </select>
              </Field>
            )}
          </div>
          <Field label="System prompt">
            <input name="system" placeholder="You are a helpful assistant." />
          </Field>
          </MoreFields>
        </ActionForm>
      </Section>
    </Page>
  );
}
