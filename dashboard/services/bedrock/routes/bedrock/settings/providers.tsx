import { load, mws } from "@mws-dashboard/aws";
import { ActionForm, ErrorNotice, Field, List, Pill, Section, Sheet } from "@mws-dashboard/ui";
import { Bot, KeyRound, Pencil, Repeat2, RotateCcw, Sparkles, Star } from "lucide-react";

import { forgetProvider, saveProvider, setDefaultProvider } from "../actions";

interface Provider {
  name: string;
  kind: "echo" | "openai" | "anthropic";
  source: "builtin" | "environment" | "stored" | "environment+stored";
  url?: string;
  apiKey?: string;
  apiKeySet: boolean;
  model?: string;
  models: string[];
  modelMap: Record<string, string>;
  params: Record<string, unknown>;
  headers: Record<string, string>;
  timeoutSeconds: number;
}

const KIND_ICON = { echo: Repeat2, openai: Bot, anthropic: Sparkles };
const SOURCE = { builtin: "built in", environment: "env", stored: "stored", "environment+stored": "env + stored" };

const lines = (m: Record<string, string>) => Object.entries(m).map(([k, v]) => `${k}=${v}`).join("\n");

function ProviderForm({ p }: { p?: Provider }) {
  return (
    <ActionForm action={saveProvider.bind(null, p?.name ?? null)} submit="Save" testId={p ? `edit-provider-${p.name}` : "add-provider"}>
      {!p && (
        <Field label="Name">
          <input name="name" placeholder="ollama" pattern="[A-Za-z0-9._\-]+" required />
        </Field>
      )}
      <div className="form-row">
        <Field label="API">
          <select name="kind" defaultValue={p?.kind ?? "openai"}>
            <option value="openai">OpenAI compatible</option>
            <option value="anthropic">Anthropic</option>
            <option value="echo">Echo</option>
          </select>
        </Field>
        <Field label="Timeout (s)">
          <input name="timeout" type="number" min={1} defaultValue={p?.timeoutSeconds} />
        </Field>
      </div>
      <Field label="URL">
        <input name="url" defaultValue={p?.url} placeholder="http://127.0.0.1:11434/v1" />
      </Field>
      <Field label="API key">
        <input name="apiKey" type="password" autoComplete="off" placeholder={p?.apiKeySet ? `${p.apiKey} (unchanged)` : ""} />
      </Field>
      {p?.apiKeySet && (
        <label className="check">
          <input type="checkbox" name="clearKey" /> Remove stored key
        </label>
      )}
      <div className="form-row">
        <Field label="Models">
          <input name="models" defaultValue={p?.models.join(", ")} placeholder="meta.*, mistral.*" />
        </Field>
        <Field label="Upstream model">
          <input name="model" defaultValue={p?.model} placeholder="llama3.1:8b" />
        </Field>
      </div>
      <Field label="Model map">
        <textarea name="modelMap" rows={3} className="code-editor" spellCheck={false} defaultValue={p && lines(p.modelMap)} placeholder="meta.llama3-8b-instruct-v1:0=llama3:8b" />
      </Field>
      <Field label="Default parameters">
        <textarea name="params" rows={3} className="code-editor" spellCheck={false} defaultValue={p && Object.keys(p.params).length ? JSON.stringify(p.params, null, 2) : ""} placeholder='{"temperature": 0.2}' />
      </Field>
      <Field label="Headers">
        <textarea name="headers" rows={2} className="code-editor" spellCheck={false} defaultValue={p && lines(p.headers)} placeholder="x-team=ml" />
      </Field>
      <label className="check">
        <input type="checkbox" name="makeDefault" /> Default provider
      </label>
    </ActionForm>
  );
}

export async function Providers() {
  const res = await load(() => mws<{ default: string; providers: Provider[] }>("/_aws/bedrock/providers"));
  if (!res.ok) {
    return (
      <Section title="Model providers">
        <ErrorNotice error={res.error} />
      </Section>
    );
  }
  const { default: fallback, providers } = res.value;
  return (
    <Section
      title="Model providers"
      count={providers.length}
      actions={
        <>
          {providers.length > 1 && (
            <ActionForm action={setDefaultProvider} submit="Set default provider" icon={<Star size={15} />} inline testId="default-provider">
              <select name="provider" aria-label="Default provider" defaultValue={fallback}>
                {providers.map((p) => (
                  <option key={p.name} value={p.name}>
                    {p.name}
                  </option>
                ))}
              </select>
            </ActionForm>
          )}
          <Sheet title="Add model provider" label="Add provider" testId="add-provider">
            <ProviderForm />
          </Sheet>
        </>
      }
    >
      <List
        label="Model providers"
        rows={providers.map((p) => {
          const Icon = KIND_ICON[p.kind];
          return {
            key: p.name,
            icon: <Icon size={20} aria-hidden />,
            title: p.name,
            subtitle: p.kind === "echo" ? "Deterministic, offline" : <code>{p.url}</code>,
            meta: (
              <span className="chips">
                {p.name === fallback && <Pill icon={<Star size={11} />}>default</Pill>}
                {p.models.map((m) => (
                  <Pill key={m}>{m}</Pill>
                ))}
                {p.model && <Pill>→ {p.model}</Pill>}
                {p.apiKeySet && <Pill icon={<KeyRound size={11} />}>{p.apiKey}</Pill>}
                <Pill>{SOURCE[p.source]}</Pill>
              </span>
            ),
            actions:
              p.kind === "echo" && p.source === "builtin" ? undefined : (
                <>
                  <Sheet title={`Edit ${p.name}`} label={`Edit ${p.name}`} icon={<Pencil size={15} />} testId={`edit-provider-${p.name}`}>
                    <ProviderForm p={p} />
                  </Sheet>
                  {p.source.includes("stored") && (
                    <ActionForm
                      action={forgetProvider.bind(null, p.name)}
                      submit={p.source === "stored" ? `Delete ${p.name}` : `Reset ${p.name} to environment`}
                      icon={<RotateCcw size={15} />}
                      tone="danger"
                      confirm={p.source === "stored" ? `Delete provider ${p.name}?` : `Drop stored settings for ${p.name} and use the environment's?`}
                    />
                  )}
                </>
              ),
          };
        })}
      />
    </Section>
  );
}
