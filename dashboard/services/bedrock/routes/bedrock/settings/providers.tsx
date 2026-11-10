import { load, mws } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, ErrorNotice, List, Pill, Section, Sheet } from "@mws-dashboard/ui";
import { KeyRound, Pencil, Repeat2, RotateCcw, Server, Star, TriangleAlert } from "lucide-react";

import { NO_LOCAL, providerLogo, type Local } from "../../../lib/presets";
import { forgetProvider, saveProvider, setDefaultProvider } from "../actions";
import { ProviderFields, type ProviderView } from "./fields";

interface Provider extends ProviderView {
  source: "builtin" | "environment" | "stored" | "environment+stored";
}

/** What a row says about where the provider is: a host, or the CLI. */
function where(p: Provider) {
  if (p.kind === "claude-code" || p.kind === "codex") {
    const host = p.bridge && hostPort(p.bridge);
    return <code>{host ? `${p.command} @ ${host}` : p.command}</code>;
  }
  try {
    const u = new URL(p.url ?? "");
    return <code>{u.port ? `${u.hostname}:${u.port}` : u.hostname}</code>;
  } catch {
    return p.url ? <code>{p.url}</code> : undefined;
  }
}

function hostPort(url: string) {
  try {
    const u = new URL(url);
    return u.port ? `${u.hostname}:${u.port}` : u.hostname;
  } catch {
    return url;
  }
}

export async function Providers() {
  const [res, local] = await Promise.all([
    load(() => mws<{ default: string; providers: Provider[] }>("/_aws/bedrock/providers")),
    load(() => mws<Local>("/_aws/bedrock/local")),
  ]);
  if (!res.ok) {
    return (
      <Section title="Model providers">
        <ErrorNotice error={res.error} />
      </Section>
    );
  }
  const { default: fallback, providers } = res.value;
  const names = providers.map((p) => p.name);
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
            <ActionForm action={saveProvider.bind(null, null)} submit="Save" testId="add-provider">
              <ProviderFields names={names} local={local.ok && local.value.tools ? local.value : NO_LOCAL} />
            </ActionForm>
          </Sheet>
        </>
      }
    >
      <List
        label="Model providers"
        rows={providers.map((p) => {
          const logo = providerLogo(p);
          return {
            key: p.name,
            icon: logo ? <AwsIcon icon={logo} size={22} /> : p.kind === "echo" ? <Repeat2 size={20} aria-hidden /> : <Server size={20} aria-hidden />,
            title: p.name,
            subtitle: p.kind === "echo" ? undefined : where(p),
            meta: (
              <span className="chips">
                {p.name === fallback && <Pill icon={<Star size={11} />}>default</Pill>}
                {p.installed === false && (
                  <Pill tone="warn" icon={<TriangleAlert size={11} />}>
                    not installed
                  </Pill>
                )}
                {p.models.map((m) => (
                  <Pill key={m}>{m}</Pill>
                ))}
                {p.model && <Pill>→ {p.model}</Pill>}
                {p.apiKeySet && <Pill icon={<KeyRound size={11} />}>{p.apiKey}</Pill>}
                {p.source.startsWith("environment") && <Pill title={p.source === "environment" ? "From the environment" : "Environment, with stored changes"}>env</Pill>}
              </span>
            ),
            actions:
              p.kind === "echo" && p.source === "builtin" ? undefined : (
                <>
                  <Sheet title={`Edit ${p.name}`} label={`Edit ${p.name}`} icon={<Pencil size={15} />} testId={`edit-provider-${p.name}`}>
                    <ActionForm action={saveProvider.bind(null, p.name)} submit="Save" testId={`edit-provider-${p.name}`}>
                      <ProviderFields p={p} />
                    </ActionForm>
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
