"use client";

// The model provider form's fields. Adding one starts from a logo: picking
// a preset fills in the API, URL, models and CLI, and shows only the fields
// that preset needs (the rest wait under More). Local tools MWS found are
// marked and come first.

import { iconUrl } from "@mws-dashboard/ui/catalog";
import { FieldShell } from "@mws-dashboard/ui/fields";
import { Check, ExternalLink, SlidersHorizontal, Wrench } from "lucide-react";
import { useState, type ReactNode } from "react";

import { PRESETS, type Kind, type Local, type Preset } from "../../../lib/presets";

export interface ProviderView {
  name: string;
  kind: Kind;
  url?: string;
  apiKey?: string;
  apiKeySet: boolean;
  model?: string;
  models: string[];
  modelMap: Record<string, string>;
  params: Record<string, unknown>;
  headers: Record<string, string>;
  timeoutSeconds: number;
  command?: string;
  args?: string[];
  installed?: boolean;
}

// The console stores names lowercased; MWS takes letters, digits, - _ and .
const NAME = { required: true, pattern: "^[a-z0-9._-]+$", hint: "Lowercase letters, digits, . - and _" };

const CUSTOM: Preset = { id: "custom", label: "Custom", icon: "", kind: "openai", place: "cloud" };

const lines = (m: Record<string, string>) =>
  Object.entries(m)
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");

const isCli = (k: Kind) => k === "claude-code" || k === "codex";

/** The first free name: `openai`, else `openai-2`, ... */
function freeName(id: string, names: string[]) {
  if (!names.includes(id)) return id;
  for (let n = 2; ; n++) if (!names.includes(`${id}-${n}`)) return `${id}-${n}`;
}

function Logo({ icon, size = 28 }: { icon: string; size?: number }) {
  return <img src={iconUrl(icon)} alt="" width={size} height={size} style={{ width: size, height: size }} />;
}

/** The preset gallery: on this machine first (found tools before the rest), then cloud APIs. */
function Gallery({ chosen, choose, local, names }: { chosen: string; choose: (p: Preset) => void; local: Local; names: string[] }) {
  const found = (p: Preset) => !!(p.detect && local[p.detect]?.found);
  const groups: [string, Preset[]][] = [
    ["On this machine", PRESETS.filter((p) => p.place === "local").sort((a, b) => Number(found(b)) - Number(found(a)))],
    ["Cloud", PRESETS.filter((p) => p.place === "cloud")],
  ];
  return (
    <div className="presets" role="radiogroup" aria-label="Provider">
      {groups.map(([title, list]) => (
        <section key={title} aria-label={title}>
          <h3>{title}</h3>
          <div className="preset-grid">
            {list.map((p) => (
              <button
                key={p.id}
                type="button"
                role="radio"
                aria-checked={chosen === p.id}
                className="preset"
                data-testid={`preset-${p.id}`}
                onClick={() => choose(p)}
                title={p.label}
              >
                <Logo icon={p.icon} />
                <span>{p.label}</span>
                {found(p) && <i className="preset-found" aria-label="Installed" title={local[p.detect!]?.path} />}
                {names.includes(p.id) && <Check className="preset-added" size={12} aria-label="Added" />}
              </button>
            ))}
            {title === "Cloud" && (
              <button type="button" role="radio" aria-checked={chosen === CUSTOM.id} className="preset" data-testid="preset-custom" onClick={() => choose(CUSTOM)} title="Custom">
                <Wrench size={22} aria-hidden />
                <span>Custom</span>
              </button>
            )}
          </div>
        </section>
      ))}
    </div>
  );
}

/** Fields that only some providers need, folded away unless `open`. */
function More({ open, children }: { open: boolean; children: ReactNode }) {
  if (open) return <>{children}</>;
  return (
    <details className="more-fields">
      <summary>
        <SlidersHorizontal size={14} aria-hidden /> More
      </summary>
      {children}
    </details>
  );
}

export function ProviderFields({ p, names = [], local = {} }: { p?: ProviderView; names?: string[]; local?: Local }) {
  const [preset, setPreset] = useState<Preset>(CUSTOM);
  // An existing provider shows its own kind's fields; a new one its preset's.
  const kind: Kind = p?.kind ?? preset.kind;
  const custom = !p && preset.id === CUSTOM.id;
  const cli = isCli(kind);
  const localServer = !p && preset.place === "local" && !cli;
  const v = (from: string | undefined, fallback?: string) => (p ? from : fallback);
  const tool = cli ? local[kind] : undefined;
  return (
    <>
      {!p && (
        <Gallery
          chosen={preset.id}
          choose={setPreset}
          local={local}
          names={names}
        />
      )}
      {/* Fields remount per preset, so each starts from that preset's values. */}
      <div key={p?.name ?? preset.id} className="preset-fields">
        {!p && (
          <FieldShell label="Name" rule={NAME} taken={names} unique>
            <input name="name" placeholder="ollama" required defaultValue={custom ? undefined : freeName(preset.id, names)} />
          </FieldShell>
        )}
        {custom ? (
          <FieldShell label="API">
            <select name="kind" defaultValue="openai">
              <option value="openai">OpenAI compatible</option>
              <option value="anthropic">Anthropic</option>
              <option value="claude-code">Claude Code CLI</option>
              <option value="codex">Codex CLI</option>
              <option value="echo">Echo</option>
            </select>
          </FieldShell>
        ) : (
          <input type="hidden" name="kind" value={kind} />
        )}
        {cli && (
          <FieldShell
            label="Command"
            hint={
              tool && !tool.found && !p ? (
                <span className="warn-text">Not found where MWS runs</span>
              ) : p && p.installed === false ? (
                <span className="warn-text">Not found where MWS runs</span>
              ) : undefined
            }
          >
            <input name="command" defaultValue={p?.command ?? preset.command} placeholder={kind === "codex" ? "codex" : "claude"} />
          </FieldShell>
        )}
        {!cli && (custom || localServer || p) && (
          <FieldShell label="URL" format="url">
            <input name="url" defaultValue={v(p?.url, preset.url)} placeholder="http://127.0.0.1:11434/v1" />
          </FieldShell>
        )}
        {!cli && !localServer && (
          <FieldShell
            label="API key"
            hint={
              preset.keyUrl && !p ? (
                <a href={preset.keyUrl} target="_blank" rel="noreferrer" className="inline-link">
                  {new URL(preset.keyUrl).hostname} <ExternalLink size={11} aria-hidden />
                </a>
              ) : undefined
            }
          >
            <input name="apiKey" type="password" autoComplete="off" placeholder={p?.apiKeySet ? `${p.apiKey} (unchanged)` : ""} />
          </FieldShell>
        )}
        {p?.apiKeySet && (
          <label className="check">
            <input type="checkbox" name="clearKey" /> Remove stored key
          </label>
        )}
        <div className="form-row">
          <FieldShell label="Models">
            <input name="models" defaultValue={p ? p.models.join(", ") : preset.models} placeholder="meta.*, mistral.*" />
          </FieldShell>
          <FieldShell label="Upstream model">
            <input name="model" defaultValue={v(p?.model, preset.model)} placeholder={cli || preset.models ? "auto" : "llama3.1:8b"} />
          </FieldShell>
        </div>
        <More open={custom}>
          {!cli && !custom && !localServer && !p && (
            <FieldShell label="URL" format="url">
              <input name="url" defaultValue={preset.url} />
            </FieldShell>
          )}
          {localServer && (
            <FieldShell label="API key">
              <input name="apiKey" type="password" autoComplete="off" />
            </FieldShell>
          )}
          {cli && (
            <FieldShell label="Extra arguments">
              <input name="args" defaultValue={p?.args?.join(" ")} placeholder={kind === "codex" ? "-c model_reasoning_effort=low" : "--effort low"} />
            </FieldShell>
          )}
          <FieldShell label="Timeout (s)">
            <input name="timeout" type="number" min={1} defaultValue={p?.timeoutSeconds} />
          </FieldShell>
          <FieldShell label="Model map" format="pairs">
            <textarea name="modelMap" rows={3} className="code-editor" spellCheck={false} defaultValue={p && lines(p.modelMap)} placeholder="meta.llama3-8b-instruct-v1:0=llama3:8b" />
          </FieldShell>
          {!cli && (
            <>
              <FieldShell label="Default parameters" format="json">
                <textarea
                  name="params"
                  rows={3}
                  className="code-editor"
                  spellCheck={false}
                  defaultValue={p && Object.keys(p.params).length ? JSON.stringify(p.params, null, 2) : ""}
                  placeholder='{"temperature": 0.2}'
                />
              </FieldShell>
              <FieldShell label="Headers" format="pairs">
                <textarea name="headers" rows={2} className="code-editor" spellCheck={false} defaultValue={p && lines(p.headers)} placeholder="x-team=ml" />
              </FieldShell>
            </>
          )}
        </More>
        <label className="check">
          <input type="checkbox" name="makeDefault" defaultChecked={!p && !!preset.fallback} /> Default provider
        </label>
      </div>
    </>
  );
}
