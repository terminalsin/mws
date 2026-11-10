// Model provider presets: what the console fills in when adding a provider.
// Shared by the server page and the client fields (no server-only imports).

export type Kind = "echo" | "openai" | "anthropic" | "claude-code" | "codex";

/** Where a provider runs: on this machine (a CLI or a local server) or in the cloud. */
export type Place = "local" | "cloud";

export interface Preset {
  id: string;
  label: string;
  icon: string;
  kind: Kind;
  place: Place;
  url?: string;
  /** The CLI it runs (Claude Code, Codex). */
  command?: string;
  /** Bedrock model ids it answers. */
  models?: string;
  /** The upstream model, when Bedrock ids mean nothing to the provider. */
  model?: string;
  /** Where to get an API key (cloud presets need one). */
  keyUrl?: string;
  /** Answers every model nothing else claims. */
  fallback?: boolean;
  /** `GET /_aws/bedrock/local` key that says it is installed. */
  detect?: string;
}

export const PRESETS: Preset[] = [
  { id: "claude-code", label: "Claude Code", icon: "ai/claudecode", kind: "claude-code", place: "local", command: "claude", models: "anthropic.*", detect: "claude-code" },
  { id: "codex", label: "Codex", icon: "ai/codex", kind: "codex", place: "local", command: "codex", models: "openai.*", detect: "codex" },
  { id: "ollama", label: "Ollama", icon: "ai/ollama", kind: "openai", place: "local", url: "http://127.0.0.1:11434/v1", models: "meta.*", model: "llama3.1:8b", detect: "ollama" },
  { id: "lmstudio", label: "LM Studio", icon: "ai/lmstudio", kind: "openai", place: "local", url: "http://127.0.0.1:1234/v1", models: "meta.*", detect: "lmstudio" },
  { id: "vllm", label: "vLLM", icon: "ai/vllm", kind: "openai", place: "local", url: "http://127.0.0.1:8000/v1" },
  { id: "anthropic", label: "Anthropic", icon: "ai/anthropic", kind: "anthropic", place: "cloud", url: "https://api.anthropic.com", models: "anthropic.*", keyUrl: "https://console.anthropic.com/settings/keys" },
  { id: "openai", label: "OpenAI", icon: "ai/openai", kind: "openai", place: "cloud", url: "https://api.openai.com/v1", models: "openai.*", model: "gpt-5-mini", keyUrl: "https://platform.openai.com/api-keys" },
  { id: "openrouter", label: "OpenRouter", icon: "ai/openrouter", kind: "openai", place: "cloud", url: "https://openrouter.ai/api/v1", model: "openrouter/auto", fallback: true, keyUrl: "https://openrouter.ai/settings/keys" },
  { id: "gemini", label: "Gemini", icon: "ai/gemini", kind: "openai", place: "cloud", url: "https://generativelanguage.googleapis.com/v1beta/openai", model: "gemini-2.5-flash", fallback: true, keyUrl: "https://aistudio.google.com/apikey" },
  { id: "mistral", label: "Mistral", icon: "ai/mistral", kind: "openai", place: "cloud", url: "https://api.mistral.ai/v1", models: "mistral.*", model: "mistral-large-latest", keyUrl: "https://console.mistral.ai/api-keys" },
  { id: "groq", label: "Groq", icon: "ai/groq", kind: "openai", place: "cloud", url: "https://api.groq.com/openai/v1", models: "meta.*", model: "llama-3.3-70b-versatile", keyUrl: "https://console.groq.com/keys" },
  { id: "deepseek", label: "DeepSeek", icon: "ai/deepseek", kind: "openai", place: "cloud", url: "https://api.deepseek.com/v1", models: "deepseek.*", model: "deepseek-chat", keyUrl: "https://platform.deepseek.com/api_keys" },
  { id: "xai", label: "xAI", icon: "ai/xai", kind: "openai", place: "cloud", url: "https://api.x.ai/v1", model: "grok-4", keyUrl: "https://console.x.ai" },
  { id: "fireworks", label: "Fireworks", icon: "ai/fireworks", kind: "openai", place: "cloud", url: "https://api.fireworks.ai/inference/v1", models: "meta.*", model: "accounts/fireworks/models/llama-v3p3-70b-instruct", keyUrl: "https://fireworks.ai/account/api-keys" },
  { id: "cerebras", label: "Cerebras", icon: "ai/cerebras", kind: "openai", place: "cloud", url: "https://api.cerebras.ai/v1", models: "meta.*", model: "llama-3.3-70b", keyUrl: "https://cloud.cerebras.ai" },
  { id: "perplexity", label: "Perplexity", icon: "ai/perplexity", kind: "openai", place: "cloud", url: "https://api.perplexity.ai", model: "sonar", keyUrl: "https://www.perplexity.ai/account/api/keys" },
];

/** The logo of a configured provider: its preset's, matched by kind, then
 * by host, then by name. */
export function providerLogo(p: { name: string; kind: Kind; url?: string }): string | undefined {
  if (p.kind === "claude-code" || p.kind === "codex") return PRESETS.find((x) => x.kind === p.kind)?.icon;
  const host = hostOf(p.url);
  const byHost = host && PRESETS.find((x) => x.url && hostOf(x.url) === host && (x.place === "cloud" || portOf(x.url) === portOf(p.url)));
  if (byHost) return byHost.icon;
  const byName = PRESETS.find((x) => p.name === x.id || p.name.startsWith(`${x.id}-`));
  if (byName) return byName.icon;
  return p.kind === "anthropic" ? "ai/anthropic" : undefined;
}

function hostOf(url: string | undefined) {
  try {
    return url ? new URL(url).hostname : undefined;
  } catch {
    return undefined;
  }
}

function portOf(url: string | undefined) {
  try {
    return url ? new URL(url).port : undefined;
  } catch {
    return undefined;
  }
}

/** What `GET /_aws/bedrock/local` says: the local tools found (here, or on
 * the host through the CLI bridge), whether MWS runs in a container, and
 * the bridge it was given. */
export interface Local {
  tools: Record<string, { found: boolean; command: string; path?: string; via?: "bridge"; loggedIn?: boolean }>;
  container: boolean;
  bridge: { url: string; reachable: boolean } | null;
}

/** The command that logs a CLI in. */
export const LOGIN: Record<string, string> = { "claude-code": "claude login", codex: "codex login" };

export const NO_LOCAL: Local = { tools: {}, container: false, bridge: null };
