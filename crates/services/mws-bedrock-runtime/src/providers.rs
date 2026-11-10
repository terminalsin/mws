//! Model providers: which upstream answers which Bedrock model, and how.
//!
//! Settings come from two layers. The environment layer is read once at
//! start-up (`MWS_BEDROCK_BACKEND*`, `MWS_BEDROCK_PROVIDERS`,
//! `MWS_BEDROCK_PROVIDER_<NAME>_<SETTING>` and `MWS_BEDROCK_DEFAULT_PROVIDER`).
//! The stored layer is edited at runtime through `/_aws/bedrock/providers`
//! and saved with the rest of MWS state (so `MWS_DB` keeps it). Stored
//! settings win field by field; deleting a stored provider falls back to
//! whatever the environment says.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::backend::{self, Backend, Script};

/// The provider that always exists: deterministic, offline answers.
pub const ECHO: &str = "echo";

/// How a provider is spoken to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Echo,
    /// Any OpenAI Chat Completions server (OpenAI, Ollama, vLLM, LM Studio...).
    OpenAi,
    /// The Anthropic Messages API.
    Anthropic,
    /// The local Claude Code CLI (`claude -p`), with its own login.
    #[serde(rename = "claude-code")]
    ClaudeCode,
    /// The local Codex CLI (`codex exec`), with its own login.
    Codex,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Kind> {
        match s.trim().to_ascii_lowercase().as_str() {
            "echo" => Some(Kind::Echo),
            "openai" | "openai-compatible" | "openai_compatible" => Some(Kind::OpenAi),
            "anthropic" => Some(Kind::Anthropic),
            "claude-code" | "claude_code" | "claudecode" => Some(Kind::ClaudeCode),
            "codex" => Some(Kind::Codex),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Echo => "echo",
            Kind::OpenAi => "openai",
            Kind::Anthropic => "anthropic",
            Kind::ClaudeCode => "claude-code",
            Kind::Codex => "codex",
        }
    }

    /// Whether the provider is a local CLI rather than an HTTP API.
    pub fn is_cli(self) -> bool {
        matches!(self, Kind::ClaudeCode | Kind::Codex)
    }

    /// The kind a provider has when its settings do not say.
    fn infer(name: &str) -> Kind {
        match name {
            "echo" => Kind::Echo,
            "anthropic" | "claude" => Kind::Anthropic,
            "claude-code" | "claudecode" => Kind::ClaudeCode,
            "codex" => Kind::Codex,
            _ => Kind::OpenAi,
        }
    }
}

/// One provider's settings. Every field is optional so a layer can set only
/// some of them; [`Providers::effective`] fills the rest with defaults.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ProviderConfig {
    pub kind: Option<Kind>,
    /// Base URL: `.../v1` for OpenAI-compatible servers, the API root for
    /// Anthropic.
    pub url: Option<String>,
    pub api_key: Option<String>,
    /// The upstream model every request uses, unless `modelMap` names one.
    pub model: Option<String>,
    /// Bedrock model id (`*` wildcards allowed) to upstream model name.
    pub model_map: Option<BTreeMap<String, String>>,
    /// Bedrock model ids this provider answers (`*` wildcards allowed),
    /// e.g. `anthropic.*`.
    pub models: Option<Vec<String>>,
    /// Request-body fields sent when the Bedrock request does not set them
    /// (`temperature`, `max_tokens`, `top_p`, `reasoning_effort`, ...).
    pub params: Option<Map<String, Value>>,
    /// Extra HTTP headers sent upstream.
    pub headers: Option<BTreeMap<String, String>>,
    pub timeout_seconds: Option<u64>,
    /// `anthropic-version` header (Anthropic only).
    pub anthropic_version: Option<String>,
    /// The executable a CLI provider runs (`claude`, `codex` or a path).
    pub command: Option<String>,
    /// Extra arguments for a CLI provider.
    pub args: Option<Vec<String>>,
}

impl ProviderConfig {
    /// `self` with every field `over` sets replaced.
    fn overlay(&self, over: &ProviderConfig) -> ProviderConfig {
        ProviderConfig {
            kind: over.kind.or(self.kind),
            url: over.url.clone().or_else(|| self.url.clone()),
            api_key: over.api_key.clone().or_else(|| self.api_key.clone()),
            model: over.model.clone().or_else(|| self.model.clone()),
            model_map: over.model_map.clone().or_else(|| self.model_map.clone()),
            models: over.models.clone().or_else(|| self.models.clone()),
            params: over.params.clone().or_else(|| self.params.clone()),
            headers: over.headers.clone().or_else(|| self.headers.clone()),
            timeout_seconds: over.timeout_seconds.or(self.timeout_seconds),
            anthropic_version: over.anthropic_version.clone().or_else(|| self.anthropic_version.clone()),
            command: over.command.clone().or_else(|| self.command.clone()),
            args: over.args.clone().or_else(|| self.args.clone()),
        }
    }

    /// Check a provider's settings, as the control API receives them.
    pub fn validate(&self, name: &str) -> Result<(), String> {
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
            return Err(format!("Provider name {name:?} must be letters, digits, '-', '_' or '.'."));
        }
        if let Some(u) = self.url.as_deref().filter(|u| !u.is_empty()) {
            if !(u.starts_with("http://") || u.starts_with("https://")) {
                return Err(format!("Provider URL {u:?} must start with http:// or https://."));
            }
        }
        if let Some(c) = &self.command {
            if c.contains(['\r', '\n', '\0']) {
                return Err(format!("Command {c:?} is not a valid executable name."));
            }
        }
        if self.timeout_seconds == Some(0) {
            return Err("timeoutSeconds must be at least 1.".into());
        }
        for (k, v) in self.headers.iter().flatten() {
            if k.is_empty() || k.contains([':', '\r', '\n', ' ']) || v.contains(['\r', '\n']) {
                return Err(format!("Header {k:?} is not a valid HTTP header."));
            }
        }
        Ok(())
    }
}

/// A layer of provider settings.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Providers {
    /// The provider for models no `models` pattern claims.
    pub default: Option<String>,
    pub providers: BTreeMap<String, ProviderConfig>,
}

/// A provider with every setting decided.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolved {
    pub name: String,
    pub kind: Kind,
    pub url: String,
    pub api_key: Option<String>,
    pub model: Option<String>,
    pub model_map: BTreeMap<String, String>,
    pub models: Vec<String>,
    pub params: Map<String, Value>,
    pub headers: BTreeMap<String, String>,
    pub timeout: Duration,
    pub anthropic_version: String,
    /// CLI providers: the executable (`None` = the CLI's usual name).
    pub command: Option<String>,
    pub args: Vec<String>,
}

const DEFAULT_TIMEOUT: u64 = 300;

fn default_url(name: &str, kind: Kind) -> String {
    match (kind, name) {
        (Kind::Anthropic, _) => "https://api.anthropic.com".into(),
        (Kind::OpenAi, "ollama") => "http://127.0.0.1:11434/v1".into(),
        (Kind::OpenAi, "lmstudio" | "lm-studio") => "http://127.0.0.1:1234/v1".into(),
        (Kind::OpenAi, "vllm") => "http://127.0.0.1:8000/v1".into(),
        (Kind::OpenAi, _) => "https://api.openai.com/v1".into(),
        (Kind::Echo | Kind::ClaudeCode | Kind::Codex, _) => String::new(),
    }
}

/// Does `id` match `pattern` (`*` matches any run of characters)?
pub fn glob(pattern: &str, id: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == id;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !id.starts_with(first) || id.len() < first.len() + last.len() || !id.ends_with(last) {
        return false;
    }
    let mut rest = &id[first.len()..id.len() - last.len()];
    for p in &parts[1..parts.len() - 1] {
        match rest.find(p) {
            Some(i) => rest = &rest[i + p.len()..],
            None => return false,
        }
    }
    true
}

/// How specific a pattern is: its literal characters.
fn specificity(pattern: &str) -> usize {
    pattern.chars().filter(|c| *c != '*').count()
}

impl Resolved {
    /// The upstream model name for a Bedrock model id.
    pub fn upstream_model(&self, model_id: &str) -> String {
        let mapped = self
            .model_map
            .iter()
            .filter(|(p, _)| glob(p, model_id))
            .max_by_key(|(p, _)| (!p.contains('*'), specificity(p)))
            .map(|(_, m)| m.clone());
        mapped.or_else(|| self.model.clone()).unwrap_or_else(|| match self.kind {
            Kind::Anthropic => backend::anthropic_model_name(model_id),
            _ => model_id.to_string(),
        })
    }

    /// The model a CLI provider asks for: the mapped or fixed model, else
    /// the Claude model a Bedrock `anthropic.*` id names (Claude Code), else
    /// the CLI's own default.
    pub fn cli_model(&self, model_id: &str) -> Option<String> {
        // A model the provider itself listed: `<provider>.<model>`.
        if let Some(m) = model_id.strip_prefix(&format!("{}.", self.name)) {
            return Some(m.to_string());
        }
        let mapped = self
            .model_map
            .iter()
            .filter(|(p, _)| glob(p, model_id))
            .max_by_key(|(p, _)| (!p.contains('*'), specificity(p)))
            .map(|(_, m)| m.clone());
        mapped.or_else(|| self.model.clone()).or_else(|| match self.kind {
            Kind::ClaudeCode if model_id.starts_with("anthropic.") => Some(backend::anthropic_model_name(model_id)),
            _ => None,
        })
    }

    pub fn backend(&self, script: Script) -> Arc<dyn Backend> {
        match self.kind {
            Kind::ClaudeCode | Kind::Codex => Arc::new(crate::cli::Cli { provider: self.clone() }),
            Kind::Echo => Arc::new(backend::Echo { script }),
            Kind::OpenAi => Arc::new(backend::OpenAiCompatible { provider: self.clone() }),
            Kind::Anthropic => Arc::new(backend::Anthropic { provider: self.clone() }),
        }
    }

    /// What the control API shows: everything but the API key itself.
    pub fn describe(&self, source: &str) -> Value {
        let mut v = json!({
            "name": self.name,
            "kind": self.kind.as_str(),
            "source": source,
            "apiKeySet": self.api_key.is_some(),
            "models": self.models,
            "modelMap": self.model_map,
            "params": self.params,
            "headers": self.headers.iter().map(|(k, v)| (k.clone(), redact_header(k, v))).collect::<BTreeMap<_, _>>(),
            "timeoutSeconds": self.timeout.as_secs(),
        });
        if self.kind.is_cli() {
            let command = self.command.clone().unwrap_or_else(|| crate::cli::default_command(self.kind).to_string());
            if !self.url.is_empty() {
                v["url"] = json!(self.url);
            }
            match crate::cli::bridge_url(self) {
                Some(url) => v["bridge"] = json!(url),
                None => v["installed"] = json!(crate::cli::find(&command).is_some()),
            }
            v["command"] = json!(command);
            v["args"] = json!(self.args);
        } else if self.kind != Kind::Echo {
            v["url"] = json!(self.url);
        }
        if let Some(k) = &self.api_key {
            v["apiKey"] = json!(redact(k));
        }
        if let Some(m) = &self.model {
            v["model"] = json!(m);
        }
        if self.kind == Kind::Anthropic {
            v["anthropicVersion"] = json!(self.anthropic_version);
        }
        v
    }
}

/// `sk-…wxyz`: enough to tell keys apart, not enough to use one.
pub fn redact(key: &str) -> String {
    let n = key.chars().count();
    if n <= 8 {
        return "…".into();
    }
    let head: String = key.chars().take(3).collect();
    let tail: String = key.chars().skip(n - 4).collect();
    format!("{head}…{tail}")
}

fn redact_header(name: &str, value: &str) -> String {
    let n = name.to_ascii_lowercase();
    if n.contains("auth") || n.contains("key") || n.contains("token") || n.contains("secret") {
        redact(value)
    } else {
        value.to_string()
    }
}

impl Providers {
    /// The environment layer.
    pub fn from_env() -> Self {
        Self::from_vars(std::env::vars())
    }

    /// The environment layer from explicit variables (for tests).
    pub fn from_vars(vars: impl IntoIterator<Item = (String, String)>) -> Self {
        let vars: BTreeMap<String, String> = vars.into_iter().filter(|(_, v)| !v.is_empty()).collect();
        let var = |k: &str| vars.get(k).cloned();
        let mut out = Providers::default();

        // The original single-backend variables.
        let legacy_model = var("MWS_BEDROCK_BACKEND_MODEL");
        match var("MWS_BEDROCK_BACKEND").map(|s| s.to_ascii_lowercase()).as_deref() {
            Some(name @ ("openai" | "anthropic")) => {
                let kind = Kind::infer(name);
                let fallback = if kind == Kind::Anthropic { "ANTHROPIC_API_KEY" } else { "OPENAI_API_KEY" };
                out.providers.insert(
                    name.to_string(),
                    ProviderConfig {
                        kind: Some(kind),
                        url: var("MWS_BEDROCK_BACKEND_URL"),
                        api_key: var("MWS_BEDROCK_BACKEND_API_KEY").or_else(|| var(fallback)),
                        model: legacy_model,
                        ..Default::default()
                    },
                );
                out.default = Some(name.to_string());
            }
            Some("echo") | None => {}
            Some(other) => tracing::warn!("unknown MWS_BEDROCK_BACKEND {other:?}; using echo"),
        }

        // A whole configuration as JSON.
        if let Some(raw) = var("MWS_BEDROCK_PROVIDERS") {
            match parse_providers_json(&raw) {
                Ok(p) => {
                    if p.default.is_some() {
                        out.default = p.default;
                    }
                    for (name, c) in p.providers {
                        let base = out.providers.remove(&name).unwrap_or_default();
                        out.providers.insert(name, base.overlay(&c));
                    }
                }
                Err(e) => tracing::warn!("ignoring MWS_BEDROCK_PROVIDERS: {e}"),
            }
        }

        // One variable per setting: MWS_BEDROCK_PROVIDER_<NAME>_<SETTING>.
        const SETTINGS: [&str; 12] = [
            "ANTHROPIC_VERSION",
            "COMMAND",
            "TIMEOUT_SECONDS",
            "MODEL_MAP",
            "API_KEY",
            "HEADERS",
            "MODELS",
            "PARAMS",
            "MODEL",
            "KIND",
            "ARGS",
            "URL",
        ];
        for (k, v) in &vars {
            let Some(rest) = k.strip_prefix("MWS_BEDROCK_PROVIDER_") else { continue };
            let Some((name, setting)) =
                SETTINGS.iter().find_map(|s| rest.strip_suffix(s).and_then(|n| n.strip_suffix('_')).map(|n| (n, *s)))
            else {
                tracing::warn!("ignoring {k}: unknown provider setting");
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let name = name.to_ascii_lowercase().replace('_', "-");
            let c = out.providers.entry(name).or_default();
            let res: Result<(), String> = (|| {
                match setting {
                    "KIND" => c.kind = Some(Kind::parse(v).ok_or_else(|| format!("unknown kind {v:?}"))?),
                    "URL" => c.url = Some(v.clone()),
                    "API_KEY" => c.api_key = Some(v.clone()),
                    "MODEL" => c.model = Some(v.clone()),
                    "MODELS" => c.models = Some(list(v)),
                    "MODEL_MAP" => c.model_map = Some(string_map(v)?),
                    "HEADERS" => c.headers = Some(string_map(v)?),
                    "PARAMS" => {
                        c.params = Some(match serde_json::from_str(v) {
                            Ok(Value::Object(m)) => m,
                            _ => return Err("expected a JSON object".into()),
                        })
                    }
                    "TIMEOUT_SECONDS" => {
                        c.timeout_seconds = Some(v.parse().map_err(|_| format!("{v:?} is not a number"))?)
                    }
                    "ANTHROPIC_VERSION" => c.anthropic_version = Some(v.clone()),
                    "COMMAND" => c.command = Some(v.clone()),
                    "ARGS" => c.args = Some(v.split_whitespace().map(str::to_string).collect()),
                    _ => unreachable!(),
                }
                Ok(())
            })();
            if let Err(e) = res {
                tracing::warn!("ignoring {k}: {e}");
            }
        }

        if let Some(d) = var("MWS_BEDROCK_DEFAULT_PROVIDER") {
            out.default = Some(d.to_ascii_lowercase());
        }
        // Fill keys for the well-known hosts from the vendors' own variables.
        for (name, c) in &mut out.providers {
            if c.api_key.is_some() {
                continue;
            }
            let kind = c.kind.unwrap_or_else(|| Kind::infer(name));
            let url = c.url.clone().unwrap_or_else(|| default_url(name, kind));
            c.api_key = match kind {
                Kind::OpenAi if url.contains("api.openai.com") => var("OPENAI_API_KEY"),
                Kind::Anthropic if url.contains("api.anthropic.com") => var("ANTHROPIC_API_KEY"),
                _ => None,
            };
        }
        out
    }

    /// `self` (the environment) with `stored` on top.
    pub fn merged(&self, stored: &Providers) -> Providers {
        let mut out = self.clone();
        for (name, c) in &stored.providers {
            let base = out.providers.remove(name).unwrap_or_default();
            out.providers.insert(name.clone(), base.overlay(c));
        }
        if stored.default.is_some() {
            out.default = stored.default.clone();
        }
        out
    }

    /// Every setting of the provider called `name`.
    pub fn resolve(&self, name: &str) -> Option<Resolved> {
        let c = match self.providers.get(name) {
            Some(c) => c.clone(),
            None if name == ECHO => ProviderConfig::default(),
            None => return None,
        };
        let kind = c.kind.unwrap_or_else(|| Kind::infer(name));
        Some(Resolved {
            name: name.to_string(),
            kind,
            url: c.url.filter(|u| !u.is_empty()).unwrap_or_else(|| default_url(name, kind)),
            api_key: c.api_key.filter(|k| !k.is_empty()),
            model: c.model.filter(|m| !m.is_empty()),
            model_map: c.model_map.unwrap_or_default(),
            models: c.models.unwrap_or_default(),
            params: c.params.unwrap_or_default(),
            headers: c.headers.unwrap_or_default(),
            timeout: Duration::from_secs(c.timeout_seconds.unwrap_or(DEFAULT_TIMEOUT)),
            anthropic_version: c.anthropic_version.unwrap_or_else(|| "2023-06-01".into()),
            command: c.command.filter(|c| !c.is_empty()),
            args: c.args.unwrap_or_default(),
        })
    }

    /// The default provider's name (`echo` unless configured).
    pub fn default_name(&self) -> String {
        self.default.clone().filter(|d| d == ECHO || self.providers.contains_key(d)).unwrap_or_else(|| ECHO.into())
    }

    /// The provider that answers `model_id`: the most specific `models`
    /// pattern that matches, otherwise the default.
    pub fn route(&self, model_id: &str) -> Resolved {
        let claimed = self
            .providers
            .iter()
            .flat_map(|(name, c)| c.models.iter().flatten().map(move |p| (name, p)))
            .filter(|(_, p)| glob(p, model_id))
            .max_by_key(|(name, p)| (!p.contains('*'), specificity(p), std::cmp::Reverse((*name).clone())))
            .map(|(name, _)| name.clone());
        // Models a CLI provider listed itself are named after it.
        let listed = || {
            let (prefix, _) = model_id.split_once('.')?;
            self.resolve(prefix).filter(|r| r.kind.is_cli())
        };
        claimed
            .and_then(|n| self.resolve(&n))
            .or_else(listed)
            .or_else(|| self.resolve(&self.default_name()))
            .unwrap_or_else(|| self.resolve(ECHO).expect("echo always resolves"))
    }

    /// Every provider's name, `echo` included.
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.providers.keys().cloned().collect();
        if !names.iter().any(|n| n == ECHO) {
            names.insert(0, ECHO.into());
        }
        names
    }
}

fn parse_providers_json(raw: &str) -> Result<Providers, String> {
    let v: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    if v.get("providers").is_some_and(Value::is_object) {
        serde_json::from_value(v).map_err(|e| e.to_string())
    } else {
        let providers = serde_json::from_value(v).map_err(|e| e.to_string())?;
        Ok(Providers { default: None, providers })
    }
}

fn list(s: &str) -> Vec<String> {
    s.split(',').map(str::trim).filter(|x| !x.is_empty()).map(str::to_string).collect()
}

/// A JSON object of strings, or `a=b,c=d`.
fn string_map(s: &str) -> Result<BTreeMap<String, String>, String> {
    if s.trim_start().starts_with('{') {
        return serde_json::from_str(s).map_err(|e| format!("expected a JSON object of strings: {e}"));
    }
    list(s)
        .into_iter()
        .map(|kv| {
            kv.split_once('=')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                .ok_or_else(|| format!("{kv:?} is not key=value"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Providers {
        Providers::from_vars(pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())))
    }

    #[test]
    fn globs() {
        assert!(glob("anthropic.*", "anthropic.claude-3-haiku-20240307-v1:0"));
        assert!(glob("*llama*", "meta.llama3-8b-instruct-v1:0"));
        assert!(!glob("meta.*", "anthropic.claude"));
        assert!(glob("a*b*c", "aXbYc"));
        assert!(!glob("ab*ba", "aba"));
    }

    #[test]
    fn legacy_variables_still_work() {
        let p = env(&[
            ("MWS_BEDROCK_BACKEND", "openai"),
            ("MWS_BEDROCK_BACKEND_URL", "http://localhost:11434/v1"),
            ("MWS_BEDROCK_BACKEND_MODEL", "llama3"),
            ("OPENAI_API_KEY", "sk-legacy"),
        ]);
        let r = p.route("amazon.nova-lite-v1:0");
        assert_eq!(r.name, "openai");
        assert_eq!(r.url, "http://localhost:11434/v1");
        assert_eq!(r.api_key.as_deref(), Some("sk-legacy"));
        assert_eq!(r.upstream_model("amazon.nova-lite-v1:0"), "llama3");
    }

    #[test]
    fn per_provider_variables_route_by_model() {
        let p = env(&[
            ("MWS_BEDROCK_PROVIDER_LOCAL_LLM_KIND", "openai"),
            ("MWS_BEDROCK_PROVIDER_LOCAL_LLM_URL", "http://127.0.0.1:8000/v1"),
            ("MWS_BEDROCK_PROVIDER_LOCAL_LLM_MODELS", "meta.*,mistral.*"),
            ("MWS_BEDROCK_PROVIDER_LOCAL_LLM_MODEL_MAP", "meta.llama3-8b-instruct-v1:0=llama3:8b"),
            ("MWS_BEDROCK_PROVIDER_LOCAL_LLM_PARAMS", r#"{"temperature":0.1}"#),
            ("MWS_BEDROCK_PROVIDER_ANTHROPIC_MODELS", "anthropic.*"),
            ("MWS_BEDROCK_PROVIDER_ANTHROPIC_TIMEOUT_SECONDS", "30"),
            ("ANTHROPIC_API_KEY", "sk-ant-123456789"),
        ]);
        let llama = p.route("meta.llama3-8b-instruct-v1:0");
        assert_eq!(llama.name, "local-llm");
        assert_eq!(llama.upstream_model("meta.llama3-8b-instruct-v1:0"), "llama3:8b");
        assert_eq!(llama.params["temperature"], json!(0.1));
        let claude = p.route("anthropic.claude-3-haiku-20240307-v1:0");
        assert_eq!(claude.kind, Kind::Anthropic);
        assert_eq!(claude.api_key.as_deref(), Some("sk-ant-123456789"));
        assert_eq!(claude.timeout, Duration::from_secs(30));
        assert_eq!(claude.upstream_model("anthropic.claude-3-haiku-20240307-v1:0"), "claude-3-haiku-20240307");
        assert_eq!(p.route("amazon.titan-text-express-v1").name, ECHO);
    }

    #[test]
    fn stored_settings_win_field_by_field() {
        let envp = env(&[(
            "MWS_BEDROCK_PROVIDERS",
            r#"{"default":"gw","providers":{"gw":{"url":"http://a/v1","apiKey":"k-env-12345"}}}"#,
        )]);
        let stored = Providers {
            default: None,
            providers: [("gw".to_string(), ProviderConfig { url: Some("http://b/v1".into()), ..Default::default() })]
                .into(),
        };
        let r = envp.merged(&stored).route("x");
        assert_eq!(r.name, "gw");
        assert_eq!(r.url, "http://b/v1");
        assert_eq!(r.api_key.as_deref(), Some("k-env-12345"));
    }

    #[test]
    fn redacts_keys() {
        assert_eq!(redact("sk-abcdefghijklmnop"), "sk-…mnop");
        assert_eq!(redact("short"), "…");
    }
}
