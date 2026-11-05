//! The foundation model catalog and the system-defined (cross-Region)
//! inference profiles built from it.
//!
//! Real Bedrock lists the models a Region serves; MWS serves every model
//! in every Region, with the throughput types and cross-Region profiles
//! the model has in AWS. `MWS_BEDROCK_MODELS` names a JSON file of extra
//! [`ModelSpec`]s (for models newer than this list).

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// The request and response format a model speaks through `InvokeModel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Family {
    /// Anthropic Messages API (`anthropic_version`, `messages`).
    Anthropic,
    /// Amazon Nova understanding models (`messages`, `inferenceConfig`).
    Nova,
    /// Amazon Titan Text (`inputText`, `textGenerationConfig`).
    TitanText,
    /// Amazon Titan Text Embeddings (`inputText`).
    TitanEmbed,
    /// Amazon Titan Multimodal Embeddings (`inputText`, `inputImage`).
    TitanEmbedImage,
    /// Image generation (Titan Image Generator, Nova Canvas).
    Image,
    /// Video generation (Nova Reel), only through `StartAsyncInvoke`.
    Video,
    /// Meta Llama (`prompt`, `max_gen_len`).
    Llama,
    /// Mistral text completion (`prompt`, `max_tokens`).
    Mistral,
    /// Mistral chat models (`messages`), e.g. Pixtral Large.
    MistralChat,
    /// Cohere Command R (`message`, `chat_history`).
    CohereCommand,
    /// Cohere Embed (`texts`, `input_type`).
    CohereEmbed,
    /// Cohere Rerank (`query`, `documents`).
    CohereRerank,
    /// AI21 Jamba (`messages`, OpenAI-style).
    Jamba,
    /// DeepSeek R1 (`prompt`).
    DeepSeek,
    /// OpenAI open-weight models (Chat Completions format).
    OpenAi,
}

impl Family {
    /// Whether the model answers `Converse`.
    pub fn conversational(self) -> bool {
        !matches!(
            self,
            Family::TitanEmbed
                | Family::TitanEmbedImage
                | Family::Image
                | Family::Video
                | Family::CohereEmbed
                | Family::CohereRerank
        )
    }

    pub fn embedding(self) -> bool {
        matches!(self, Family::TitanEmbed | Family::TitanEmbedImage | Family::CohereEmbed)
    }
}

/// One foundation model.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelSpec {
    pub model_id: String,
    pub model_name: String,
    pub provider_name: String,
    pub family: Family,
    pub input_modalities: Vec<String>,
    pub output_modalities: Vec<String>,
    #[serde(default)]
    pub response_streaming_supported: bool,
    #[serde(default)]
    pub customizations_supported: Vec<String>,
    /// `ON_DEMAND`, `PROVISIONED` and/or `INFERENCE_PROFILE`.
    pub inference_types_supported: Vec<String>,
    /// Cross-Region profile prefixes: `us`, `eu`, `apac`, `global`.
    #[serde(default)]
    pub profiles: Vec<String>,
    /// `ACTIVE` or `LEGACY`.
    #[serde(default = "active")]
    pub lifecycle: String,
    /// The context window, in tokens.
    #[serde(default = "default_context")]
    pub context_window: u32,
}

fn active() -> String {
    "ACTIVE".into()
}

fn default_context() -> u32 {
    128_000
}

impl ModelSpec {
    pub fn on_demand(&self) -> bool {
        self.inference_types_supported.iter().any(|t| t == "ON_DEMAND")
    }

    pub fn arn(&self, partition: &str, region: &str) -> String {
        format!("arn:{partition}:bedrock:{region}::foundation-model/{}", self.model_id)
    }
}

const TEXT: &[&str] = &["TEXT"];
const TEXT_IMAGE: &[&str] = &["TEXT", "IMAGE"];
const TEXT_IMAGE_VIDEO: &[&str] = &["TEXT", "IMAGE", "VIDEO"];
const EMBEDDING: &[&str] = &["EMBEDDING"];
const IMAGE: &[&str] = &["IMAGE"];

const OD: &[&str] = &["ON_DEMAND"];
const OD_PT: &[&str] = &["ON_DEMAND", "PROVISIONED"];
const OD_IP: &[&str] = &["ON_DEMAND", "INFERENCE_PROFILE"];
const IP: &[&str] = &["INFERENCE_PROFILE"];
const FT: &[&str] = &["FINE_TUNING"];
const FT_DIST: &[&str] = &["FINE_TUNING", "DISTILLATION"];
const FT_CPT: &[&str] = &["FINE_TUNING", "CONTINUED_PRE_TRAINING"];

#[allow(clippy::too_many_arguments)]
fn m(
    id: &str,
    name: &str,
    provider: &str,
    family: Family,
    input: &[&str],
    output: &[&str],
    streaming: bool,
    custom: &[&str],
    types: &[&str],
    profiles: &[&str],
    context_window: u32,
) -> ModelSpec {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    ModelSpec {
        model_id: id.into(),
        model_name: name.into(),
        provider_name: provider.into(),
        family,
        input_modalities: s(input),
        output_modalities: s(output),
        response_streaming_supported: streaming,
        customizations_supported: s(custom),
        inference_types_supported: s(types),
        profiles: s(profiles),
        lifecycle: active(),
        context_window,
    }
}

fn builtin() -> Vec<ModelSpec> {
    use Family::*;
    let us_eu_apac: &[&str] = &["us", "eu", "apac"];
    let all4: &[&str] = &["us", "eu", "apac", "global"];
    let mut v = vec![
        // Anthropic
        m(
            "anthropic.claude-3-haiku-20240307-v1:0",
            "Claude 3 Haiku",
            "Anthropic",
            Anthropic,
            TEXT_IMAGE,
            TEXT,
            true,
            FT,
            OD_IP,
            us_eu_apac,
            200_000,
        ),
        m(
            "anthropic.claude-3-5-sonnet-20240620-v1:0",
            "Claude 3.5 Sonnet",
            "Anthropic",
            Anthropic,
            TEXT_IMAGE,
            TEXT,
            true,
            &[],
            OD_IP,
            us_eu_apac,
            200_000,
        ),
        m(
            "anthropic.claude-3-5-haiku-20241022-v1:0",
            "Claude 3.5 Haiku",
            "Anthropic",
            Anthropic,
            TEXT,
            TEXT,
            true,
            &[],
            OD_IP,
            &["us"],
            200_000,
        ),
        m(
            "anthropic.claude-3-7-sonnet-20250219-v1:0",
            "Claude 3.7 Sonnet",
            "Anthropic",
            Anthropic,
            TEXT_IMAGE,
            TEXT,
            true,
            &[],
            IP,
            us_eu_apac,
            200_000,
        ),
        m(
            "anthropic.claude-sonnet-4-20250514-v1:0",
            "Claude Sonnet 4",
            "Anthropic",
            Anthropic,
            TEXT_IMAGE,
            TEXT,
            true,
            &[],
            IP,
            all4,
            200_000,
        ),
        m(
            "anthropic.claude-opus-4-20250514-v1:0",
            "Claude Opus 4",
            "Anthropic",
            Anthropic,
            TEXT_IMAGE,
            TEXT,
            true,
            &[],
            IP,
            &["us"],
            200_000,
        ),
        m(
            "anthropic.claude-opus-4-1-20250805-v1:0",
            "Claude Opus 4.1",
            "Anthropic",
            Anthropic,
            TEXT_IMAGE,
            TEXT,
            true,
            &[],
            IP,
            &["us"],
            200_000,
        ),
        m(
            "anthropic.claude-sonnet-4-5-20250929-v1:0",
            "Claude Sonnet 4.5",
            "Anthropic",
            Anthropic,
            TEXT_IMAGE,
            TEXT,
            true,
            &[],
            IP,
            all4,
            200_000,
        ),
        m(
            "anthropic.claude-haiku-4-5-20251001-v1:0",
            "Claude Haiku 4.5",
            "Anthropic",
            Anthropic,
            TEXT_IMAGE,
            TEXT,
            true,
            &[],
            IP,
            all4,
            200_000,
        ),
        m(
            "anthropic.claude-opus-4-5-20251101-v1:0",
            "Claude Opus 4.5",
            "Anthropic",
            Anthropic,
            TEXT_IMAGE,
            TEXT,
            true,
            &[],
            IP,
            all4,
            200_000,
        ),
        // Amazon
        m(
            "amazon.nova-micro-v1:0",
            "Nova Micro",
            "Amazon",
            Nova,
            TEXT,
            TEXT,
            true,
            FT_DIST,
            OD_IP,
            us_eu_apac,
            128_000,
        ),
        m(
            "amazon.nova-lite-v1:0",
            "Nova Lite",
            "Amazon",
            Nova,
            TEXT_IMAGE_VIDEO,
            TEXT,
            true,
            FT_DIST,
            OD_IP,
            us_eu_apac,
            300_000,
        ),
        m(
            "amazon.nova-pro-v1:0",
            "Nova Pro",
            "Amazon",
            Nova,
            TEXT_IMAGE_VIDEO,
            TEXT,
            true,
            FT_DIST,
            OD_IP,
            us_eu_apac,
            300_000,
        ),
        m(
            "amazon.nova-premier-v1:0",
            "Nova Premier",
            "Amazon",
            Nova,
            TEXT_IMAGE_VIDEO,
            TEXT,
            true,
            &["DISTILLATION"],
            IP,
            &["us"],
            1_000_000,
        ),
        m(
            "amazon.titan-text-express-v1",
            "Titan Text G1 - Express",
            "Amazon",
            TitanText,
            TEXT,
            TEXT,
            true,
            FT_CPT,
            OD_PT,
            &[],
            8_000,
        ),
        m(
            "amazon.titan-text-lite-v1",
            "Titan Text G1 - Lite",
            "Amazon",
            TitanText,
            TEXT,
            TEXT,
            true,
            FT_CPT,
            OD_PT,
            &[],
            4_000,
        ),
        m(
            "amazon.titan-embed-text-v1",
            "Titan Embeddings G1 - Text",
            "Amazon",
            TitanEmbed,
            TEXT,
            EMBEDDING,
            false,
            &[],
            OD,
            &[],
            8_000,
        ),
        m(
            "amazon.titan-embed-text-v2:0",
            "Titan Text Embeddings V2",
            "Amazon",
            TitanEmbed,
            TEXT,
            EMBEDDING,
            false,
            &[],
            OD,
            &[],
            8_000,
        ),
        m(
            "amazon.titan-embed-image-v1",
            "Titan Multimodal Embeddings G1",
            "Amazon",
            TitanEmbedImage,
            TEXT_IMAGE,
            EMBEDDING,
            false,
            FT,
            OD_PT,
            &[],
            128,
        ),
        m(
            "amazon.titan-image-generator-v2:0",
            "Titan Image Generator G1 v2",
            "Amazon",
            Image,
            TEXT_IMAGE,
            IMAGE,
            false,
            FT,
            OD_PT,
            &[],
            512,
        ),
        m("amazon.nova-canvas-v1:0", "Nova Canvas", "Amazon", Image, TEXT_IMAGE, IMAGE, false, &[], OD, &[], 1_024),
        m("amazon.nova-reel-v1:1", "Nova Reel", "Amazon", Video, TEXT_IMAGE, &["VIDEO"], false, &[], OD, &[], 512),
        // Meta
        m("meta.llama3-8b-instruct-v1:0", "Llama 3 8B Instruct", "Meta", Llama, TEXT, TEXT, true, &[], OD, &[], 8_000),
        m(
            "meta.llama3-70b-instruct-v1:0",
            "Llama 3 70B Instruct",
            "Meta",
            Llama,
            TEXT,
            TEXT,
            true,
            &[],
            OD,
            &[],
            8_000,
        ),
        m(
            "meta.llama3-1-8b-instruct-v1:0",
            "Llama 3.1 8B Instruct",
            "Meta",
            Llama,
            TEXT,
            TEXT,
            true,
            FT,
            OD_IP,
            &["us"],
            128_000,
        ),
        m(
            "meta.llama3-1-70b-instruct-v1:0",
            "Llama 3.1 70B Instruct",
            "Meta",
            Llama,
            TEXT,
            TEXT,
            true,
            FT,
            OD_IP,
            &["us"],
            128_000,
        ),
        m(
            "meta.llama3-2-1b-instruct-v1:0",
            "Llama 3.2 1B Instruct",
            "Meta",
            Llama,
            TEXT,
            TEXT,
            true,
            FT,
            IP,
            &["us", "eu"],
            128_000,
        ),
        m(
            "meta.llama3-2-3b-instruct-v1:0",
            "Llama 3.2 3B Instruct",
            "Meta",
            Llama,
            TEXT,
            TEXT,
            true,
            FT,
            IP,
            &["us", "eu"],
            128_000,
        ),
        m(
            "meta.llama3-2-11b-instruct-v1:0",
            "Llama 3.2 11B Instruct",
            "Meta",
            Llama,
            TEXT_IMAGE,
            TEXT,
            true,
            FT,
            IP,
            &["us"],
            128_000,
        ),
        m(
            "meta.llama3-2-90b-instruct-v1:0",
            "Llama 3.2 90B Instruct",
            "Meta",
            Llama,
            TEXT_IMAGE,
            TEXT,
            true,
            FT,
            IP,
            &["us"],
            128_000,
        ),
        m(
            "meta.llama3-3-70b-instruct-v1:0",
            "Llama 3.3 70B Instruct",
            "Meta",
            Llama,
            TEXT,
            TEXT,
            true,
            &[],
            IP,
            &["us"],
            128_000,
        ),
        m(
            "meta.llama4-scout-17b-instruct-v1:0",
            "Llama 4 Scout 17B Instruct",
            "Meta",
            Llama,
            TEXT_IMAGE,
            TEXT,
            true,
            &[],
            IP,
            &["us"],
            3_500_000,
        ),
        m(
            "meta.llama4-maverick-17b-instruct-v1:0",
            "Llama 4 Maverick 17B Instruct",
            "Meta",
            Llama,
            TEXT_IMAGE,
            TEXT,
            true,
            &[],
            IP,
            &["us"],
            1_000_000,
        ),
        // Mistral AI
        m(
            "mistral.mistral-7b-instruct-v0:2",
            "Mistral 7B Instruct",
            "Mistral AI",
            Mistral,
            TEXT,
            TEXT,
            true,
            &[],
            OD,
            &[],
            32_000,
        ),
        m(
            "mistral.mixtral-8x7b-instruct-v0:1",
            "Mixtral 8x7B Instruct",
            "Mistral AI",
            Mistral,
            TEXT,
            TEXT,
            true,
            &[],
            OD,
            &[],
            32_000,
        ),
        m(
            "mistral.mistral-large-2402-v1:0",
            "Mistral Large (24.02)",
            "Mistral AI",
            Mistral,
            TEXT,
            TEXT,
            true,
            &[],
            OD,
            &[],
            32_000,
        ),
        m(
            "mistral.mistral-small-2402-v1:0",
            "Mistral Small (24.02)",
            "Mistral AI",
            Mistral,
            TEXT,
            TEXT,
            true,
            &[],
            OD,
            &[],
            32_000,
        ),
        m(
            "mistral.pixtral-large-2502-v1:0",
            "Pixtral Large (25.02)",
            "Mistral AI",
            MistralChat,
            TEXT_IMAGE,
            TEXT,
            true,
            &[],
            IP,
            &["us", "eu"],
            128_000,
        ),
        // Cohere
        m("cohere.command-r-v1:0", "Command R", "Cohere", CohereCommand, TEXT, TEXT, true, &[], OD, &[], 128_000),
        m("cohere.command-r-plus-v1:0", "Command R+", "Cohere", CohereCommand, TEXT, TEXT, true, &[], OD, &[], 128_000),
        m(
            "cohere.embed-english-v3",
            "Embed English",
            "Cohere",
            CohereEmbed,
            TEXT,
            EMBEDDING,
            false,
            &[],
            OD_PT,
            &[],
            512,
        ),
        m(
            "cohere.embed-multilingual-v3",
            "Embed Multilingual",
            "Cohere",
            CohereEmbed,
            TEXT,
            EMBEDDING,
            false,
            &[],
            OD_PT,
            &[],
            512,
        ),
        m("cohere.rerank-v3-5:0", "Rerank 3.5", "Cohere", CohereRerank, TEXT, TEXT, false, &[], OD, &[], 4_000),
        // AI21 Labs
        m("ai21.jamba-1-5-large-v1:0", "Jamba 1.5 Large", "AI21 Labs", Jamba, TEXT, TEXT, true, &[], OD, &[], 256_000),
        m("ai21.jamba-1-5-mini-v1:0", "Jamba 1.5 Mini", "AI21 Labs", Jamba, TEXT, TEXT, true, &[], OD, &[], 256_000),
        // DeepSeek
        m("deepseek.r1-v1:0", "DeepSeek-R1", "DeepSeek", DeepSeek, TEXT, TEXT, true, &[], IP, &["us"], 128_000),
        // OpenAI
        m("openai.gpt-oss-120b-1:0", "gpt-oss-120b", "OpenAI", OpenAi, TEXT, TEXT, true, &[], OD, &[], 128_000),
        m("openai.gpt-oss-20b-1:0", "gpt-oss-20b", "OpenAI", OpenAi, TEXT, TEXT, true, &[], OD, &[], 128_000),
    ];
    for legacy in
        ["anthropic.claude-3-5-sonnet-20240620-v1:0", "meta.llama3-8b-instruct-v1:0", "meta.llama3-70b-instruct-v1:0"]
    {
        if let Some(s) = v.iter_mut().find(|s| s.model_id == legacy) {
            s.lifecycle = "LEGACY".into();
        }
    }
    v
}

/// Every foundation model MWS serves: the built-in list plus any from
/// `MWS_BEDROCK_MODELS`.
pub fn models() -> &'static [ModelSpec] {
    static MODELS: OnceLock<Vec<ModelSpec>> = OnceLock::new();
    MODELS.get_or_init(|| {
        let mut v = builtin();
        if let Some(path) = std::env::var_os("MWS_BEDROCK_MODELS").filter(|p| !p.is_empty()) {
            match std::fs::read(&path)
                .map_err(|e| e.to_string())
                .and_then(|b| serde_json::from_slice::<Vec<ModelSpec>>(&b).map_err(|e| e.to_string()))
            {
                Ok(extra) => {
                    for e in extra {
                        v.retain(|s| s.model_id != e.model_id);
                        v.push(e);
                    }
                }
                Err(e) => tracing::warn!("ignoring MWS_BEDROCK_MODELS {path:?}: {e}"),
            }
        }
        v
    })
}

pub fn model(model_id: &str) -> Option<&'static ModelSpec> {
    models().iter().find(|m| m.model_id == model_id)
}

/// The Regions a cross-Region profile prefix routes to.
pub fn profile_regions(prefix: &str) -> &'static [&'static str] {
    match prefix {
        "us" => &["us-east-1", "us-east-2", "us-west-2"],
        "eu" => &["eu-central-1", "eu-west-1", "eu-west-3", "eu-north-1"],
        "apac" => &["ap-northeast-1", "ap-northeast-2", "ap-south-1", "ap-southeast-1", "ap-southeast-2"],
        _ => &[],
    }
}

/// Which cross-Region prefixes a source Region can use: its geography's
/// and `global`.
pub fn prefixes_for_region(region: &str) -> Vec<&'static str> {
    let mut v: Vec<&'static str> =
        ["us", "eu", "apac"].into_iter().filter(|p| profile_regions(p).contains(&region)).collect();
    v.push("global");
    v
}

fn geography(prefix: &str) -> &'static str {
    match prefix {
        "us" => "US",
        "eu" => "EU",
        "apac" => "APAC",
        _ => "Global",
    }
}

/// A system-defined inference profile.
#[derive(Debug, Clone)]
pub struct SystemProfile {
    pub id: String,
    pub name: String,
    pub description: String,
    pub model: &'static ModelSpec,
    /// Foundation model ARNs the profile routes to.
    pub model_arns: Vec<String>,
}

/// The system-defined profiles visible from `region`.
pub fn system_profiles(partition: &str, region: &str) -> Vec<SystemProfile> {
    let prefixes = prefixes_for_region(region);
    let mut out = Vec::new();
    for spec in models() {
        for prefix in &spec.profiles {
            if !prefixes.contains(&prefix.as_str()) {
                continue;
            }
            out.push(system_profile_for(partition, prefix, spec));
        }
    }
    out
}

fn system_profile_for(partition: &str, prefix: &str, spec: &'static ModelSpec) -> SystemProfile {
    let (model_arns, description) = if prefix == "global" {
        (
            vec![format!("arn:{partition}:bedrock:::foundation-model/{}", spec.model_id)],
            format!("Routes requests to {} {} in all commercial AWS Regions.", spec.provider_name, spec.model_name),
        )
    } else {
        let regions = profile_regions(prefix);
        (
            regions.iter().map(|r| spec.arn(partition, r)).collect(),
            format!("Routes requests to {} {} in {}.", spec.provider_name, spec.model_name, join_regions(regions)),
        )
    };
    SystemProfile {
        id: format!("{prefix}.{}", spec.model_id),
        name: format!("{} {} {}", geography(prefix), spec.provider_name, spec.model_name),
        description,
        model: spec,
        model_arns,
    }
}

fn join_regions(regions: &[&str]) -> String {
    match regions {
        [] => String::new(),
        [one] => one.to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// The system profile with this id, if `region` can use it.
pub fn system_profile(partition: &str, region: &str, id: &str) -> Option<SystemProfile> {
    let (prefix, model_id) = id.split_once('.')?;
    if !prefixes_for_region(region).contains(&prefix) {
        return None;
    }
    let spec = model(model_id)?;
    spec.profiles.iter().any(|p| p == prefix).then(|| system_profile_for(partition, prefix, spec))
}
