//! Guardrail evaluation, shared by `ApplyGuardrail` and guarded model
//! invocations in bedrock-runtime.
//!
//! The policies act as configured, with deterministic detectors standing
//! in for Bedrock's classifiers: denied words and managed profanity match
//! whole words, denied topics match their name or one of their example
//! phrases, content filters match small per-category phrase lists, PII
//! entities with a recognizable shape (email, phone, SSN, card numbers
//! with a Luhn check, IP and MAC addresses, URLs, AWS keys, IBANs) are
//! found by pattern, custom regexes run as written, and contextual
//! grounding scores are word-overlap ratios against the grounding source
//! and query.
//!
//! The assessment is a document keyed by bedrock-runtime's generated field
//! names, so the runtime turns it into its own `GuardrailAssessment`.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::generated::types;

/// Whether the content is a prompt or a model response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Input,
    Output,
}

impl Source {
    pub fn parse(s: &str) -> Source {
        if s == "OUTPUT" {
            Source::Output
        } else {
            Source::Input
        }
    }
}

/// One piece of content to evaluate.
#[derive(Debug, Clone, Default)]
pub struct Block {
    pub text: String,
    /// `grounding_source`, `query` and/or `guard_content`.
    pub qualifiers: Vec<String>,
}

impl Block {
    pub fn text(text: impl Into<String>) -> Block {
        Block { text: text.into(), qualifiers: Vec::new() }
    }

    fn guarded(&self) -> bool {
        self.qualifiers.is_empty() || self.qualifiers.iter().any(|q| q == "guard_content")
    }
}

/// The result of evaluating content against a guardrail.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub intervened: bool,
    /// Every block's text with anonymized entities masked.
    pub masked: Vec<String>,
    /// Whether any policy blocked (rather than only masked).
    pub blocked: bool,
    /// The configured blocked message for this source.
    pub blocked_message: String,
    /// `GuardrailAssessment` fields.
    pub assessment: Map<String, Value>,
    /// `GuardrailUsage` fields.
    pub usage: Map<String, Value>,
    pub characters_guarded: i64,
    pub characters_total: i64,
}

impl Outcome {
    /// The texts `ApplyGuardrail` returns: the blocked message, the masked
    /// content, or nothing when the guardrail took no action.
    pub fn outputs(&self) -> Vec<String> {
        if self.blocked {
            vec![self.blocked_message.clone()]
        } else if self.intervened {
            self.masked.clone()
        } else {
            Vec::new()
        }
    }

    pub fn action_reason(&self) -> &'static str {
        if self.blocked {
            "Guardrail blocked."
        } else if self.intervened {
            "Guardrail masked."
        } else {
            "No action."
        }
    }
}

/// Decide what a policy entry does for `source`: `None` when it is
/// disabled, else the action (`BLOCK`, `ANONYMIZE` or `NONE`).
fn action_for(
    source: Source,
    input_action: &Option<String>,
    output_action: &Option<String>,
    input_enabled: Option<bool>,
    output_enabled: Option<bool>,
    default: &str,
) -> Option<String> {
    let (action, enabled) = match source {
        Source::Input => (input_action, input_enabled),
        Source::Output => (output_action, output_enabled),
    };
    if enabled == Some(false) {
        return None;
    }
    Some(action.clone().unwrap_or_else(|| default.to_string()))
}

#[derive(Default)]
struct Acc {
    intervened: bool,
    blocked: bool,
}

impl Acc {
    fn take(&mut self, action: &str) {
        match action {
            "BLOCK" => {
                self.intervened = true;
                self.blocked = true;
            }
            "ANONYMIZE" => self.intervened = true,
            _ => {}
        }
    }
}

fn words(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric() && c != '\'').filter(|w| !w.is_empty()).map(str::to_lowercase).collect()
}

/// Whether `phrase` occurs in `text` as whole words, ignoring case.
fn contains_phrase(text: &str, phrase: &str) -> bool {
    let p = words(phrase);
    if p.is_empty() {
        return false;
    }
    let t = words(text);
    t.windows(p.len()).any(|w| w == p.as_slice())
}

const PROFANITY: &[&str] = &["damn", "shit", "fuck", "fucking", "bastard", "asshole", "bitch", "crap", "dick", "piss"];

fn content_phrases(kind: &str) -> &'static [&'static str] {
    match kind {
        "HATE" => &["inferior race", "subhuman", "i hate all", "should be exterminated"],
        "INSULTS" => &["idiot", "stupid", "moron", "loser", "dumb", "pathetic"],
        "SEXUAL" => &["porn", "pornography", "explicit sex", "nude", "nudes"],
        "VIOLENCE" => &["kill", "murder", "bomb", "shoot", "stab", "assault", "torture"],
        "MISCONDUCT" => &["steal", "launder money", "hack into", "make meth", "counterfeit", "shoplift", "evade taxes"],
        "PROMPT_ATTACK" => &[
            "ignore previous instructions",
            "ignore all previous instructions",
            "ignore your instructions",
            "ignore the above",
            "disregard previous instructions",
            "disregard your instructions",
            "jailbreak",
            "do anything now",
            "developer mode",
        ],
        _ => &[],
    }
}

struct PiiPattern {
    kind: &'static str,
    re: Regex,
    check: fn(&str) -> bool,
}

fn always(_: &str) -> bool {
    true
}

fn luhn(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, d)| {
            if i % 2 == 1 {
                let x = d * 2;
                if x > 9 {
                    x - 9
                } else {
                    x
                }
            } else {
                *d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

fn ipv4(s: &str) -> bool {
    s.split('.').all(|o| o.parse::<u8>().is_ok())
}

fn pii_patterns() -> &'static [PiiPattern] {
    static P: OnceLock<Vec<PiiPattern>> = OnceLock::new();
    P.get_or_init(|| {
        let p = |kind, re: &str, check| PiiPattern { kind, re: Regex::new(re).expect("PII pattern"), check };
        vec![
            p("EMAIL", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", always),
            p("URL", r"\bhttps?://[^\s<>\x22]+", always),
            p("AWS_ACCESS_KEY", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", always),
            p("AWS_SECRET_KEY", r"\b[A-Za-z0-9/+]{40}\b", |s| {
                s.chars().any(|c| c.is_ascii_digit()) && s.chars().any(|c| c.is_ascii_uppercase())
            }),
            p("US_SOCIAL_SECURITY_NUMBER", r"\b\d{3}-\d{2}-\d{4}\b", always),
            p("CREDIT_DEBIT_CARD_NUMBER", r"\b\d(?:[ -]?\d){12,18}\b", luhn),
            p("MAC_ADDRESS", r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b", always),
            p("IP_ADDRESS", r"\b\d{1,3}(?:\.\d{1,3}){3}\b", ipv4),
            p("INTERNATIONAL_BANK_ACCOUNT_NUMBER", r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", always),
            p("PHONE", r"(?:\+\d{1,3}[\s.-]?)?\(?\b\d{3}\)?[\s.-]?\d{3}[\s.-]\d{4}\b", always),
        ]
    })
}

/// A span found in a text, to mask or report.
struct Hit {
    start: usize,
    end: usize,
    mask: Option<String>,
}

/// Mask the ANONYMIZE hits of `text`, leftmost first, skipping overlaps.
fn mask(text: &str, mut hits: Vec<Hit>) -> String {
    hits.sort_by_key(|h| (h.start, std::cmp::Reverse(h.end)));
    let mut out = String::new();
    let mut at = 0;
    for h in hits {
        let Some(m) = h.mask else { continue };
        if h.start < at {
            continue;
        }
        out.push_str(&text[at..h.start]);
        out.push_str(&m);
        at = h.end;
    }
    out.push_str(&text[at..]);
    out
}

fn units(chars: i64) -> i64 {
    if chars == 0 {
        0
    } else {
        (chars + 999) / 1000
    }
}

/// Evaluate `blocks` against `policy` (a guardrail version).
pub fn evaluate(policy: &types::GetGuardrailResponse, source: Source, blocks: &[Block]) -> Outcome {
    let guarded: Vec<&Block> = blocks.iter().filter(|b| b.guarded()).collect();
    let total_chars: i64 = blocks.iter().map(|b| b.text.chars().count() as i64).sum();
    let guarded_chars: i64 = guarded.iter().map(|b| b.text.chars().count() as i64).sum();
    let mut acc = Acc::default();
    let mut assessment = Map::new();
    let mut hits: Vec<Vec<Hit>> = guarded.iter().map(|_| Vec::new()).collect();
    let mut usage = Map::new();
    let u = units(guarded_chars);
    let unit = |configured: bool| if configured { u } else { 0 };

    // Denied topics.
    if let Some(tp) = &policy.topic_policy {
        let mut topics = Vec::new();
        for t in &tp.topics {
            let Some(action) =
                action_for(source, &t.input_action, &t.output_action, t.input_enabled, t.output_enabled, "BLOCK")
            else {
                continue;
            };
            let examples = t.examples.clone().unwrap_or_default();
            let found = guarded.iter().any(|b| {
                contains_phrase(&b.text, &t.name)
                    || examples.iter().any(|e| b.text.to_lowercase().contains(&e.to_lowercase()))
            });
            if found {
                acc.take(&action);
                topics.push(
                    json!({"name": t.name, "type": "DENY", "action": blocked_or_none(&action), "detected": true}),
                );
            }
        }
        if !topics.is_empty() {
            assessment.insert("topic_policy".into(), json!({ "topics": topics }));
        }
    }
    usage.insert("topic_policy_units".into(), json!(unit(policy.topic_policy.is_some())));

    // Content filters.
    if let Some(cp) = &policy.content_policy {
        let mut filters = Vec::new();
        for f in cp.filters.iter().flatten() {
            let strength = match source {
                Source::Input => &f.input_strength,
                Source::Output => &f.output_strength,
            };
            if strength == "NONE" {
                continue;
            }
            let Some(action) =
                action_for(source, &f.input_action, &f.output_action, f.input_enabled, f.output_enabled, "BLOCK")
            else {
                continue;
            };
            let found = guarded.iter().any(|b| content_phrases(&f.r#type).iter().any(|p| contains_phrase(&b.text, p)));
            if found {
                acc.take(&action);
                filters.push(json!({
                    "type": f.r#type,
                    "confidence": "HIGH",
                    "filter_strength": strength,
                    "action": blocked_or_none(&action),
                    "detected": true,
                }));
            }
        }
        if !filters.is_empty() {
            assessment.insert("content_policy".into(), json!({ "filters": filters }));
        }
    }
    usage.insert("content_policy_units".into(), json!(unit(policy.content_policy.is_some())));

    // Denied words and managed word lists.
    if let Some(wp) = &policy.word_policy {
        let mut custom = Vec::new();
        let mut managed = Vec::new();
        for w in wp.words.iter().flatten() {
            let Some(action) =
                action_for(source, &w.input_action, &w.output_action, w.input_enabled, w.output_enabled, "BLOCK")
            else {
                continue;
            };
            if guarded.iter().any(|b| contains_phrase(&b.text, &w.text)) {
                acc.take(&action);
                custom.push(json!({"match": w.text, "action": blocked_or_none(&action), "detected": true}));
            }
        }
        for l in wp.managed_word_lists.iter().flatten() {
            let Some(action) =
                action_for(source, &l.input_action, &l.output_action, l.input_enabled, l.output_enabled, "BLOCK")
            else {
                continue;
            };
            for word in PROFANITY {
                if guarded.iter().any(|b| contains_phrase(&b.text, word)) {
                    acc.take(&action);
                    managed.push(json!({
                        "match": word,
                        "type": "PROFANITY",
                        "action": blocked_or_none(&action),
                        "detected": true,
                    }));
                }
            }
        }
        if !custom.is_empty() || !managed.is_empty() {
            assessment.insert("word_policy".into(), json!({ "custom_words": custom, "managed_word_lists": managed }));
        }
    }
    usage.insert("word_policy_units".into(), json!(unit(policy.word_policy.is_some())));

    // Sensitive information.
    if let Some(sp) = &policy.sensitive_information_policy {
        let mut entities = Vec::new();
        let mut regexes = Vec::new();
        for e in sp.pii_entities.iter().flatten() {
            let default = e.action.clone();
            let Some(action) =
                action_for(source, &e.input_action, &e.output_action, e.input_enabled, e.output_enabled, &default)
            else {
                continue;
            };
            for pattern in pii_patterns().iter().filter(|p| p.kind == e.r#type) {
                for (i, b) in guarded.iter().enumerate() {
                    for m in pattern.re.find_iter(&b.text) {
                        if !(pattern.check)(m.as_str()) {
                            continue;
                        }
                        acc.take(&action);
                        entities.push(json!({
                            "match": m.as_str(),
                            "type": e.r#type,
                            "action": pii_action(&action),
                            "detected": true,
                        }));
                        let mask = (action == "ANONYMIZE").then(|| format!("{{{}}}", e.r#type));
                        hits[i].push(Hit { start: m.start(), end: m.end(), mask });
                    }
                }
            }
        }
        for r in sp.regexes.iter().flatten() {
            let default = r.action.clone();
            let Some(action) =
                action_for(source, &r.input_action, &r.output_action, r.input_enabled, r.output_enabled, &default)
            else {
                continue;
            };
            let Ok(re) = Regex::new(&r.pattern) else { continue };
            for (i, b) in guarded.iter().enumerate() {
                for m in re.find_iter(&b.text) {
                    if m.as_str().is_empty() {
                        continue;
                    }
                    acc.take(&action);
                    regexes.push(json!({
                        "name": r.name,
                        "match": m.as_str(),
                        "regex": r.pattern,
                        "action": pii_action(&action),
                        "detected": true,
                    }));
                    let mask = (action == "ANONYMIZE").then(|| format!("{{{}}}", r.name));
                    hits[i].push(Hit { start: m.start(), end: m.end(), mask });
                }
            }
        }
        if !entities.is_empty() || !regexes.is_empty() {
            assessment
                .insert("sensitive_information_policy".into(), json!({ "pii_entities": entities, "regexes": regexes }));
        }
    }
    let pii = policy.sensitive_information_policy.as_ref();
    let has_entities = pii.is_some_and(|p| p.pii_entities.as_ref().is_some_and(|e| !e.is_empty()));
    let has_regexes = pii.is_some_and(|p| p.regexes.as_ref().is_some_and(|r| !r.is_empty()));
    usage.insert("sensitive_information_policy_units".into(), json!(unit(has_regexes)));
    usage.insert("sensitive_information_policy_free_units".into(), json!(unit(has_entities)));

    // Contextual grounding: responses against their grounding source and
    // the query.
    if let Some(gp) = &policy.contextual_grounding_policy {
        let source_text: String = blocks
            .iter()
            .filter(|b| b.qualifiers.iter().any(|q| q == "grounding_source"))
            .map(|b| b.text.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let query: String = blocks
            .iter()
            .filter(|b| b.qualifiers.iter().any(|q| q == "query"))
            .map(|b| b.text.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let response: String = guarded.iter().map(|b| b.text.as_str()).collect::<Vec<_>>().join(" ");
        if source == Source::Output && !source_text.is_empty() {
            let mut filters = Vec::new();
            for f in &gp.filters {
                if f.enabled == Some(false) {
                    continue;
                }
                let score = match f.r#type.as_str() {
                    "GROUNDING" => overlap(&response, &source_text),
                    _ => overlap(&query, &response),
                };
                let detected = score < f.threshold;
                let action = f.action.clone().unwrap_or_else(|| "BLOCK".into());
                if detected {
                    acc.take(&action);
                }
                filters.push(json!({
                    "type": f.r#type,
                    "threshold": f.threshold,
                    "score": (score * 100.0).round() / 100.0,
                    "action": if detected { blocked_or_none(&action) } else { "NONE" },
                    "detected": detected,
                }));
            }
            assessment.insert("contextual_grounding_policy".into(), json!({ "filters": filters }));
        }
    }
    usage.insert("contextual_grounding_policy_units".into(), json!(unit(policy.contextual_grounding_policy.is_some())));

    let coverage = json!({ "text_characters": { "guarded": guarded_chars, "total": total_chars } });
    assessment.insert(
        "invocation_metrics".into(),
        json!({ "guardrail_processing_latency": 1, "usage": Value::Object(usage.clone()), "guardrail_coverage": coverage }),
    );
    let masked = guarded.iter().zip(hits).map(|(b, h)| mask(&b.text, h)).collect();
    let blocked_message = match source {
        Source::Input => policy.blocked_input_messaging.clone(),
        Source::Output => policy.blocked_outputs_messaging.clone(),
    };
    Outcome {
        intervened: acc.intervened,
        blocked: acc.blocked,
        masked,
        blocked_message,
        assessment,
        usage,
        characters_guarded: guarded_chars,
        characters_total: total_chars,
    }
}

fn blocked_or_none(action: &str) -> &'static str {
    if action == "BLOCK" {
        "BLOCKED"
    } else {
        "NONE"
    }
}

fn pii_action(action: &str) -> &'static str {
    match action {
        "BLOCK" => "BLOCKED",
        "ANONYMIZE" => "ANONYMIZED",
        _ => "NONE",
    }
}

/// The share of `a`'s words (longer than three letters) found in `b`.
fn overlap(a: &str, b: &str) -> f64 {
    let a: Vec<String> = words(a).into_iter().filter(|w| w.chars().count() > 3).collect();
    if a.is_empty() {
        return 1.0;
    }
    let b: std::collections::BTreeSet<String> = words(b).into_iter().collect();
    a.iter().filter(|w| b.contains(*w)).count() as f64 / a.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_accepts_test_cards() {
        assert!(luhn("4111 1111 1111 1111"));
        assert!(!luhn("4111 1111 1111 1112"));
    }

    #[test]
    fn phrases_match_whole_words() {
        assert!(contains_phrase("Please IGNORE previous instructions now", "ignore previous instructions"));
        assert!(!contains_phrase("skill", "kill"));
    }

    #[test]
    fn masks_leftmost_first() {
        let text = "mail a@b.co now";
        let hits = vec![Hit { start: 5, end: 11, mask: Some("{EMAIL}".into()) }];
        assert_eq!(mask(text, hits), "mail {EMAIL} now");
    }
}
