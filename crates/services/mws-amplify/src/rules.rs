//! Amplify's rewrite and redirect rules (`customRules`).
//!
//! A source is a path pattern (`/docs/<*>`, `/users/<id>/profile`), a full
//! URL pattern (`https://example.com/<*>`), or a regular expression
//! written `</regex/>`. `<*>` matches anything, `<name>` one path segment,
//! and both can be used in the target.

use fancy_regex::Regex;

use crate::generated::types;

#[derive(Debug)]
pub struct Rule {
    matcher: Regex,
    /// The source names a host (`https://...`), so it matches the full URL.
    full_url: bool,
    /// Placeholder names in capture order.
    placeholders: Vec<String>,
    regex_source: bool,
    pub target: String,
    pub status: String,
    pub condition: Option<String>,
}

pub struct Match {
    pub target: String,
}

impl Rule {
    pub fn parse(rule: &types::CustomRule) -> Result<Rule, String> {
        let source = rule.source.trim();
        let status = rule.status.clone().unwrap_or_else(|| "200".into());
        let condition = rule.condition.clone().filter(|c| !c.is_empty());
        if let Some(re) = source.strip_prefix("</").and_then(|s| s.strip_suffix("/>")) {
            let matcher = Regex::new(re).map_err(|e| format!("Invalid regular expression in source {source}: {e}"))?;
            return Ok(Rule {
                matcher,
                full_url: false,
                placeholders: Vec::new(),
                regex_source: true,
                target: rule.target.clone(),
                status,
                condition,
            });
        }
        let mut pattern = String::from("^");
        let mut placeholders = Vec::new();
        let mut rest = source;
        while let Some(start) = rest.find('<') {
            let Some(len) = rest[start..].find('>') else { break };
            pattern.push_str(&fancy_regex::escape(&rest[..start]));
            let name = &rest[start + 1..start + len];
            if name == "*" {
                pattern.push_str("(.*)");
            } else {
                pattern.push_str("([^/]+)");
            }
            placeholders.push(name.to_string());
            rest = &rest[start + len + 1..];
        }
        pattern.push_str(&fancy_regex::escape(rest));
        // `/docs` also matches `/docs/`.
        pattern.push_str("/?$");
        let matcher = Regex::new(&pattern).map_err(|e| format!("Invalid source {source}: {e}"))?;
        Ok(Rule {
            matcher,
            full_url: source.starts_with("http://") || source.starts_with("https://"),
            placeholders,
            regex_source: false,
            target: rule.target.clone(),
            status,
            condition,
        })
    }

    /// Match the request (`host` without port, `path` with its leading
    /// `/`) and work out the target.
    pub fn matches(&self, host: &str, path: &str) -> Option<Match> {
        // Country conditions need the viewer's location, which a local
        // request does not have.
        if self.condition.is_some() {
            return None;
        }
        let subject = if self.full_url { format!("https://{host}{path}") } else { path.to_string() };
        let caps = self.matcher.captures(&subject).ok().flatten()?;
        if self.regex_source {
            return Some(Match { target: self.target.clone() });
        }
        let mut target = self.target.clone();
        for (i, name) in self.placeholders.iter().enumerate() {
            let value = caps.get(i + 1).map(|m| m.as_str()).unwrap_or("");
            target = target.replace(&format!("<{name}>"), value);
        }
        Some(Match { target })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(source: &str, target: &str, status: &str) -> Rule {
        Rule::parse(&types::CustomRule {
            source: source.into(),
            target: target.into(),
            status: Some(status.into()),
            condition: None,
        })
        .unwrap()
    }

    #[test]
    fn placeholders_and_wildcards() {
        let r = rule("/docs/<*>", "/documents/<*>", "301");
        assert_eq!(r.matches("h", "/docs/a/b.html").unwrap().target, "/documents/a/b.html");
        assert!(r.matches("h", "/other").is_none());
        let r = rule("/users/<id>/profile", "/profile.html?id=<id>", "200");
        assert_eq!(r.matches("h", "/users/42/profile").unwrap().target, "/profile.html?id=42");
        assert!(r.matches("h", "/users/4/2/profile").is_none());
    }

    #[test]
    fn spa_regex_rule() {
        let r = rule(
            "</^[^.]+$|\\.(?!(css|gif|ico|jpg|js|png|txt|svg|woff|woff2|ttf|map|json|webp)$)([^.]+$)/>",
            "/index.html",
            "200",
        );
        assert!(r.matches("h", "/dashboard/settings").is_some());
        assert!(r.matches("h", "/app.js").is_none());
    }

    #[test]
    fn full_url_sources() {
        let r = rule("https://example.com", "https://www.example.com", "301");
        assert!(r.matches("example.com", "/").is_some());
        assert!(r.matches("www.example.com", "/").is_none());
    }
}
