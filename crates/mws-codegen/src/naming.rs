/// `SAMLProviderArn` -> `saml_provider_arn`, `MFADevices` -> `mfa_devices`.
pub fn snake_case(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut out = String::with_capacity(name.len() + 4);
    for (i, &c) in chars.iter().enumerate() {
        if c.is_ascii_uppercase() {
            let prev = if i > 0 { Some(chars[i - 1]) } else { None };
            let next = chars.get(i + 1).copied();
            let boundary = match prev {
                None => false,
                Some(p) if p.is_ascii_lowercase() || p.is_ascii_digit() => true,
                Some(p) if p.is_ascii_uppercase() => next.is_some_and(|n| n.is_ascii_lowercase()),
                _ => false,
            };
            if boundary && !out.ends_with('_') {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    out
}

const KEYWORDS: &[&str] = &[
    "as", "async", "await", "break", "const", "continue", "dyn", "else", "enum", "extern", "false", "fn", "for", "if",
    "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "static", "struct", "trait",
    "true", "type", "unsafe", "use", "where", "while", "abstract", "become", "box", "do", "final", "gen", "macro",
    "override", "priv", "try", "typeof", "unsized", "virtual", "yield",
];

/// A field or function identifier that is safe to emit.
pub fn ident(snake: &str) -> String {
    match snake {
        "self" | "super" | "crate" | "Self" => format!("{snake}_"),
        s if KEYWORDS.contains(&s) => format!("r#{s}"),
        s if s.starts_with(|c: char| c.is_ascii_digit()) => format!("_{s}"),
        s => s.to_string(),
    }
}

/// AWS validation messages name members in lower camel case.
pub fn lower_camel(name: &str) -> String {
    let mut c = name.chars();
    match c.next() {
        Some(f) => f.to_lowercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// A Rust type name for a shape.
pub fn type_name(local: &str) -> String {
    let mut out = String::new();
    let mut upper = true;
    for c in local.chars() {
        if c.is_ascii_alphanumeric() {
            if upper {
                out.extend(c.to_uppercase());
                upper = false;
            } else {
                out.push(c);
            }
        } else {
            upper = true;
        }
    }
    if out == "Self" {
        out.push('_');
    }
    out
}

pub fn rust_str(s: &str) -> String {
    format!("{s:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snake_case_handles_acronyms() {
        assert_eq!(snake_case("UserName"), "user_name");
        assert_eq!(snake_case("SAMLProviderArn"), "saml_provider_arn");
        assert_eq!(snake_case("MFADevices"), "mfa_devices");
        assert_eq!(snake_case("OpenIDConnectProviderArn"), "open_id_connect_provider_arn");
        assert_eq!(snake_case("GetAccountAuthorizationDetails"), "get_account_authorization_details");
        assert_eq!(snake_case("AccessKeyId"), "access_key_id");
        assert_eq!(snake_case("Base32StringSeed"), "base32_string_seed");
    }

    #[test]
    fn idents_escape_keywords() {
        assert_eq!(ident("type"), "r#type");
        assert_eq!(ident("self"), "self_");
    }
}
