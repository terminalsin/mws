//! DNS name handling as Route 53 does it: names are case-insensitive, stored
//! lowercase with a trailing dot, and returned with characters outside
//! `[a-z0-9-_.]` escaped as `\ooo` octal (so `*` reads back as `\052`).

/// Normalize a name from a request: unescape `\ooo`, lowercase, add the
/// trailing dot, and check label and name lengths. `None` if invalid.
pub fn normalize(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let mut out = String::with_capacity(raw.len() + 1);
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let digits: String = chars.clone().take(3).collect();
            if digits.len() == 3 && digits.chars().all(|d| d.is_digit(8)) {
                let code = u32::from_str_radix(&digits, 8).ok()?;
                out.push(char::from_u32(code)?.to_ascii_lowercase());
                for _ in 0..3 {
                    chars.next();
                }
                continue;
            }
            out.push(chars.next()?.to_ascii_lowercase());
            continue;
        }
        if c.is_whitespace() || !c.is_ascii() {
            return None;
        }
        out.push(c.to_ascii_lowercase());
    }
    if out == "." {
        return Some(out);
    }
    let bare = out.strip_suffix('.').unwrap_or(&out).to_string();
    if bare.is_empty() || bare.len() > 253 {
        return None;
    }
    if bare.split('.').any(|l| l.is_empty() || l.len() > 63) {
        return None;
    }
    Some(format!("{bare}."))
}

/// A stored name as Route 53 returns it.
pub fn display(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.') {
            out.push(c);
        } else {
            out.push_str(&format!("\\{:03o}", c as u32));
        }
    }
    out
}

/// Sort key: labels reversed, so `www.example.com.` sorts as
/// `com.example.www`, which is how Route 53 orders record sets.
pub fn sort_key(name: &str) -> String {
    let bare = name.strip_suffix('.').unwrap_or(name);
    bare.split('.').rev().collect::<Vec<_>>().join(".")
}

/// Whether `name` is the zone apex or below it.
pub fn in_zone(name: &str, zone: &str) -> bool {
    name == zone || name.ends_with(&format!(".{zone}"))
}

/// The name without its trailing dot (for condition keys).
pub fn bare(name: &str) -> &str {
    name.strip_suffix('.').unwrap_or(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_and_escapes() {
        assert_eq!(normalize("WWW.Example.com").as_deref(), Some("www.example.com."));
        assert_eq!(normalize("\\052.example.com.").as_deref(), Some("*.example.com."));
        assert_eq!(display("*.example.com."), "\\052.example.com.");
        assert!(normalize("a..b").is_none());
        assert!(normalize(&format!("{}.com", "a".repeat(64))).is_none());
        assert_eq!(sort_key("www.example.com."), "com.example.www");
        assert!(in_zone("a.example.com.", "example.com."));
        assert!(!in_zone("badexample.com.", "example.com."));
    }
}
