//! Smithy `@pattern` values are ECMAScript regular expressions. This
//! translates the common differences to the `regex` crate's syntax, and
//! reports patterns it cannot support (e.g. look-around).

/// Returns the translated pattern, or `None` if `regex` cannot express it.
pub fn translate(pattern: &str) -> Option<String> {
    translate_syntax(pattern).filter(|out| regex::Regex::new(out).is_ok())
}

/// For patterns `regex` cannot express (look-around, back-references):
/// the translated pattern for `fancy-regex`, which backtracks.
///
/// `.` matches newlines here: these patterns guard free text (policy
/// documents, descriptions) that services accept across lines.
pub fn translate_fancy(pattern: &str) -> Option<String> {
    translate_syntax(pattern).map(|out| format!("(?s){out}")).filter(|out| fancy_regex::Regex::new(out).is_ok())
}

fn translate_syntax(pattern: &str) -> Option<String> {
    // ECMAScript `\w`, `\d`, `\s` are ASCII-only; in `regex` they are Unicode.
    let mut out = String::with_capacity(pattern.len() + 16);
    let mut in_class = false;
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let n = chars.next()?;
                let (cls, neg) = match n {
                    'w' => ("0-9A-Za-z_", false),
                    'W' => ("0-9A-Za-z_", true),
                    'd' => ("0-9", false),
                    'D' => ("0-9", true),
                    _ => {
                        out.push('\\');
                        out.push(n);
                        continue;
                    }
                };
                if in_class {
                    if neg {
                        // A negated class inside a class cannot be inlined.
                        return None;
                    }
                    out.push_str(cls);
                } else {
                    out.push('[');
                    if neg {
                        out.push('^');
                    }
                    out.push_str(cls);
                    out.push(']');
                }
            }
            '[' if !in_class => {
                in_class = true;
                out.push(c);
                if chars.peek() == Some(&'^') {
                    out.push(chars.next().unwrap());
                }
                if chars.peek() == Some(&']') {
                    out.push_str("\\]");
                    chars.next();
                }
            }
            ']' if in_class => {
                in_class = false;
                out.push(c);
            }
            c => out.push(c),
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_ecmascript_classes() {
        let p = translate(r"^[\w+=,.@-]+$").unwrap();
        let re = regex::Regex::new(&p).unwrap();
        assert!(re.is_match("bob+admin@x"));
        assert!(!re.is_match("bøb"), "\\w is ASCII-only in ECMAScript");
        assert!(translate(r"^[\u0009\u000A\u000D -ÿ]+$").is_some());
        assert!(translate(r"^[\p{L}\p{Z}\p{N}_.:/=+\-@]*$").is_some());
        assert!(translate(r"^[a-z0-9]([a-z0-9]|-(?!-)){1,61}[a-z0-9]$").is_none(), "look-ahead is unsupported");
        assert!(translate_fancy(r"^[a-z0-9]([a-z0-9]|-(?!-)){1,61}[a-z0-9]$").is_some());
    }
}
