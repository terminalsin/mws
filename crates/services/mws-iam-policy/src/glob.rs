//! Wildcard matching for actions, resources and `*Like` conditions.

/// `*` matches any sequence, `?` any single character. Case-sensitive.
pub fn glob_matches(pattern: &str, value: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let v: Vec<char> = value.chars().collect();
    glob_chars(&p, &v, false)
}

/// Case-insensitive variant, used for actions.
pub fn glob_matches_ci(pattern: &str, value: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let v: Vec<char> = value.chars().collect();
    glob_chars(&p, &v, true)
}

fn glob_chars(p: &[char], v: &[char], ci: bool) -> bool {
    // Iterative wildcard matching with backtracking on the last `*`.
    let (mut pi, mut vi) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    let eq = |a: char, b: char| if ci { a.eq_ignore_ascii_case(&b) } else { a == b };
    while vi < v.len() {
        if pi < p.len() && (p[pi] == '?' || (p[pi] != '*' && eq(p[pi], v[vi]))) {
            pi += 1;
            vi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = vi;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            vi = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// ARN matching: the first five colon-separated components are matched
/// independently, the resource part (which may contain `:` and `/`) as one.
pub fn arn_matches(pattern: &str, arn: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let pp: Vec<&str> = pattern.splitn(6, ':').collect();
    let ap: Vec<&str> = arn.splitn(6, ':').collect();
    if pp.len() != 6 || ap.len() != 6 {
        return glob_matches(pattern, arn);
    }
    pp.iter().zip(ap.iter()).all(|(p, a)| glob_matches(p, a))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globbing() {
        assert!(glob_matches("*", ""));
        assert!(glob_matches("a*c", "abbbc"));
        assert!(glob_matches("a?c", "abc"));
        assert!(!glob_matches("a?c", "ac"));
        assert!(glob_matches_ci("IAM:Get*", "iam:GetUser"));
        assert!(!glob_matches("IAM:Get*", "iam:GetUser"));
    }

    #[test]
    fn arns() {
        assert!(arn_matches("arn:aws:iam::*:user/*", "arn:aws:iam::123456789012:user/team/bob"));
        assert!(!arn_matches("arn:aws:iam::*:user/*", "arn:aws:iam::123456789012:role/bob"));
        assert!(arn_matches("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/a:b/c"));
        assert!(!arn_matches("arn:aws:iam::1*:user/x", "arn:aws:sts::1:user/x"));
    }
}
