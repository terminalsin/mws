use std::collections::BTreeMap;

use percent_encoding::percent_decode_str;

/// Decoded query-string parameters, in request order.
#[derive(Debug, Clone, Default)]
pub struct Query {
    pairs: Vec<(String, String)>,
}

impl Query {
    pub fn parse(raw: Option<&str>) -> Self {
        let pairs = raw.map(|q| form_urlencoded::parse(q.as_bytes()).into_owned().collect()).unwrap_or_default();
        Self { pairs }
    }

    /// First value of `name`.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.pairs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// Every value of `name`, for list-typed query members.
    pub fn get_all(&self, name: &str) -> Vec<&str> {
        self.pairs.iter().filter(|(k, _)| k == name).map(|(_, v)| v.as_str()).collect()
    }

    pub fn contains(&self, name: &str) -> bool {
        self.pairs.iter().any(|(k, _)| k == name)
    }
}

/// Values captured from `{Label}` segments, percent-decoded.
pub type Labels = BTreeMap<&'static str, String>;

/// Match a Smithy URI pattern such as `/2013-04-01/hostedzone/{Id}/rrset`
/// (optionally with a literal query part like `?tagging` or `?x=y`) against a
/// raw request path and query. `{Name+}` labels are greedy and may span
/// several segments.
pub fn match_uri(pattern: &'static str, path: &str, query: &Query) -> Option<Labels> {
    let (path_pat, query_pat) = match pattern.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (pattern, None),
    };
    if let Some(qp) = query_pat {
        for part in qp.split('&').filter(|p| !p.is_empty()) {
            match part.split_once('=') {
                Some((k, v)) => {
                    if query.get(k) != Some(v) {
                        return None;
                    }
                }
                None => {
                    if !query.contains(part) {
                        return None;
                    }
                }
            }
        }
    }
    let pat_segs: Vec<&'static str> = path_pat.trim_start_matches('/').split('/').collect();
    // Older SDK models (botocore's Route 53) add a trailing slash; AWS
    // routes both spellings the same.
    let path = path.trim_start_matches('/').trim_end_matches('/');
    let path_segs: Vec<&str> = if path.is_empty() { vec![""] } else { path.split('/').collect() };
    let mut labels = Labels::new();
    let mut i = 0;
    for (n, seg) in pat_segs.iter().enumerate() {
        if let Some(name) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            if let Some(name) = name.strip_suffix('+') {
                // Greedy: take everything up to the segments the rest of the pattern needs.
                let rest = pat_segs.len() - n - 1;
                if path_segs.len() < i + 1 + rest {
                    return None;
                }
                let end = path_segs.len() - rest;
                let joined = path_segs[i..end].join("/");
                if joined.is_empty() {
                    return None;
                }
                labels.insert(name, decode(&joined));
                i = end;
            } else {
                let value = path_segs.get(i)?;
                if value.is_empty() {
                    return None;
                }
                labels.insert(name, decode(value));
                i += 1;
            }
        } else {
            if path_segs.get(i).map(|s| decode(s)) != Some(seg.to_string()) {
                return None;
            }
            i += 1;
        }
    }
    (i == path_segs.len()).then_some(labels)
}

fn decode(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_literals_and_greedy() {
        let q = Query::default();
        let l = match_uri("/2013-04-01/hostedzone/{Id}/rrset", "/2013-04-01/hostedzone/Z123/rrset", &q).unwrap();
        assert_eq!(l["Id"], "Z123");
        assert!(match_uri("/2013-04-01/hostedzone/{Id}", "/2013-04-01/hostedzone/Z123/rrset", &q).is_none());
        assert!(match_uri("/2013-04-01/hostedzone", "/2013-04-01/hostedzonecount", &q).is_none());
        let l = match_uri("/b/{Key+}/x", "/b/a/b%20c/x", &q).unwrap();
        assert_eq!(l["Key"], "a/b c");
        assert!(match_uri("/b/{Id}", "/b/", &q).is_none());
        assert!(match_uri("/a/{Id}/rrset", "/a/Z1/rrset/", &q).is_some());
    }

    #[test]
    fn query_literals() {
        let q = Query::parse(Some("tagging&x=1"));
        assert!(match_uri("/a?tagging", "/a", &q).is_some());
        assert!(match_uri("/a?x=1", "/a", &q).is_some());
        assert!(match_uri("/a?x=2", "/a", &q).is_none());
        assert!(match_uri("/a?acl", "/a", &q).is_none());
        assert_eq!(Query::parse(Some("a=1&a=2")).get_all("a"), vec!["1", "2"]);
    }
}
