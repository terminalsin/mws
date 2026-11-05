//! `multipart/form-data` bodies, as twine uploads them.

pub struct Part {
    pub name: String,
    pub filename: Option<String>,
    pub data: Vec<u8>,
}

impl Part {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.data).into_owned()
    }
}

pub fn boundary(content_type: &str) -> Option<String> {
    let (mime, params) = content_type.split_once(';')?;
    if !mime.trim().eq_ignore_ascii_case("multipart/form-data") {
        return None;
    }
    params.split(';').find_map(|p| {
        let (k, v) = p.trim().split_once('=')?;
        k.trim().eq_ignore_ascii_case("boundary").then(|| v.trim().trim_matches('"').to_string())
    })
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (from..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

fn param(header: &str, key: &str) -> Option<String> {
    header.split(';').find_map(|p| {
        let (k, v) = p.trim().split_once('=')?;
        k.trim().eq_ignore_ascii_case(key).then(|| v.trim().trim_matches('"').to_string())
    })
}

pub fn parse(body: &[u8], boundary: &str) -> Vec<Part> {
    let delim = format!("--{boundary}").into_bytes();
    let mut parts = Vec::new();
    let Some(mut pos) = find(body, &delim, 0) else { return parts };
    loop {
        let start = pos + delim.len();
        if body.get(start..start + 2) == Some(b"--") {
            break;
        }
        let header_start = start + 2;
        let Some(header_end) = find(body, b"\r\n\r\n", header_start) else { break };
        let headers = String::from_utf8_lossy(&body[header_start..header_end]).into_owned();
        let data_start = header_end + 4;
        let mut next_delim = b"\r\n".to_vec();
        next_delim.extend_from_slice(&delim);
        let Some(data_end) = find(body, &next_delim, data_start) else { break };
        let disposition = headers
            .split("\r\n")
            .find(|l| l.to_ascii_lowercase().starts_with("content-disposition:"))
            .unwrap_or("")
            .to_string();
        if let Some(name) = param(&disposition, "name") {
            parts.push(Part {
                name,
                filename: param(&disposition, "filename"),
                data: body[data_start..data_end].to_vec(),
            });
        }
        pos = data_end + 2;
    }
    parts
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_fields_and_files() {
        let body = b"--b\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\npkg\r\n--b\r\nContent-Disposition: form-data; name=\"content\"; filename=\"pkg-1.0.tar.gz\"\r\nContent-Type: application/octet-stream\r\n\r\n\x00\x01\r\n--b--\r\n";
        let parts = super::parse(body, "b");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].text(), "pkg");
        assert_eq!(parts[1].filename.as_deref(), Some("pkg-1.0.tar.gz"));
        assert_eq!(parts[1].data, vec![0, 1]);
        assert_eq!(super::boundary("multipart/form-data; boundary=\"b\"").as_deref(), Some("b"));
    }
}
