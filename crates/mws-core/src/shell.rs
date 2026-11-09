//! A shell and file browser over anything that can run a script: the
//! console's terminal and file explorer for compute resources (instances,
//! containers). A service authorizes the caller, finds the resource and
//! hands a [`Shell`] to [`serve`] with the rest of the path:
//!
//! | Request | Effect |
//! | --- | --- |
//! | `POST exec` `{"command", "cwd"?}` | Run a command: `{"stdout", "stderr", "exitCode", "cwd"}` (the working directory after it, so `cd` carries over). |
//! | `GET files?path=` | List a directory: `{"path", "entries": [{"name", "type": "file"\|"dir"\|"link", "size", "modified", "mode"}]}`. |
//! | `GET file?path=` | A file's bytes (at most [`MAX_READ`]; `x-mws-truncated: true` when cut). |
//! | `PUT file?path=` | Write the body to a file, creating its directory. |
//! | `DELETE file?path=` | Remove a file or directory. |
//! | `POST dir?path=` | Make a directory. |

use base64::Engine as _;
use bytes::Bytes;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{HttpRequest, HttpResponse};

/// The most of a file `GET file` returns.
pub const MAX_READ: usize = 8 * 1024 * 1024;

/// What a script printed and how it ended.
#[derive(Debug, Clone, Default)]
pub struct Output {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Something that runs `sh` scripts as root, with optional standard input.
#[async_trait::async_trait]
pub trait Shell: Send + Sync {
    async fn run(&self, script: &str, stdin: Option<Bytes>) -> Result<Output, String>;
}

/// `s` as one single-quoted shell word.
pub fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

const MARK: char = '\u{1e}';

/// The script for one terminal command run in `cwd`. It reports the exit
/// status and the working directory after a marker on the last line.
pub fn exec_script(command: &str, cwd: Option<&str>) -> String {
    let cd = match cwd.filter(|c| !c.is_empty()) {
        Some(c) => format!("cd {} 2>/dev/null || cd \"$HOME\" 2>/dev/null || cd /", quote(c)),
        None => "cd \"$HOME\" 2>/dev/null || cd /".to_string(),
    };
    // An EXIT trap, so `exit 3` still reports its status and directory.
    format!("{cd}\ntrap '__mws_rc=$?; printf \"\\n\\036%s\\036%s\" \"$__mws_rc\" \"$PWD\"' EXIT\n{command}\n")
}

/// Split a terminal command's output into what it printed, its exit code
/// and the directory it ended in.
pub fn parse_exec(out: &Output) -> (String, i32, Option<String>) {
    let s = &out.stdout;
    match s.rfind(MARK).and_then(|end| s[..end].rfind(MARK).map(|start| (start, end))) {
        Some((start, end)) => {
            let printed = s[..start].strip_suffix('\n').unwrap_or(&s[..start]).to_string();
            let code = s[start + 1..end].trim().parse().unwrap_or(out.exit_code);
            (printed, code, Some(s[end + 1..].to_string()))
        }
        None => (s.clone(), out.exit_code, None),
    }
}

/// The script that lists `path`: one `type|size|mtime|mode|name` line per entry.
pub fn list_script(path: &str) -> String {
    format!(
        r#"P={p}
[ -d "$P" ] || {{ echo "$P: not a directory" >&2; exit 2; }}
cd "$P" || exit 1
for f in * .[!.]* ..?*; do
  [ -e "$f" ] || [ -L "$f" ] || continue
  if [ -L "$f" ]; then t=link; elif [ -d "$f" ]; then t=dir; else t=file; fi
  s=$(stat -c '%s|%Y|%a' "$f" 2>/dev/null || echo '0|0|')
  printf '%s|%s|%s\n' "$t" "$s" "$f"
done
"#,
        p = quote(path)
    )
}

/// Entries from [`list_script`]'s output, directories first.
pub fn parse_list(stdout: &str) -> Vec<Value> {
    let mut entries: Vec<(bool, String, Value)> = stdout
        .lines()
        .filter_map(|l| {
            let mut parts = l.splitn(5, '|');
            let kind = parts.next()?;
            let size: u64 = parts.next()?.parse().unwrap_or(0);
            let modified: i64 = parts.next()?.parse().unwrap_or(0);
            let mode = parts.next()?.to_string();
            let name = parts.next()?.to_string();
            let v = json!({ "name": name, "type": kind, "size": size, "modified": modified, "mode": mode });
            Some((kind != "dir", name.to_lowercase(), v))
        })
        .collect();
    entries.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
    entries.into_iter().map(|(_, _, v)| v).collect()
}

fn read_script(path: &str) -> String {
    format!(
        r#"P={p}
[ -f "$P" ] || {{ echo "$P: not a file" >&2; exit 2; }}
stat -c '%s' "$P"
head -c {max} "$P" | base64
"#,
        p = quote(path),
        max = MAX_READ
    )
}

fn write_script(path: &str) -> String {
    format!(r#"P={p}; mkdir -p "$(dirname "$P")" && cat > "$P""#, p = quote(path))
}

fn json_response(status: u16, body: Value) -> HttpResponse {
    http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Bytes::from(body.to_string()))
        .expect("valid response")
}

/// `{"message": ...}` with `status`.
pub fn error(status: u16, message: impl Into<String>) -> HttpResponse {
    json_response(status, json!({ "message": message.into() }))
}

fn query_path(request: &HttpRequest) -> Option<String> {
    let q = request.uri().query()?;
    q.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == "path").then(|| percent_decode(v))
    })
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex =
            (bytes[i] == b'%').then(|| s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok())).flatten();
        match (bytes[i], hex) {
            (b'%', Some(b)) => {
                out.push(b);
                i += 3;
            }
            (b'+', _) => {
                out.push(b' ');
                i += 1;
            }
            (b, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn failure(out: &Output) -> HttpResponse {
    let msg = out.stderr.trim();
    let status = if msg.contains("not a directory") || msg.contains("not a file") || msg.contains("No such file") {
        404
    } else {
        400
    };
    error(status, if msg.is_empty() { format!("The command exited with {}.", out.exit_code) } else { msg.to_string() })
}

#[derive(Deserialize)]
struct ExecBody {
    command: String,
    #[serde(default)]
    cwd: Option<String>,
}

/// Serve `rest` (the path after the resource, such as `exec` or `files`)
/// with `shell`.
pub async fn serve(shell: &dyn Shell, request: &HttpRequest, rest: &str) -> HttpResponse {
    let method = request.method().clone();
    let path = query_path(request).filter(|p| !p.is_empty());
    let run = |script: String, stdin: Option<Bytes>| async move { shell.run(&script, stdin).await };
    match (rest.trim_matches('/'), method) {
        ("exec", http::Method::POST) => {
            let body: ExecBody = match serde_json::from_slice(request.body()) {
                Ok(b) => b,
                Err(e) => return error(400, format!("Expected {{\"command\", \"cwd\"?}}: {e}")),
            };
            match run(exec_script(&body.command, body.cwd.as_deref()), None).await {
                Ok(out) => {
                    let (stdout, code, cwd) = parse_exec(&out);
                    json_response(200, json!({ "stdout": stdout, "stderr": out.stderr, "exitCode": code, "cwd": cwd }))
                }
                Err(e) => error(409, e),
            }
        }
        ("files", http::Method::GET) => {
            let p = path.unwrap_or_else(|| "/".into());
            match run(list_script(&p), None).await {
                Ok(out) if out.exit_code == 0 => {
                    json_response(200, json!({ "path": p, "entries": parse_list(&out.stdout) }))
                }
                Ok(out) => failure(&out),
                Err(e) => error(409, e),
            }
        }
        ("file", m) => {
            let Some(p) = path else { return error(400, "Pass the file as ?path=.") };
            match m {
                http::Method::GET => match run(read_script(&p), None).await {
                    Ok(out) if out.exit_code == 0 => {
                        let (size, b64) = out.stdout.split_once('\n').unwrap_or((out.stdout.as_str(), ""));
                        let size: usize = size.trim().parse().unwrap_or(0);
                        let clean: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
                        let data = match base64::engine::general_purpose::STANDARD.decode(clean) {
                            Ok(d) => d,
                            Err(e) => return error(500, format!("Could not read {p}: {e}")),
                        };
                        http::Response::builder()
                            .status(200)
                            .header("content-type", "application/octet-stream")
                            .header("x-mws-size", size.to_string())
                            .header("x-mws-truncated", (size > data.len()).to_string())
                            .body(Bytes::from(data))
                            .expect("valid response")
                    }
                    Ok(out) => failure(&out),
                    Err(e) => error(409, e),
                },
                http::Method::PUT | http::Method::POST => {
                    match run(write_script(&p), Some(request.body().clone())).await {
                        Ok(out) if out.exit_code == 0 => {
                            json_response(200, json!({ "path": p, "size": request.body().len() }))
                        }
                        Ok(out) => failure(&out),
                        Err(e) => error(409, e),
                    }
                }
                http::Method::DELETE => {
                    if p.trim_end_matches('/').is_empty() {
                        return error(400, "Refusing to remove /.");
                    }
                    match run(format!("rm -rf -- {}", quote(&p)), None).await {
                        Ok(out) if out.exit_code == 0 => json_response(200, json!({ "path": p })),
                        Ok(out) => failure(&out),
                        Err(e) => error(409, e),
                    }
                }
                _ => error(405, "Use GET, PUT or DELETE."),
            }
        }
        ("dir", http::Method::POST) => {
            let Some(p) = path else { return error(400, "Pass the directory as ?path=.") };
            match run(format!("mkdir -p -- {}", quote(&p)), None).await {
                Ok(out) if out.exit_code == 0 => json_response(200, json!({ "path": p })),
                Ok(out) => failure(&out),
                Err(e) => error(409, e),
            }
        }
        (other, m) => error(404, format!("No {m} {other} here: use exec, files, file or dir.")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_single_quotes() {
        assert_eq!(quote("it's"), r"'it'\''s'");
    }

    #[test]
    fn exec_reports_status_after_exit() {
        let script = exec_script("cd /tmp; echo hi; exit 3", None);
        let out = std::process::Command::new("sh").arg("-c").arg(&script).output().unwrap();
        let out = Output {
            exit_code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8(out.stdout).unwrap(),
            stderr: String::new(),
        };
        assert_eq!(parse_exec(&out), ("hi\n".to_string(), 3, Some("/tmp".to_string())));
    }

    #[test]
    fn parses_exec_markers() {
        let out = Output { exit_code: 0, stdout: "hello\n\n\u{1e}3\u{1e}/tmp".into(), stderr: String::new() };
        assert_eq!(parse_exec(&out), ("hello\n".to_string(), 3, Some("/tmp".to_string())));
    }

    #[test]
    fn lists_directories_first() {
        let v = parse_list("file|5|10|644|b.txt\ndir|0|10|755|z\nlink|3|10|777|a|b\n");
        let names: Vec<_> = v.iter().map(|e| e["name"].as_str().unwrap().to_string()).collect();
        assert_eq!(names, ["z", "a|b", "b.txt"]);
    }

    #[test]
    fn decodes_paths() {
        assert_eq!(percent_decode("%2Fetc%2Fmy%20file+x"), "/etc/my file x");
    }
}
