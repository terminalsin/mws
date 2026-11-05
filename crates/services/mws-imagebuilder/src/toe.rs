//! AWS Task Orchestrator and Executor (AWSTOE) component documents: what
//! Image Builder runs on build and test instances.
//!
//! A document has phases (`build`, `validate`, `test`) of steps, each an
//! action module. MWS turns each step into a shell script that the build
//! runs inside the instance, the way AWSTOE runs it through the SSM agent.

use std::collections::BTreeMap;

use base64::Engine;
use serde_json::Value;

use crate::generated::types as t;
use crate::yaml;

pub const PHASES: &[&str] = &["build", "validate", "test"];

const ACTIONS: &[&str] = &[
    "ExecuteBash",
    "ExecuteBinary",
    "ExecuteDocument",
    "ExecutePowerShell",
    "CreateFile",
    "AppendFile",
    "DeleteFile",
    "CreateFolder",
    "DeleteFolder",
    "CopyFile",
    "CopyFolder",
    "MoveFile",
    "MoveFolder",
    "ReadFile",
    "ListFiles",
    "SetFileEncoding",
    "SetFileOwner",
    "SetFolderOwner",
    "SetFilePermissions",
    "SetFolderPermissions",
    "S3Download",
    "S3Upload",
    "WebDownload",
    "UpdateOS",
    "Reboot",
    "InstallMSI",
    "UninstallMSI",
    "Assert",
];

/// A component document, checked.
#[derive(Debug, Clone)]
pub struct Document {
    pub doc: Value,
    pub parameters: Vec<t::ComponentParameterDetail>,
    pub phases: Vec<String>,
}

impl Document {
    /// Parse and check a document the way `CreateComponent` does.
    pub fn parse(text: &str) -> Result<Document, String> {
        let doc = yaml::parse(text).map_err(|e| format!("The document is not valid YAML: {e}"))?;
        if !doc.is_object() {
            return Err("The document must be a YAML mapping.".into());
        }
        if doc.get("schemaVersion").and_then(yaml::text).is_none() {
            return Err("The document is missing the required property 'schemaVersion'.".into());
        }
        let phases = doc
            .get("phases")
            .and_then(Value::as_array)
            .filter(|p| !p.is_empty())
            .ok_or("The document must contain at least one phase.")?;
        let mut names = Vec::new();
        for phase in phases {
            let name = phase.get("name").and_then(Value::as_str).ok_or("Every phase must have a name.")?;
            if !PHASES.contains(&name) {
                return Err(format!(
                    "The phase name '{name}' is not valid. Valid phase names are: build, validate, test."
                ));
            }
            let steps = phase
                .get("steps")
                .and_then(Value::as_array)
                .ok_or_else(|| format!("The phase '{name}' must contain a list of steps."))?;
            for step in steps {
                let sname = step.get("name").and_then(Value::as_str).ok_or("Every step must have a name.")?;
                let action = step
                    .get("action")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("The step '{sname}' must have an action."))?;
                if !ACTIONS.contains(&action) {
                    return Err(format!("The action '{action}' of step '{sname}' is not a valid action module."));
                }
            }
            names.push(name.to_string());
        }
        let mut parameters = Vec::new();
        for p in doc.get("parameters").and_then(Value::as_array).into_iter().flatten() {
            let Some((name, spec)) = p.as_object().and_then(|o| o.iter().next()) else {
                return Err("Every parameter must be a mapping of its name to its definition.".into());
            };
            let ty = spec.get("type").and_then(Value::as_str).unwrap_or("string");
            if !matches!(ty, "string" | "stringList") {
                return Err(format!("The type '{ty}' of parameter '{name}' is not valid."));
            }
            parameters.push(t::ComponentParameterDetail {
                name: name.clone(),
                r#type: ty.to_string(),
                default_value: spec.get("default").map(|d| match d {
                    Value::Array(a) => a.iter().filter_map(yaml::text).collect(),
                    other => yaml::text(other).into_iter().collect(),
                }),
                description: spec.get("description").and_then(yaml::text),
            });
        }
        Ok(Document { doc, parameters, phases: names })
    }

    /// `TEST` when the document only tests, `BUILD` otherwise.
    pub fn component_type(&self) -> &'static str {
        if self.phases.iter().all(|p| p == "test") {
            "TEST"
        } else {
            "BUILD"
        }
    }

    /// The steps of `phase` as scripts, with `{{ name }}` references
    /// replaced by parameter and constant values.
    pub fn plan(&self, phase: &str, params: &BTreeMap<String, String>) -> Result<Vec<Step>, String> {
        let mut vars = BTreeMap::new();
        for p in &self.parameters {
            if let Some(d) = &p.default_value {
                vars.insert(p.name.clone(), d.join(","));
            }
        }
        for c in self.doc.get("constants").and_then(Value::as_array).into_iter().flatten() {
            if let Some((name, spec)) = c.as_object().and_then(|o| o.iter().next()) {
                if let Some(v) = spec.get("value").and_then(yaml::text) {
                    vars.insert(name.clone(), v);
                }
            }
        }
        vars.extend(params.clone());
        let mut out = Vec::new();
        for p in self.doc["phases"].as_array().into_iter().flatten() {
            if p.get("name").and_then(Value::as_str) != Some(phase) {
                continue;
            }
            for step in p["steps"].as_array().into_iter().flatten() {
                let step = substitute(step, &vars);
                let name = step["name"].as_str().unwrap_or_default().to_string();
                let action = step["action"].as_str().unwrap_or_default().to_string();
                let script = script_for(&action, &step["inputs"]).map_err(|e| format!("Step '{name}': {e}"))?;
                out.push(Step {
                    name,
                    action,
                    script,
                    on_failure: step.get("onFailure").and_then(Value::as_str).unwrap_or("Abort").to_string(),
                    max_attempts: step.get("maxAttempts").and_then(Value::as_u64).unwrap_or(1).clamp(1, 10) as u32,
                });
            }
        }
        Ok(out)
    }
}

/// One step, ready to run.
#[derive(Debug, Clone)]
pub struct Step {
    pub name: String,
    pub action: String,
    pub script: String,
    /// `Abort`, `Continue` or `Ignore`.
    pub on_failure: String,
    pub max_attempts: u32,
}

/// Replace `{{ name }}` in every string of `v`.
fn substitute(v: &Value, vars: &BTreeMap<String, String>) -> Value {
    match v {
        Value::String(s) => Value::String(replace_vars(s, vars)),
        Value::Array(a) => Value::Array(a.iter().map(|x| substitute(x, vars)).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), substitute(x, vars))).collect()),
        other => other.clone(),
    }
}

pub fn replace_vars(s: &str, vars: &BTreeMap<String, String>) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find("{{") {
        let Some(end) = rest[start..].find("}}") else { break };
        let name = rest[start + 2..start + end].trim();
        out.push_str(&rest[..start]);
        match vars.get(name) {
            Some(v) => out.push_str(v),
            None => out.push_str(&rest[start..start + end + 2]),
        }
        rest = &rest[start + end + 2..];
    }
    out.push_str(rest);
    out
}

/// Quote for a POSIX shell.
pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn str_of(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(yaml::text)
}

fn items(inputs: &Value) -> Vec<Value> {
    match inputs {
        Value::Array(a) => a.clone(),
        Value::Object(_) => vec![inputs.clone()],
        _ => Vec::new(),
    }
}

fn need(v: &Value, key: &str) -> Result<String, String> {
    str_of(v, key).ok_or_else(|| format!("the input '{key}' is required"))
}

/// The shell script for one action module.
fn script_for(action: &str, inputs: &Value) -> Result<String, String> {
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s.as_bytes());
    let mut lines: Vec<String> = Vec::new();
    match action {
        "ExecuteBash" => {
            let commands =
                inputs.get("commands").and_then(Value::as_array).ok_or("the input 'commands' is required")?;
            lines.extend(commands.iter().filter_map(yaml::text));
        }
        "ExecuteBinary" => {
            let path = need(inputs, "path")?;
            let args: Vec<String> = inputs
                .get("arguments")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(yaml::text)
                .map(|a| sh_quote(&a))
                .collect();
            lines.push(format!("{} {}", sh_quote(&path), args.join(" ")));
        }
        "CreateFile" | "AppendFile" => {
            for f in items(inputs) {
                let path = need(&f, "path")?;
                let content = str_of(&f, "content").unwrap_or_default();
                let redirect = if action == "AppendFile" { ">>" } else { ">" };
                lines.push(format!("mkdir -p \"$(dirname {p})\"", p = sh_quote(&path)));
                if action == "CreateFile" && f.get("overwrite").and_then(Value::as_bool) == Some(false) {
                    lines.push(format!(
                        "if [ -e {p} ]; then echo 'File {path} already exists' >&2; exit 1; fi",
                        p = sh_quote(&path)
                    ));
                }
                lines.push(format!(
                    "printf '%s' {} | base64 -d {redirect} {}",
                    sh_quote(&b64(&content)),
                    sh_quote(&path)
                ));
                if let Some(perm) = str_of(&f, "permissions") {
                    lines.push(format!("chmod {} {}", sh_quote(&perm), sh_quote(&path)));
                }
                if let Some(owner) = str_of(&f, "owner") {
                    let group = str_of(&f, "group").map(|g| format!(":{g}")).unwrap_or_default();
                    lines.push(format!("chown {} {}", sh_quote(&format!("{owner}{group}")), sh_quote(&path)));
                }
            }
        }
        "DeleteFile" => {
            for f in items(inputs) {
                lines.push(format!("rm -f {}", sh_quote(&need(&f, "path")?)));
            }
        }
        "CreateFolder" => {
            for f in items(inputs) {
                let path = need(&f, "path")?;
                lines.push(format!("mkdir -p {}", sh_quote(&path)));
                if let Some(perm) = str_of(&f, "permissions") {
                    lines.push(format!("chmod {} {}", sh_quote(&perm), sh_quote(&path)));
                }
            }
        }
        "DeleteFolder" => {
            for f in items(inputs) {
                let path = need(&f, "path")?;
                if f.get("force").and_then(Value::as_bool) == Some(true) {
                    lines.push(format!("rm -rf {}", sh_quote(&path)));
                } else {
                    lines.push(format!("rmdir {}", sh_quote(&path)));
                }
            }
        }
        "CopyFile" | "CopyFolder" | "MoveFile" | "MoveFolder" => {
            for f in items(inputs) {
                let src = need(&f, "source")?;
                let dst = need(&f, "destination")?;
                lines.push(format!("mkdir -p \"$(dirname {})\"", sh_quote(&dst)));
                let cmd = if action.starts_with("Copy") { "cp -r" } else { "mv" };
                lines.push(format!("{cmd} {} {}", sh_quote(&src), sh_quote(&dst)));
            }
        }
        "ReadFile" => {
            lines.push(format!("cat {}", sh_quote(&need(inputs, "path")?)));
        }
        "ListFiles" => {
            for f in items(inputs) {
                lines.push(format!("ls -la {}", sh_quote(&need(&f, "path")?)));
            }
        }
        "SetFileEncoding" | "Assert" => lines.push("true".into()),
        "SetFileOwner" | "SetFolderOwner" => {
            for f in items(inputs) {
                let owner = need(&f, "owner")?;
                let group = str_of(&f, "group").map(|g| format!(":{g}")).unwrap_or_default();
                let r = if action == "SetFolderOwner" { "-R " } else { "" };
                lines.push(format!(
                    "chown {r}{} {}",
                    sh_quote(&format!("{owner}{group}")),
                    sh_quote(&need(&f, "path")?)
                ));
            }
        }
        "SetFilePermissions" | "SetFolderPermissions" => {
            for f in items(inputs) {
                let r = if action == "SetFolderPermissions" { "-R " } else { "" };
                lines.push(format!(
                    "chmod {r}{} {}",
                    sh_quote(&need(&f, "permissions")?),
                    sh_quote(&need(&f, "path")?)
                ));
            }
        }
        "WebDownload" => {
            for f in items(inputs) {
                let src = need(&f, "source")?;
                let dst = need(&f, "destination")?;
                lines.push(format!("mkdir -p \"$(dirname {})\"", sh_quote(&dst)));
                lines.push(format!(
                    "if command -v curl >/dev/null 2>&1; then curl -fsSL -o {d} {s}; else wget -q -O {d} {s}; fi",
                    d = sh_quote(&dst),
                    s = sh_quote(&src)
                ));
            }
        }
        "S3Download" | "S3Upload" => {
            for f in items(inputs) {
                let src = need(&f, "source")?;
                let dst = need(&f, "destination")?;
                let recursive =
                    if f.get("recurse").and_then(Value::as_bool) == Some(true) { " --recursive" } else { "" };
                lines.push(format!("aws s3 cp{recursive} {} {}", sh_quote(&src), sh_quote(&dst)));
            }
        }
        "UpdateOS" => {
            lines.push(
                "if command -v dnf >/dev/null 2>&1; then dnf -y upgrade; \
                 elif command -v yum >/dev/null 2>&1; then yum -y update; \
                 elif command -v apt-get >/dev/null 2>&1; then export DEBIAN_FRONTEND=noninteractive; apt-get update && apt-get -y upgrade; \
                 elif command -v zypper >/dev/null 2>&1; then zypper -n update; \
                 elif command -v apk >/dev/null 2>&1; then apk upgrade --no-cache; fi"
                    .into(),
            );
        }
        // The instance keeps running; the next step continues.
        "Reboot" => lines.push("echo 'Reboot requested'".into()),
        "ExecutePowerShell" | "InstallMSI" | "UninstallMSI" => {
            return Err(format!("the action module '{action}' is only supported on Windows"));
        }
        "ExecuteDocument" => return Err("the action module 'ExecuteDocument' is not supported by MWS".into()),
        other => return Err(format!("the action module '{other}' is not valid")),
    }
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r#"
name: hello
schemaVersion: 1.0
parameters:
  - Greeting:
      type: string
      default: hello
phases:
  - name: build
    steps:
      - name: Say
        action: ExecuteBash
        inputs:
          commands:
            - echo "{{ Greeting }} world" > /tmp/out
      - name: File
        action: CreateFile
        inputs:
          - path: /etc/motd
            content: "it's {{Greeting}}"
  - name: test
    steps:
      - name: Check
        action: ExecuteBash
        inputs:
          commands: ["test -f /tmp/out"]
"#;

    #[test]
    fn plans_steps() {
        let d = Document::parse(DOC).unwrap();
        assert_eq!(d.component_type(), "BUILD");
        assert_eq!(d.parameters[0].name, "Greeting");
        let mut p = BTreeMap::new();
        p.insert("Greeting".to_string(), "hi".to_string());
        let steps = d.plan("build", &p).unwrap();
        assert_eq!(steps.len(), 2);
        assert!(steps[0].script.contains("echo \"hi world\""));
        assert!(steps[1].script.contains("base64 -d > '/etc/motd'"));
        assert_eq!(d.plan("test", &p).unwrap().len(), 1);
    }

    #[test]
    fn rejects_bad_documents() {
        assert!(Document::parse("schemaVersion: 1.0\nphases: []").is_err());
        assert!(Document::parse("schemaVersion: 1.0\nphases:\n  - name: deploy\n    steps: []").is_err());
        assert!(Document::parse("phases:\n  - name: build\n    steps: []").is_err());
        let bad = "schemaVersion: 1.0\nphases:\n  - name: build\n    steps:\n      - name: x\n        action: Nope\n";
        assert!(Document::parse(bad).is_err());
    }
}
