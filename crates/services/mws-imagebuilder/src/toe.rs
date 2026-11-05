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

    /// The steps of `phase`, with `{{ name }}` references replaced by
    /// parameter and constant values and loops unrolled. References to
    /// earlier steps' outputs (`{{ build.Step.outputs.stdout }}`) stay
    /// until the step runs ([`Step::script`]).
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
            for raw in p["steps"].as_array().into_iter().flatten() {
                let name = raw["name"].as_str().unwrap_or_default().to_string();
                let iterations = match raw.get("loop") {
                    Some(l) => loop_iterations(&substitute(l, &vars)).map_err(|e| format!("Step '{name}': {e}"))?,
                    None => vec![None],
                };
                for iteration in iterations {
                    let mut step_vars = vars.clone();
                    if let Some((loop_name, index, value)) = &iteration {
                        for prefix in std::iter::once("loop").chain(loop_name.as_deref()) {
                            step_vars.insert(format!("{prefix}.index"), index.to_string());
                            step_vars.insert(format!("{prefix}.value"), value.clone());
                        }
                    }
                    let step = substitute(raw, &step_vars);
                    let action = step["action"].as_str().unwrap_or_default().to_string();
                    let inputs = step.get("inputs").cloned().unwrap_or(Value::Null);
                    let planned = Step {
                        name: name.clone(),
                        action,
                        inputs,
                        iteration: iteration.as_ref().map(|(_, _, v)| v.clone()),
                        on_failure: step.get("onFailure").and_then(Value::as_str).unwrap_or("Abort").to_string(),
                        max_attempts: step.get("maxAttempts").and_then(Value::as_u64).unwrap_or(1).clamp(1, 10) as u32,
                    };
                    // Check the inputs now, so a bad document fails before
                    // anything runs.
                    if planned.action == "ExecuteDocument" {
                        planned.nested(&BTreeMap::new()).map(|_| ())
                    } else {
                        planned.script(&BTreeMap::new()).map(|_| ())
                    }
                    .map_err(|e| format!("Step '{name}': {e}"))?;
                    out.push(planned);
                }
            }
        }
        Ok(out)
    }

    /// The phases in document order.
    pub fn phase_names(&self) -> &[String] {
        &self.phases
    }
}

/// Most iterations one step's loop may run.
const MAX_ITERATIONS: i64 = 1000;

/// A step's `loop`: each iteration's loop name, index and value.
#[allow(clippy::type_complexity)]
fn loop_iterations(l: &Value) -> Result<Vec<Option<(Option<String>, usize, String)>>, String> {
    let name = l.get("name").and_then(yaml::text);
    let values: Vec<String> = if let Some(each) = l.get("forEach") {
        match each {
            Value::Array(a) => a.iter().filter_map(yaml::text).collect(),
            Value::Object(_) => {
                let delimiter = each.get("delimiter").and_then(yaml::text).unwrap_or_else(|| ",".into());
                if delimiter.is_empty() {
                    return Err("the loop's 'delimiter' must not be empty".into());
                }
                match each.get("list") {
                    Some(Value::Array(a)) => a.iter().filter_map(yaml::text).collect(),
                    Some(v) => match yaml::text(v) {
                        Some(s) => s.split(delimiter.as_str()).map(str::to_string).collect(),
                        None => return Err("the loop's 'forEach' needs a 'list'".into()),
                    },
                    None => return Err("the loop's 'forEach' needs a 'list'".into()),
                }
            }
            _ => return Err("the loop's 'forEach' must be a list".into()),
        }
    } else if let Some(f) = l.get("for") {
        let int = |key: &str| -> Result<i64, String> {
            f.get(key)
                .and_then(yaml::text)
                .and_then(|v| v.trim().parse().ok())
                .ok_or_else(|| format!("the loop's 'for' needs an integer '{key}'"))
        };
        let (start, end, by) = (int("start")?, int("end")?, int("updateBy")?);
        if by == 0 || (end - start).signum() * by.signum() < 0 {
            return Err(format!("the loop from {start} to {end} by {by} never ends"));
        }
        let count = (end - start) / by + 1;
        if count > MAX_ITERATIONS {
            return Err(format!("the loop runs {count} times; the most is {MAX_ITERATIONS}"));
        }
        (0..count).map(|i| (start + i * by).to_string()).collect()
    } else {
        return Err("the loop needs 'forEach' or 'for'".into());
    };
    if values.len() as i64 > MAX_ITERATIONS {
        return Err(format!("the loop runs {} times; the most is {MAX_ITERATIONS}", values.len()));
    }
    Ok(values.into_iter().enumerate().map(|(i, v)| Some((name.clone(), i, v))).collect())
}

/// One step, ready to run.
#[derive(Debug, Clone)]
pub struct Step {
    pub name: String,
    pub action: String,
    pub inputs: Value,
    /// The loop value, for a step that loops.
    pub iteration: Option<String>,
    /// `Abort`, `Continue` or `Ignore`.
    pub on_failure: String,
    pub max_attempts: u32,
}

/// What an `ExecuteDocument` step runs.
#[derive(Debug, Clone, PartialEq)]
pub struct Nested {
    /// An S3 URI, an Image Builder component ARN or a path on the instance.
    pub document: String,
    /// The phases to run; all of them when `None`.
    pub phases: Option<Vec<String>>,
    pub parameters: BTreeMap<String, String>,
}

impl Step {
    /// The shell script, with `outputs` of earlier steps filled in.
    pub fn script(&self, outputs: &BTreeMap<String, String>) -> Result<String, String> {
        script_for(&self.action, &substitute(&self.inputs, outputs))
    }

    /// The document an `ExecuteDocument` step runs.
    pub fn nested(&self, outputs: &BTreeMap<String, String>) -> Result<Nested, String> {
        let inputs = substitute(&self.inputs, outputs);
        let document = need(&inputs, "document")?;
        let phases = match inputs.get("phases") {
            None | Some(Value::Null) => None,
            Some(Value::Array(a)) => Some(a.iter().filter_map(yaml::text).collect::<Vec<_>>()),
            Some(v) => Some(
                yaml::text(v)
                    .unwrap_or_default()
                    .split(',')
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect(),
            ),
        };
        if let Some(bad) = phases.iter().flatten().find(|p| !PHASES.contains(&p.as_str())) {
            return Err(format!("the phase name '{bad}' is not valid"));
        }
        let mut parameters = BTreeMap::new();
        for p in inputs.get("parameters").and_then(Value::as_array).into_iter().flatten() {
            let Some(o) = p.as_object() else { return Err("every parameter must be a mapping".into()) };
            match (o.get("name").and_then(yaml::text), o.get("value").and_then(yaml::text)) {
                (Some(n), Some(v)) if o.len() == 2 => {
                    parameters.insert(n, v);
                }
                _ => {
                    for (k, v) in o {
                        let v = match v {
                            Value::Array(a) => a.iter().filter_map(yaml::text).collect::<Vec<_>>().join(","),
                            other => yaml::text(other).unwrap_or_default(),
                        };
                        parameters.insert(k.clone(), v);
                    }
                }
            }
        }
        Ok(Nested { document, phases, parameters })
    }
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
        // The build runs nested documents itself (`Step::nested`).
        "ExecuteDocument" => return Err("the action module 'ExecuteDocument' does not run as a script".into()),
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
        let none = BTreeMap::new();
        assert!(steps[0].script(&none).unwrap().contains("echo \"hi world\""));
        assert!(steps[1].script(&none).unwrap().contains("base64 -d > '/etc/motd'"));
        assert_eq!(d.plan("test", &p).unwrap().len(), 1);
    }

    #[test]
    fn unrolls_loops() {
        let doc = r#"
schemaVersion: 1.0
phases:
  - name: build
    steps:
      - name: Each
        action: ExecuteBash
        loop:
          name: pkg
          forEach: [git, jq]
        inputs:
          commands: ["echo {{ loop.index }} {{ pkg.value }}"]
      - name: Split
        action: ExecuteBash
        loop:
          forEach:
            list: a;b;c
            delimiter: ";"
        inputs:
          commands: ["echo {{ loop.value }}"]
      - name: Count
        action: ExecuteBash
        loop:
          for:
            start: 10
            end: 0
            updateBy: -5
        inputs:
          commands: ["echo {{ loop.value }} {{ build.Each.outputs.stdout }}"]
"#;
        let d = Document::parse(doc).unwrap();
        let none = BTreeMap::new();
        let steps = d.plan("build", &none).unwrap();
        let scripts: Vec<String> = steps.iter().map(|s| s.script(&none).unwrap()).collect();
        assert_eq!(
            scripts,
            vec![
                "echo 0 git",
                "echo 1 jq",
                "echo a",
                "echo b",
                "echo c",
                "echo 10 {{ build.Each.outputs.stdout }}",
                "echo 5 {{ build.Each.outputs.stdout }}",
                "echo 0 {{ build.Each.outputs.stdout }}",
            ]
        );
        let mut outputs = BTreeMap::new();
        outputs.insert("build.Each.outputs.stdout".to_string(), "jq".to_string());
        assert_eq!(steps[5].script(&outputs).unwrap(), "echo 10 jq");
        let forever = doc.replace("updateBy: -5", "updateBy: 5");
        assert!(Document::parse(&forever).unwrap().plan("build", &none).unwrap_err().contains("never ends"));
    }

    #[test]
    fn nested_documents() {
        let doc = r#"
schemaVersion: 1.0
phases:
  - name: build
    steps:
      - name: Nested
        action: ExecuteDocument
        inputs:
          document: s3://bucket/doc.yaml
          phases: build, validate
          parameters:
            - Greeting: hi
            - name: Other
              value: x
"#;
        let steps = Document::parse(doc).unwrap().plan("build", &BTreeMap::new()).unwrap();
        let n = steps[0].nested(&BTreeMap::new()).unwrap();
        assert_eq!(n.document, "s3://bucket/doc.yaml");
        assert_eq!(n.phases, Some(vec!["build".to_string(), "validate".to_string()]));
        assert_eq!(n.parameters.get("Greeting").map(String::as_str), Some("hi"));
        assert_eq!(n.parameters.get("Other").map(String::as_str), Some("x"));
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
