//! Email templates (`CreateTemplate` / `CreateEmailTemplate`, shared by
//! both APIs), custom verification email templates, and the Handlebars
//! rendering SES does with them.

use std::collections::BTreeMap;

use mws_core::{RequestContext, ServiceError};
use serde_json::Value;

use crate::names::{self, authorize, region, region_ref};
use crate::state::{CustomVerificationTemplate, Template};
use crate::v1::types as t1;
use crate::v2::types as t2;
use crate::{v1, v2, Ses};

const MAX_TEMPLATES: usize = 20_000;
const MAX_TEMPLATE_BYTES: usize = 500 * 1024;

// ---------------------------------------------------------------- rendering

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderError {
    /// `Attribute 'x' is not present in the rendering data.`
    Missing(String),
    /// Bad template data or syntax.
    Invalid(String),
}

impl RenderError {
    pub fn message(&self) -> String {
        match self {
            RenderError::Missing(a) => format!("Attribute '{a}' is not present in the rendering data."),
            RenderError::Invalid(m) => m.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rendered {
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
}

/// Render a stored template with `data` (a JSON object as text).
pub fn render(t: &Template, data: &str) -> Result<Rendered, RenderError> {
    let data: Value = serde_json::from_str(if data.trim().is_empty() { "{}" } else { data })
        .map_err(|_| RenderError::Invalid("Template data must be a valid JSON object.".into()))?;
    if !data.is_object() {
        return Err(RenderError::Invalid("Template data must be a valid JSON object.".into()));
    }
    let part = |p: &Option<String>| p.as_deref().map(|s| render_str(s, &data)).transpose();
    Ok(Rendered { subject: part(&t.subject)?.unwrap_or_default(), text: part(&t.text)?, html: part(&t.html)? })
}

/// Parse a template part, for checking it when the template is stored.
pub fn check_syntax(s: &str) -> Result<(), String> {
    parse(s).map(|_| ())
}

pub fn render_str(s: &str, data: &Value) -> Result<String, RenderError> {
    let nodes = parse(s).map_err(RenderError::Invalid)?;
    let mut out = String::new();
    let mut stack = vec![Scope { value: data, index: None }];
    render_nodes(&nodes, &mut stack, &mut out)?;
    Ok(out)
}

#[derive(Debug, Clone)]
enum Node {
    Text(String),
    Var { path: String, raw: bool },
    Block { helper: String, arg: String, body: Vec<Node>, otherwise: Vec<Node> },
}

fn parse(s: &str) -> Result<Vec<Node>, String> {
    let mut tokens = Vec::new();
    let mut rest = s;
    while let Some(start) = rest.find("{{") {
        if start > 0 {
            tokens.push(Tok::Text(rest[..start].to_string()));
        }
        let after = &rest[start..];
        let (raw, close) = if after.starts_with("{{{") { (true, "}}}") } else { (false, "}}") };
        let open_len = if raw { 3 } else { 2 };
        let end = after[open_len..].find(close).ok_or_else(|| "Unclosed expression in template".to_string())?;
        let inner = after[open_len..open_len + end].trim().trim_start_matches('~').trim_end_matches('~').trim();
        rest = &after[open_len + end + close.len()..];
        if inner.starts_with('!') {
            continue;
        }
        if let Some(b) = inner.strip_prefix('#') {
            let (helper, arg) = b.split_once(char::is_whitespace).unwrap_or((b, ""));
            tokens.push(Tok::Open(helper.to_string(), arg.trim().to_string()));
        } else if let Some(b) = inner.strip_prefix('/') {
            tokens.push(Tok::Close(b.trim().to_string()));
        } else if inner == "else" || inner == "^" {
            tokens.push(Tok::Else);
        } else {
            tokens.push(Tok::Var(inner.to_string(), raw));
        }
    }
    if !rest.is_empty() {
        tokens.push(Tok::Text(rest.to_string()));
    }
    let mut it = tokens.into_iter();
    let (nodes, end) = build(&mut it, None)?;
    if let Some(e) = end {
        return Err(format!("Unexpected {e} in template"));
    }
    Ok(nodes)
}

enum Tok {
    Text(String),
    Var(String, bool),
    Open(String, String),
    Close(String),
    Else,
}

/// Build nodes until `{{/helper}}` (or the end); returns the nodes and,
/// when an `{{else}}` stopped the run, `"else"`.
fn build(it: &mut impl Iterator<Item = Tok>, helper: Option<&str>) -> Result<(Vec<Node>, Option<String>), String> {
    let mut nodes = Vec::new();
    while let Some(t) = it.next() {
        match t {
            Tok::Text(s) => nodes.push(Node::Text(s)),
            Tok::Var(p, raw) => nodes.push(Node::Var { path: p, raw }),
            Tok::Else => {
                if helper.is_none() {
                    return Err("Unexpected {{else}} in template".into());
                }
                return Ok((nodes, Some("else".into())));
            }
            Tok::Close(name) => {
                return match helper {
                    Some(h) if h == name => Ok((nodes, None)),
                    _ => Err(format!("{name} doesn't match {}", helper.unwrap_or("nothing"))),
                };
            }
            Tok::Open(h, arg) => {
                if !matches!(h.as_str(), "if" | "unless" | "each" | "with") {
                    return Err(format!("Missing helper: \"{h}\""));
                }
                let (body, stop) = build(it, Some(&h))?;
                let otherwise = if stop.is_some() {
                    let (o, stop2) = build(it, Some(&h))?;
                    if stop2.is_some() {
                        return Err("Unexpected {{else}} in template".into());
                    }
                    o
                } else {
                    Vec::new()
                };
                nodes.push(Node::Block { helper: h, arg, body, otherwise });
            }
        }
    }
    match helper {
        Some(h) => Err(format!("{h} doesn't match nothing")),
        None => Ok((nodes, None)),
    }
}

struct Scope<'a> {
    value: &'a Value,
    index: Option<usize>,
}

fn lookup<'a>(stack: &[Scope<'a>], path: &str) -> Option<&'a Value> {
    if path == "this" || path == "." {
        return stack.last().map(|s| s.value);
    }
    let mut depth = stack.len();
    let mut p = path;
    while let Some(rest) = p.strip_prefix("../") {
        depth = depth.saturating_sub(1);
        p = rest;
    }
    let p = p.strip_prefix("this.").unwrap_or(p);
    let base = stack.get(depth.checked_sub(1)?)?.value;
    let mut cur = base;
    for part in p.split('.') {
        cur = match cur {
            Value::Object(m) => m.get(part)?,
            Value::Array(a) => a.get(part.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(cur)
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
        _ => true,
    }
}

fn to_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        other => other.to_string(),
    }
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            '`' => out.push_str("&#x60;"),
            '=' => out.push_str("&#x3D;"),
            c => out.push(c),
        }
    }
    out
}

fn render_nodes<'a>(nodes: &'a [Node], stack: &mut Vec<Scope<'a>>, out: &mut String) -> Result<(), RenderError>
where
    'a: 'a,
{
    for n in nodes {
        match n {
            Node::Text(s) => out.push_str(s),
            Node::Var { path, raw } => {
                if path == "@index" {
                    out.push_str(&stack.last().and_then(|s| s.index).unwrap_or(0).to_string());
                    continue;
                }
                // SAFETY of lifetimes: values borrowed from the data live
                // as long as the render.
                let v = lookup_owned(stack, path).ok_or_else(|| RenderError::Missing(path.clone()))?;
                let text = to_text(&v);
                out.push_str(&if *raw { text } else { escape(&text) });
            }
            Node::Block { helper, arg, body, otherwise } => {
                let v = lookup_owned(stack, arg);
                match helper.as_str() {
                    "if" | "unless" => {
                        let t = truthy(v.as_ref());
                        let branch = if t == (helper == "if") { body } else { otherwise };
                        render_nodes_owned(branch, stack, out)?;
                    }
                    "each" => match v {
                        Some(Value::Array(items)) if !items.is_empty() => {
                            for (i, item) in items.iter().enumerate() {
                                render_scoped(body, stack, item, Some(i), out)?;
                            }
                        }
                        Some(Value::Object(m)) if !m.is_empty() => {
                            for (i, (_, item)) in m.iter().enumerate() {
                                render_scoped(body, stack, item, Some(i), out)?;
                            }
                        }
                        _ => render_nodes_owned(otherwise, stack, out)?,
                    },
                    _ => match v {
                        Some(v) if truthy(Some(&v)) => render_scoped(body, stack, &v, None, out)?,
                        _ => render_nodes_owned(otherwise, stack, out)?,
                    },
                }
            }
        }
    }
    Ok(())
}

fn lookup_owned(stack: &[Scope<'_>], path: &str) -> Option<Value> {
    lookup(stack, path).cloned()
}

fn render_nodes_owned(nodes: &[Node], stack: &mut Vec<Scope<'_>>, out: &mut String) -> Result<(), RenderError> {
    // Re-borrow the stack's values for a shorter lifetime.
    let values: Vec<(Value, Option<usize>)> = stack.iter().map(|s| (s.value.clone(), s.index)).collect();
    let mut inner: Vec<Scope<'_>> = values.iter().map(|(v, i)| Scope { value: v, index: *i }).collect();
    render_nodes(nodes, &mut inner, out)
}

fn render_scoped(
    nodes: &[Node],
    stack: &mut Vec<Scope<'_>>,
    value: &Value,
    index: Option<usize>,
    out: &mut String,
) -> Result<(), RenderError> {
    let mut values: Vec<(Value, Option<usize>)> = stack.iter().map(|s| (s.value.clone(), s.index)).collect();
    values.push((value.clone(), index));
    let mut inner: Vec<Scope<'_>> = values.iter().map(|(v, i)| Scope { value: v, index: *i }).collect();
    render_nodes(nodes, &mut inner, out)
}

// ---------------------------------------------------------------- storage

fn check_template_parts(subject: Option<&str>, text: Option<&str>, html: Option<&str>) -> Result<(), String> {
    let size = subject.map_or(0, str::len) + text.map_or(0, str::len) + html.map_or(0, str::len);
    if size > MAX_TEMPLATE_BYTES {
        return Err(format!("Template size exceeds the maximum of {MAX_TEMPLATE_BYTES} bytes."));
    }
    for p in [subject, text, html].into_iter().flatten() {
        check_syntax(p)?;
    }
    Ok(())
}

impl Ses {
    pub(crate) fn find_template(&self, ctx: &RequestContext, name: &str) -> Option<Template> {
        region_ref(&self.lock(), ctx).and_then(|r| r.templates.get(name).cloned())
    }

    fn put_template(&self, ctx: &RequestContext, t: Template, create: bool) -> Result<(), Result<String, String>> {
        let mut st = self.lock();
        let r = region(&mut st, ctx);
        match (create, r.templates.get_mut(&t.name)) {
            (true, Some(_)) => return Err(Ok(format!("Template {} already exists.", t.name))),
            (false, None) => return Err(Err(format!("Template {} does not exist.", t.name))),
            (false, Some(existing)) => {
                existing.subject = t.subject;
                existing.text = t.text;
                existing.html = t.html;
            }
            (true, None) => {
                if r.templates.len() >= MAX_TEMPLATES {
                    return Err(Ok(String::new()));
                }
                r.templates.insert(t.name.clone(), t);
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------ v1

    pub(crate) fn create_template_v1(
        &self,
        ctx: &RequestContext,
        input: t1::CreateTemplateRequest,
    ) -> Result<(), ServiceError> {
        let t = input.template;
        authorize(ctx, "1", "CreateTemplate", &names::arn(ctx, &format!("template/{}", t.template_name)))?;
        if !names::valid_name(&t.template_name) {
            return Err(v1::errors::invalid_template(format!("Invalid template name: {}", t.template_name)));
        }
        check_template_parts(t.subject_part.as_deref(), t.text_part.as_deref(), t.html_part.as_deref())
            .map_err(v1::errors::invalid_template)?;
        let template = Template {
            name: t.template_name,
            subject: t.subject_part,
            text: t.text_part,
            html: t.html_part,
            created: ctx.received_at,
            tags: BTreeMap::new(),
        };
        self.put_template(ctx, template, true).map_err(|e| match e {
            Ok(m) if m.is_empty() => v1::errors::limit_exceeded("Maximum number of templates reached."),
            Ok(m) => v1::errors::already_exists(m),
            Err(m) => v1::errors::template_does_not_exist(m),
        })
    }

    pub(crate) fn update_template_v1(
        &self,
        ctx: &RequestContext,
        input: t1::UpdateTemplateRequest,
    ) -> Result<(), ServiceError> {
        let t = input.template;
        authorize(ctx, "1", "UpdateTemplate", &names::arn(ctx, &format!("template/{}", t.template_name)))?;
        check_template_parts(t.subject_part.as_deref(), t.text_part.as_deref(), t.html_part.as_deref())
            .map_err(v1::errors::invalid_template)?;
        let template = Template {
            name: t.template_name,
            subject: t.subject_part,
            text: t.text_part,
            html: t.html_part,
            ..Default::default()
        };
        self.put_template(ctx, template, false).map_err(|e| match e {
            Ok(m) => v1::errors::already_exists(m),
            Err(m) => v1::errors::template_does_not_exist(m),
        })
    }

    pub(crate) fn get_template_v1(
        &self,
        ctx: &RequestContext,
        input: t1::GetTemplateRequest,
    ) -> Result<t1::GetTemplateResponse, ServiceError> {
        authorize(ctx, "1", "GetTemplate", &names::arn(ctx, &format!("template/{}", input.template_name)))?;
        let t = self.find_template(ctx, &input.template_name).ok_or_else(|| {
            v1::errors::template_does_not_exist(format!("Template {} does not exist.", input.template_name))
        })?;
        Ok(t1::GetTemplateResponse {
            template: Some(t1::Template {
                template_name: t.name,
                subject_part: t.subject,
                text_part: t.text,
                html_part: t.html,
            }),
        })
    }

    pub(crate) fn delete_template_v1(
        &self,
        ctx: &RequestContext,
        input: t1::DeleteTemplateRequest,
    ) -> Result<(), ServiceError> {
        authorize(ctx, "1", "DeleteTemplate", &names::arn(ctx, &format!("template/{}", input.template_name)))?;
        region(&mut self.lock(), ctx).templates.remove(&input.template_name);
        Ok(())
    }

    pub(crate) fn list_templates_v1(
        &self,
        ctx: &RequestContext,
        input: t1::ListTemplatesRequest,
    ) -> Result<t1::ListTemplatesResponse, ServiceError> {
        authorize(ctx, "1", "ListTemplates", "*")?;
        let all: Vec<t1::TemplateMetadata> = region_ref(&self.lock(), ctx)
            .map(|r| {
                r.templates
                    .values()
                    .map(|t| t1::TemplateMetadata { name: Some(t.name.clone()), created_timestamp: Some(t.created) })
                    .collect()
            })
            .unwrap_or_default();
        let (page, next) = names::paginate(&all, input.next_token.as_deref(), input.max_items, 10);
        Ok(t1::ListTemplatesResponse { templates_metadata: Some(page), next_token: next })
    }

    pub(crate) fn test_render_template_v1(
        &self,
        ctx: &RequestContext,
        input: t1::TestRenderTemplateRequest,
    ) -> Result<t1::TestRenderTemplateResponse, ServiceError> {
        authorize(ctx, "1", "TestRenderTemplate", "*")?;
        let t = self.find_template(ctx, &input.template_name).ok_or_else(|| {
            v1::errors::template_does_not_exist(format!("Template {} does not exist.", input.template_name))
        })?;
        let r = render(&t, &input.template_data).map_err(|e| match e {
            RenderError::Missing(_) => v1::errors::missing_rendering_attribute(e.message()),
            RenderError::Invalid(m) => v1::errors::invalid_rendering_parameter(m),
        })?;
        Ok(t1::TestRenderTemplateResponse { rendered_template: Some(crate::mime::render_preview(ctx, &r)) })
    }

    // ------------------------------------------------------------ v2

    pub(crate) fn create_email_template_v2(
        &self,
        ctx: &RequestContext,
        input: t2::CreateEmailTemplateRequest,
    ) -> Result<t2::CreateEmailTemplateResponse, ServiceError> {
        let tags = names::tags_pairs(input.tags.as_deref());
        names::authorize_create(
            ctx,
            "CreateEmailTemplate",
            &names::arn(ctx, &format!("template/{}", input.template_name)),
            &tags,
        )?;
        names::check_tags(&tags)?;
        if !names::valid_name(&input.template_name) {
            return Err(v2::errors::bad_request(format!("Invalid template name: {}", input.template_name)));
        }
        let c = input.template_content;
        check_template_parts(c.subject.as_deref(), c.text.as_deref(), c.html.as_deref())
            .map_err(v2::errors::bad_request)?;
        let template = Template {
            name: input.template_name,
            subject: c.subject,
            text: c.text,
            html: c.html,
            created: ctx.received_at,
            tags: tags.into_iter().collect(),
        };
        self.put_template(ctx, template, true).map_err(|e| match e {
            Ok(m) if m.is_empty() => v2::errors::limit_exceeded("Maximum number of templates reached."),
            Ok(m) => v2::errors::already_exists(m),
            Err(m) => v2::errors::not_found(m),
        })?;
        Ok(Default::default())
    }

    pub(crate) fn update_email_template_v2(
        &self,
        ctx: &RequestContext,
        input: t2::UpdateEmailTemplateRequest,
    ) -> Result<t2::UpdateEmailTemplateResponse, ServiceError> {
        let arn = names::arn(ctx, &format!("template/{}", input.template_name));
        let tags = self.find_template(ctx, &input.template_name).map(|t| t.tags).unwrap_or_default();
        names::authorize_tagged(ctx, "2", "UpdateEmailTemplate", &arn, &tags)?;
        let c = input.template_content;
        check_template_parts(c.subject.as_deref(), c.text.as_deref(), c.html.as_deref())
            .map_err(v2::errors::bad_request)?;
        let template = Template {
            name: input.template_name,
            subject: c.subject,
            text: c.text,
            html: c.html,
            ..Default::default()
        };
        self.put_template(ctx, template, false).map_err(|e| match e {
            Ok(m) => v2::errors::already_exists(m),
            Err(m) => v2::errors::not_found(m),
        })?;
        Ok(Default::default())
    }

    pub(crate) fn get_email_template_v2(
        &self,
        ctx: &RequestContext,
        input: t2::GetEmailTemplateRequest,
    ) -> Result<t2::GetEmailTemplateResponse, ServiceError> {
        let arn = names::arn(ctx, &format!("template/{}", input.template_name));
        let t = self.find_template(ctx, &input.template_name);
        names::authorize_tagged(
            ctx,
            "2",
            "GetEmailTemplate",
            &arn,
            &t.as_ref().map(|t| t.tags.clone()).unwrap_or_default(),
        )?;
        let t = t.ok_or_else(|| v2::errors::not_found(format!("Template {} does not exist.", input.template_name)))?;
        Ok(t2::GetEmailTemplateResponse {
            template_name: t.name,
            template_content: t2::EmailTemplateContent { subject: t.subject, text: t.text, html: t.html },
            tags: Some(names::tag_list(&t.tags)),
        })
    }

    pub(crate) fn delete_email_template_v2(
        &self,
        ctx: &RequestContext,
        input: t2::DeleteEmailTemplateRequest,
    ) -> Result<t2::DeleteEmailTemplateResponse, ServiceError> {
        let arn = names::arn(ctx, &format!("template/{}", input.template_name));
        let t = self.find_template(ctx, &input.template_name);
        names::authorize_tagged(
            ctx,
            "2",
            "DeleteEmailTemplate",
            &arn,
            &t.as_ref().map(|t| t.tags.clone()).unwrap_or_default(),
        )?;
        if region(&mut self.lock(), ctx).templates.remove(&input.template_name).is_none() {
            return Err(v2::errors::not_found(format!("Template {} does not exist.", input.template_name)));
        }
        Ok(Default::default())
    }

    pub(crate) fn list_email_templates_v2(
        &self,
        ctx: &RequestContext,
        input: t2::ListEmailTemplatesRequest,
    ) -> Result<t2::ListEmailTemplatesResponse, ServiceError> {
        authorize(ctx, "2", "ListEmailTemplates", "*")?;
        names::check_token(input.next_token.as_deref())?;
        if input.page_size.is_some_and(|p| !(1..=100).contains(&p)) {
            return Err(v2::errors::bad_request("PageSize must be between 1 and 100."));
        }
        let all: Vec<t2::EmailTemplateMetadata> = region_ref(&self.lock(), ctx)
            .map(|r| {
                r.templates
                    .values()
                    .map(|t| t2::EmailTemplateMetadata {
                        template_name: Some(t.name.clone()),
                        created_timestamp: Some(t.created),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let (page, next) = names::paginate(&all, input.next_token.as_deref(), input.page_size, 10);
        Ok(t2::ListEmailTemplatesResponse { templates_metadata: Some(page), next_token: next })
    }

    pub(crate) fn test_render_email_template_v2(
        &self,
        ctx: &RequestContext,
        input: t2::TestRenderEmailTemplateRequest,
    ) -> Result<t2::TestRenderEmailTemplateResponse, ServiceError> {
        authorize(ctx, "2", "TestRenderEmailTemplate", &names::arn(ctx, &format!("template/{}", input.template_name)))?;
        let t = self
            .find_template(ctx, &input.template_name)
            .ok_or_else(|| v2::errors::not_found(format!("Template {} does not exist.", input.template_name)))?;
        let r = render(&t, &input.template_data).map_err(|e| v2::errors::bad_request(e.message()))?;
        Ok(t2::TestRenderEmailTemplateResponse { rendered_template: crate::mime::render_preview(ctx, &r) })
    }

    // ------------------------------------------------------------ custom verification templates

    fn custom_template(&self, ctx: &RequestContext, name: &str) -> Option<CustomVerificationTemplate> {
        region_ref(&self.lock(), ctx).and_then(|r| r.custom_verification_templates.get(name).cloned())
    }

    /// Store a custom verification template; `Err(Ok)` already exists,
    /// `Err(Err)` does not exist, `Err(Ok(""))` the limit.
    fn put_custom_template(
        &self,
        ctx: &RequestContext,
        t: CustomVerificationTemplate,
        create: bool,
    ) -> Result<(), Result<String, String>> {
        let mut st = self.lock();
        let r = region(&mut st, ctx);
        match (create, r.custom_verification_templates.get_mut(&t.name)) {
            (true, Some(_)) => Err(Ok(format!("Custom verification email template {} already exists.", t.name))),
            (false, None) => Err(Err(format!("Custom verification email template {} does not exist.", t.name))),
            (false, Some(existing)) => {
                let created = existing.created;
                let tags = std::mem::take(&mut existing.tags);
                *existing = CustomVerificationTemplate { created, tags, ..t };
                Ok(())
            }
            (true, None) => {
                if r.custom_verification_templates.len() >= 50 {
                    return Err(Ok(String::new()));
                }
                r.custom_verification_templates.insert(t.name.clone(), t);
                Ok(())
            }
        }
    }

    /// Whether `from` is a verified identity (address or domain) here.
    pub(crate) fn is_verified_sender(&self, ctx: &RequestContext, from: &str) -> bool {
        let mut st = self.lock();
        let r = region(&mut st, ctx);
        crate::identities::sending_identity(r, from).is_some()
    }

    pub(crate) fn create_custom_verification_email_template_v1(
        &self,
        ctx: &RequestContext,
        input: t1::CreateCustomVerificationEmailTemplateRequest,
    ) -> Result<(), ServiceError> {
        authorize(ctx, "1", "CreateCustomVerificationEmailTemplate", "*")?;
        if !self.is_verified_sender(ctx, &input.from_email_address) {
            return Err(v1::errors::from_email_address_not_verified(format!(
                "Email address {} is not verified.",
                input.from_email_address
            )));
        }
        if input.template_content.len() > 10 * 1024 * 1024 {
            return Err(v1::errors::custom_verification_email_invalid_content("Template content is too large."));
        }
        let t = CustomVerificationTemplate {
            name: input.template_name,
            from: input.from_email_address,
            subject: input.template_subject,
            content: input.template_content,
            success_url: input.success_redirection_url,
            failure_url: input.failure_redirection_url,
            created: ctx.received_at,
            tags: BTreeMap::new(),
        };
        self.put_custom_template(ctx, t, true).map_err(|e| match e {
            Ok(m) if m.is_empty() => {
                v1::errors::limit_exceeded("Maximum number of custom verification templates reached.")
            }
            Ok(m) => v1::errors::custom_verification_email_template_already_exists(m),
            Err(m) => v1::errors::custom_verification_email_template_does_not_exist(m),
        })
    }

    pub(crate) fn update_custom_verification_email_template_v1(
        &self,
        ctx: &RequestContext,
        input: t1::UpdateCustomVerificationEmailTemplateRequest,
    ) -> Result<(), ServiceError> {
        authorize(ctx, "1", "UpdateCustomVerificationEmailTemplate", "*")?;
        let existing = self.custom_template(ctx, &input.template_name).ok_or_else(|| {
            v1::errors::custom_verification_email_template_does_not_exist(format!(
                "Custom verification email template {} does not exist.",
                input.template_name
            ))
        })?;
        if let Some(from) = &input.from_email_address {
            if !self.is_verified_sender(ctx, from) {
                return Err(v1::errors::from_email_address_not_verified(format!(
                    "Email address {from} is not verified."
                )));
            }
        }
        let t = CustomVerificationTemplate {
            name: input.template_name,
            from: input.from_email_address.unwrap_or(existing.from),
            subject: input.template_subject.unwrap_or(existing.subject),
            content: input.template_content.unwrap_or(existing.content),
            success_url: input.success_redirection_url.unwrap_or(existing.success_url),
            failure_url: input.failure_redirection_url.unwrap_or(existing.failure_url),
            ..existing
        };
        self.put_custom_template(ctx, t, false)
            .map_err(|_| v1::errors::custom_verification_email_template_does_not_exist("Template does not exist."))
    }

    pub(crate) fn get_custom_verification_email_template_v1(
        &self,
        ctx: &RequestContext,
        input: t1::GetCustomVerificationEmailTemplateRequest,
    ) -> Result<t1::GetCustomVerificationEmailTemplateResponse, ServiceError> {
        authorize(ctx, "1", "GetCustomVerificationEmailTemplate", "*")?;
        let t = self.custom_template(ctx, &input.template_name).ok_or_else(|| {
            v1::errors::custom_verification_email_template_does_not_exist(format!(
                "Custom verification email template {} does not exist.",
                input.template_name
            ))
        })?;
        Ok(t1::GetCustomVerificationEmailTemplateResponse {
            template_name: Some(t.name),
            from_email_address: Some(t.from),
            template_subject: Some(t.subject),
            template_content: Some(t.content),
            success_redirection_url: Some(t.success_url),
            failure_redirection_url: Some(t.failure_url),
        })
    }

    pub(crate) fn delete_custom_verification_email_template_v1(
        &self,
        ctx: &RequestContext,
        input: t1::DeleteCustomVerificationEmailTemplateRequest,
    ) -> Result<(), ServiceError> {
        authorize(ctx, "1", "DeleteCustomVerificationEmailTemplate", "*")?;
        region(&mut self.lock(), ctx).custom_verification_templates.remove(&input.template_name);
        Ok(())
    }

    pub(crate) fn list_custom_verification_email_templates_v1(
        &self,
        ctx: &RequestContext,
        input: t1::ListCustomVerificationEmailTemplatesRequest,
    ) -> Result<t1::ListCustomVerificationEmailTemplatesResponse, ServiceError> {
        authorize(ctx, "1", "ListCustomVerificationEmailTemplates", "*")?;
        let all: Vec<t1::CustomVerificationEmailTemplate> = region_ref(&self.lock(), ctx)
            .map(|r| {
                r.custom_verification_templates
                    .values()
                    .map(|t| t1::CustomVerificationEmailTemplate {
                        template_name: Some(t.name.clone()),
                        from_email_address: Some(t.from.clone()),
                        template_subject: Some(t.subject.clone()),
                        success_redirection_url: Some(t.success_url.clone()),
                        failure_redirection_url: Some(t.failure_url.clone()),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let (page, next) = names::paginate(&all, input.next_token.as_deref(), input.max_results, 50);
        Ok(t1::ListCustomVerificationEmailTemplatesResponse {
            custom_verification_email_templates: Some(page),
            next_token: next,
        })
    }

    pub(crate) fn create_custom_verification_email_template_v2(
        &self,
        ctx: &RequestContext,
        input: t2::CreateCustomVerificationEmailTemplateRequest,
    ) -> Result<t2::CreateCustomVerificationEmailTemplateResponse, ServiceError> {
        let tags = names::tags_pairs(input.tags.as_deref());
        let arn = names::arn(ctx, &format!("custom-verification-email-template/{}", input.template_name));
        names::authorize_create(ctx, "CreateCustomVerificationEmailTemplate", &arn, &tags)?;
        names::check_tags(&tags)?;
        if !self.is_verified_sender(ctx, &input.from_email_address) {
            return Err(v2::errors::bad_request(format!(
                "Email address {} is not verified.",
                input.from_email_address
            )));
        }
        let t = CustomVerificationTemplate {
            name: input.template_name,
            from: input.from_email_address,
            subject: input.template_subject,
            content: input.template_content,
            success_url: input.success_redirection_url,
            failure_url: input.failure_redirection_url,
            created: ctx.received_at,
            tags: tags.into_iter().collect(),
        };
        self.put_custom_template(ctx, t, true).map_err(|e| match e {
            Ok(m) if m.is_empty() => {
                v2::errors::limit_exceeded("Maximum number of custom verification templates reached.")
            }
            Ok(m) => v2::errors::already_exists(m),
            Err(m) => v2::errors::not_found(m),
        })?;
        Ok(Default::default())
    }

    pub(crate) fn update_custom_verification_email_template_v2(
        &self,
        ctx: &RequestContext,
        input: t2::UpdateCustomVerificationEmailTemplateRequest,
    ) -> Result<t2::UpdateCustomVerificationEmailTemplateResponse, ServiceError> {
        let arn = names::arn(ctx, &format!("custom-verification-email-template/{}", input.template_name));
        authorize(ctx, "2", "UpdateCustomVerificationEmailTemplate", &arn)?;
        if self.custom_template(ctx, &input.template_name).is_none() {
            return Err(v2::errors::not_found(format!(
                "Custom verification email template {} does not exist.",
                input.template_name
            )));
        }
        if !self.is_verified_sender(ctx, &input.from_email_address) {
            return Err(v2::errors::bad_request(format!(
                "Email address {} is not verified.",
                input.from_email_address
            )));
        }
        let t = CustomVerificationTemplate {
            name: input.template_name,
            from: input.from_email_address,
            subject: input.template_subject,
            content: input.template_content,
            success_url: input.success_redirection_url,
            failure_url: input.failure_redirection_url,
            ..Default::default()
        };
        self.put_custom_template(ctx, t, false).map_err(|_| v2::errors::not_found("Template does not exist."))?;
        Ok(Default::default())
    }

    pub(crate) fn get_custom_verification_email_template_v2(
        &self,
        ctx: &RequestContext,
        input: t2::GetCustomVerificationEmailTemplateRequest,
    ) -> Result<t2::GetCustomVerificationEmailTemplateResponse, ServiceError> {
        let arn = names::arn(ctx, &format!("custom-verification-email-template/{}", input.template_name));
        authorize(ctx, "2", "GetCustomVerificationEmailTemplate", &arn)?;
        let t = self.custom_template(ctx, &input.template_name).ok_or_else(|| {
            v2::errors::not_found(format!("Custom verification email template {} does not exist.", input.template_name))
        })?;
        Ok(t2::GetCustomVerificationEmailTemplateResponse {
            template_name: Some(t.name),
            from_email_address: Some(t.from),
            template_subject: Some(t.subject),
            template_content: Some(t.content),
            tags: Some(names::tag_list(&t.tags)),
            success_redirection_url: Some(t.success_url),
            failure_redirection_url: Some(t.failure_url),
        })
    }

    pub(crate) fn delete_custom_verification_email_template_v2(
        &self,
        ctx: &RequestContext,
        input: t2::DeleteCustomVerificationEmailTemplateRequest,
    ) -> Result<t2::DeleteCustomVerificationEmailTemplateResponse, ServiceError> {
        let arn = names::arn(ctx, &format!("custom-verification-email-template/{}", input.template_name));
        authorize(ctx, "2", "DeleteCustomVerificationEmailTemplate", &arn)?;
        if region(&mut self.lock(), ctx).custom_verification_templates.remove(&input.template_name).is_none() {
            return Err(v2::errors::not_found(format!(
                "Custom verification email template {} does not exist.",
                input.template_name
            )));
        }
        Ok(Default::default())
    }

    pub(crate) fn list_custom_verification_email_templates_v2(
        &self,
        ctx: &RequestContext,
        input: t2::ListCustomVerificationEmailTemplatesRequest,
    ) -> Result<t2::ListCustomVerificationEmailTemplatesResponse, ServiceError> {
        authorize(ctx, "2", "ListCustomVerificationEmailTemplates", "*")?;
        names::check_token(input.next_token.as_deref())?;
        let all: Vec<t2::CustomVerificationEmailTemplateMetadata> = region_ref(&self.lock(), ctx)
            .map(|r| {
                r.custom_verification_templates
                    .values()
                    .map(|t| t2::CustomVerificationEmailTemplateMetadata {
                        template_name: Some(t.name.clone()),
                        from_email_address: Some(t.from.clone()),
                        template_subject: Some(t.subject.clone()),
                        success_redirection_url: Some(t.success_url.clone()),
                        failure_redirection_url: Some(t.failure_url.clone()),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let (page, next) = names::paginate(&all, input.next_token.as_deref(), input.page_size, 50);
        Ok(t2::ListCustomVerificationEmailTemplatesResponse {
            custom_verification_email_templates: Some(page),
            next_token: next,
        })
    }

    /// The template for `SendCustomVerificationEmail`.
    pub(crate) fn custom_template_for_send(
        &self,
        ctx: &RequestContext,
        name: &str,
    ) -> Option<CustomVerificationTemplate> {
        self.custom_template(ctx, name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_variables_blocks_and_escapes() {
        let data = serde_json::json!({
            "name": "Ana & Bo",
            "items": [{"n": "a"}, {"n": "b"}],
            "vip": true,
            "user": {"city": "Lisbon"}
        });
        assert_eq!(render_str("Hi {{name}}", &data).unwrap(), "Hi Ana &amp; Bo");
        assert_eq!(render_str("Hi {{{name}}}", &data).unwrap(), "Hi Ana & Bo");
        assert_eq!(render_str("{{#each items}}[{{n}}{{@index}}]{{/each}}", &data).unwrap(), "[a0][b1]");
        assert_eq!(render_str("{{#if vip}}gold{{else}}std{{/if}}", &data).unwrap(), "gold");
        assert_eq!(render_str("{{#if nope}}gold{{else}}std{{/if}}", &data).unwrap(), "std");
        assert_eq!(render_str("{{#with user}}{{city}}{{/with}}", &data).unwrap(), "Lisbon");
        assert_eq!(render_str("{{user.city}}", &data).unwrap(), "Lisbon");
        assert_eq!(render_str("Hi {{missing}}", &data).unwrap_err(), RenderError::Missing("missing".into()));
        assert!(check_syntax("{{#if a}}x").is_err());
        assert!(check_syntax("{{#bogus a}}x{{/bogus}}").is_err());
    }
}
