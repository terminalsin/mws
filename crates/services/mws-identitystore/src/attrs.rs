//! Attribute paths: `UpdateUser`/`UpdateGroup` operations, filters and
//! unique-attribute lookups.

use mws_proto_json::{Decoder, Value};

use crate::generated::{de, types};

/// An attribute operation's value as JSON (`None` removes the attribute).
pub fn operation_value(op: &types::AttributeOperation) -> Option<Value> {
    op.attribute_value.as_deref().and_then(|s| serde_json::from_str(s).ok()).filter(|v: &Value| !v.is_null())
}

/// Capitalize object keys so values written in camelCase decode like the
/// wire's PascalCase members.
fn pascal_keys(v: Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.into_iter()
                .map(|(k, v)| {
                    let mut c = k.chars();
                    let k = c.next().map(|f| f.to_uppercase().chain(c).collect::<String>()).unwrap_or_default();
                    (k, pascal_keys(v))
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.into_iter().map(pascal_keys).collect()),
        other => other,
    }
}

fn string(path: &str, v: Option<Value>) -> Result<Option<String>, String> {
    match v {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(format!("Invalid value for attribute {path}. Expected a string.")),
    }
}

fn decode<T>(
    path: &str,
    v: Option<Value>,
    f: impl FnOnce(&mut Decoder, Option<&Value>, &str) -> Option<T>,
) -> Result<Option<T>, String> {
    let Some(v) = v else { return Ok(None) };
    let v = pascal_keys(v);
    let mut d = Decoder::new();
    let out = f(&mut d, Some(&v), path);
    d.finish("ValidationException").map_err(|e| e.message)?;
    out.map(Some).ok_or_else(|| format!("Invalid value for attribute {path}."))
}

/// Apply one attribute operation to `user`.
pub fn update_user(user: &mut types::User, op: &types::AttributeOperation) -> Result<(), String> {
    let path = op.attribute_path.as_str();
    let value = operation_value(op);
    let lower = path.to_ascii_lowercase();
    if let Some(ext) = path.strip_prefix("aws:identitystore:") {
        return update_extension(user, ext, value);
    }
    if let Some(member) = lower.strip_prefix("name.") {
        let name = user.name.get_or_insert_with(Default::default);
        let v = string(path, value)?;
        match member {
            "formatted" => name.formatted = v,
            "familyname" => name.family_name = v,
            "givenname" => name.given_name = v,
            "middlename" => name.middle_name = v,
            "honorificprefix" => name.honorific_prefix = v,
            "honorificsuffix" => name.honorific_suffix = v,
            _ => return Err(unknown(path)),
        }
        return Ok(());
    }
    match lower.as_str() {
        "username" => {
            let v = string(path, value)?.ok_or_else(|| "UserName is a required attribute.".to_string())?;
            user.user_name = Some(v);
        }
        "displayname" => user.display_name = string(path, value)?,
        "nickname" => user.nick_name = string(path, value)?,
        "profileurl" => user.profile_url = string(path, value)?,
        "usertype" => user.user_type = string(path, value)?,
        "title" => user.title = string(path, value)?,
        "preferredlanguage" => user.preferred_language = string(path, value)?,
        "locale" => user.locale = string(path, value)?,
        "timezone" => user.timezone = string(path, value)?,
        "website" => user.website = string(path, value)?,
        "birthdate" => user.birthdate = string(path, value)?,
        "name" => user.name = decode(path, value, de::de_name)?,
        "emails" => user.emails = decode(path, value, de::de_emails)?,
        "addresses" => user.addresses = decode(path, value, de::de_addresses)?,
        "phonenumbers" => user.phone_numbers = decode(path, value, de::de_phone_numbers)?,
        "photos" => user.photos = decode(path, value, de::de_photos)?,
        "roles" => user.roles = decode(path, value, de::de_roles)?,
        _ => return Err(unknown(path)),
    }
    Ok(())
}

/// `aws:identitystore:enterprise` or `aws:identitystore:enterprise.department`.
fn update_extension(user: &mut types::User, rest: &str, value: Option<Value>) -> Result<(), String> {
    let (name, member) = match rest.split_once('.') {
        Some((n, m)) => (n, Some(m)),
        None => (rest, None),
    };
    let key = format!("aws:identitystore:{name}");
    let extensions = user.extensions.get_or_insert_with(Default::default);
    match member {
        None => match value {
            Some(v) => {
                extensions.insert(key, v.to_string());
            }
            None => {
                extensions.remove(&key);
            }
        },
        Some(member) => {
            let mut doc: Value = extensions
                .get(&key)
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_else(|| Value::Object(Default::default()));
            set_path(&mut doc, member, value);
            extensions.insert(key, doc.to_string());
        }
    }
    if extensions.is_empty() {
        user.extensions = None;
    }
    Ok(())
}

fn set_path(doc: &mut Value, path: &str, value: Option<Value>) {
    let mut parts = path.split('.').peekable();
    let mut cur = doc;
    while let Some(p) = parts.next() {
        if !cur.is_object() {
            *cur = Value::Object(Default::default());
        }
        let obj = cur.as_object_mut().expect("object");
        if parts.peek().is_none() {
            match value {
                Some(v) => {
                    obj.insert(p.to_string(), v);
                }
                None => {
                    obj.remove(p);
                }
            }
            return;
        }
        cur = obj.entry(p.to_string()).or_insert_with(|| Value::Object(Default::default()));
    }
}

/// Apply one attribute operation to `group`.
pub fn update_group(group: &mut types::Group, op: &types::AttributeOperation) -> Result<(), String> {
    let path = op.attribute_path.as_str();
    let value = string(path, operation_value(op))?;
    match path.to_ascii_lowercase().as_str() {
        "displayname" => {
            group.display_name = Some(value.ok_or_else(|| "DisplayName is a required attribute.".to_string())?)
        }
        "description" => group.description = value,
        _ => return Err(unknown(path)),
    }
    Ok(())
}

fn unknown(path: &str) -> String {
    format!("Invalid attribute path {path}.")
}

/// The user's value at an attribute path, as text (for unique-attribute
/// lookups, filters and `${path:...}` access control attributes).
pub fn user_value(user: &types::User, path: &str) -> Vec<String> {
    let lower = path.to_ascii_lowercase();
    let one = |v: &Option<String>| v.iter().cloned().collect::<Vec<_>>();
    if let Some(rest) = path.strip_prefix("aws:identitystore:") {
        let (name, member) = rest.split_once('.').unwrap_or((rest, ""));
        let Some(doc) = user
            .extensions
            .as_ref()
            .and_then(|e| e.get(&format!("aws:identitystore:{name}")))
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
        else {
            return Vec::new();
        };
        let mut cur = &doc;
        for p in member.split('.').filter(|p| !p.is_empty()) {
            let found = cur.as_object().and_then(|o| o.iter().find(|(k, _)| k.eq_ignore_ascii_case(p)).map(|(_, v)| v));
            match found {
                Some(v) => cur = v,
                None => return Vec::new(),
            }
        }
        return match cur {
            Value::String(s) => vec![s.clone()],
            Value::Null => Vec::new(),
            other => vec![other.to_string()],
        };
    }
    let name = user.name.clone().unwrap_or_default();
    let primary_first = |values: Vec<(bool, Option<String>)>| {
        let mut v: Vec<(bool, String)> = values.into_iter().filter_map(|(p, v)| v.map(|v| (p, v))).collect();
        v.sort_by_key(|(p, _)| !*p);
        v.into_iter().map(|(_, v)| v).collect::<Vec<_>>()
    };
    let emails = || user.emails.iter().flatten().map(|e| (e.primary, e.value.clone())).collect();
    match lower.as_str() {
        "username" => one(&user.user_name),
        "displayname" => one(&user.display_name),
        "nickname" => one(&user.nick_name),
        "profileurl" => one(&user.profile_url),
        "usertype" => one(&user.user_type),
        "title" => one(&user.title),
        "preferredlanguage" => one(&user.preferred_language),
        "locale" => one(&user.locale),
        "timezone" => one(&user.timezone),
        "website" => one(&user.website),
        "birthdate" => one(&user.birthdate),
        "name.formatted" => one(&name.formatted),
        "name.familyname" => one(&name.family_name),
        "name.givenname" => one(&name.given_name),
        "name.middlename" => one(&name.middle_name),
        "name.honorificprefix" => one(&name.honorific_prefix),
        "name.honorificsuffix" => one(&name.honorific_suffix),
        "emails.value" | "emails" => primary_first(emails()),
        "emails.type" => primary_first(user.emails.iter().flatten().map(|e| (e.primary, e.r#type.clone())).collect()),
        "phonenumbers.value" => {
            primary_first(user.phone_numbers.iter().flatten().map(|e| (e.primary, e.value.clone())).collect())
        }
        "addresses.locality" => {
            primary_first(user.addresses.iter().flatten().map(|e| (e.primary, e.locality.clone())).collect())
        }
        "addresses.region" => {
            primary_first(user.addresses.iter().flatten().map(|e| (e.primary, e.region.clone())).collect())
        }
        "addresses.country" => {
            primary_first(user.addresses.iter().flatten().map(|e| (e.primary, e.country.clone())).collect())
        }
        "addresses.postalcode" => {
            primary_first(user.addresses.iter().flatten().map(|e| (e.primary, e.postal_code.clone())).collect())
        }
        "addresses.streetaddress" => {
            primary_first(user.addresses.iter().flatten().map(|e| (e.primary, e.street_address.clone())).collect())
        }
        _ => Vec::new(),
    }
}

/// Whether `path` names a user attribute a unique-attribute lookup accepts.
pub fn is_unique_user_attribute(path: &str) -> bool {
    matches!(path.to_ascii_lowercase().as_str(), "username" | "emails.value")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(path: &str, value: Value) -> types::AttributeOperation {
        types::AttributeOperation { attribute_path: path.into(), attribute_value: Some(value.to_string()) }
    }

    #[test]
    fn updates_simple_nested_and_extension_attributes() {
        let mut u = types::User::default();
        update_user(&mut u, &op("displayName", "Alice".into())).unwrap();
        update_user(&mut u, &op("name.givenName", "Al".into())).unwrap();
        update_user(&mut u, &op("emails", serde_json::json!([{"value": "a@x.com", "primary": true}]))).unwrap();
        update_user(&mut u, &op("aws:identitystore:enterprise.department", "eng".into())).unwrap();
        assert_eq!(u.display_name.as_deref(), Some("Alice"));
        assert_eq!(u.name.as_ref().unwrap().given_name.as_deref(), Some("Al"));
        assert_eq!(user_value(&u_with(&u.emails), "emails.value"), vec!["a@x.com"]);
        assert_eq!(user_value(&u, "aws:identitystore:enterprise.department"), vec!["eng"]);
        assert!(update_user(&mut u, &op("nope", "x".into())).is_err());
    }

    fn u_with(emails: &Option<Vec<types::Email>>) -> types::User {
        types::User { emails: emails.clone(), ..Default::default() }
    }
}
