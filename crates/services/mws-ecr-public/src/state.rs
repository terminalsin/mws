//! ECR Public state: one public registry per account. Times are epoch
//! milliseconds on the emulated clock.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub token_key: String,
    /// By account.
    pub registries: BTreeMap<String, Registry>,
}

impl State {
    /// The account's registry, created (with a default alias) on first use.
    pub fn registry_mut(&mut self, account: &str) -> &mut Registry {
        self.registries.entry(account.to_string()).or_insert_with(|| Registry {
            account: account.to_string(),
            alias: default_alias(),
            ..Default::default()
        })
    }

    /// The registry an account id or alias names.
    pub fn find(&self, id_or_alias: &str) -> Option<&Registry> {
        self.registries.get(id_or_alias).or_else(|| self.registries.values().find(|r| r.alias == id_or_alias))
    }

    pub fn account_of(&self, id_or_alias: &str) -> Option<String> {
        self.find(id_or_alias).map(|r| r.account.clone())
    }
}

/// A default alias as AWS assigns them: a letter and seven letters or
/// digits.
fn default_alias() -> String {
    const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut s = String::new();
    s.push(LETTERS[rand::random::<usize>() % LETTERS.len()] as char);
    for _ in 0..7 {
        s.push(ALNUM[rand::random::<usize>() % ALNUM.len()] as char);
    }
    s
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Registry {
    pub account: String,
    pub alias: String,
    pub display_name: String,
    pub repositories: BTreeMap<String, Repo>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Catalog {
    pub description: Option<String>,
    pub architectures: Option<Vec<String>>,
    pub operating_systems: Option<Vec<String>>,
    /// The logo's bytes, base64.
    pub logo: Option<String>,
    pub about_text: Option<String>,
    pub usage_text: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Repo {
    pub name: String,
    pub arn: String,
    pub created_at: i64,
    pub catalog: Catalog,
    pub tags: BTreeMap<String, String>,
    pub policy: Option<String>,
    pub content: mws_oci::Repository,
    /// When each tag was last pointed at an image.
    pub tag_times: BTreeMap<String, i64>,
}
