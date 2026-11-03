//! `GetRandomPassword`.

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::SecretsManager;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const PUNCTUATION: &str = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

fn random_index(rng: &SystemRandom, n: usize) -> usize {
    // Rejection sampling keeps the choice uniform.
    let limit = u32::MAX - (u32::MAX % n as u32);
    loop {
        let mut b = [0u8; 4];
        rng.fill(&mut b).expect("system random is available");
        let x = u32::from_le_bytes(b);
        if x < limit {
            return (x % n as u32) as usize;
        }
    }
}

/// A password as `GetRandomPassword` builds one.
pub fn generate(input: &types::GetRandomPasswordRequest) -> Result<String, ServiceError> {
    let length = input.password_length.unwrap_or(32);
    if !(1..=4096).contains(&length) {
        return Err(errors::invalid_parameter("Password length must be between 1 and 4096."));
    }
    let excluded: Vec<char> = input.exclude_characters.as_deref().unwrap_or_default().chars().collect();
    let mut classes: Vec<Vec<char>> = Vec::new();
    let mut add = |set: &str, skip: Option<bool>| {
        if !skip.unwrap_or(false) {
            let chars: Vec<char> = set.chars().filter(|c| !excluded.contains(c)).collect();
            if !chars.is_empty() {
                classes.push(chars);
            }
        }
    };
    add(LOWER, input.exclude_lowercase);
    add(UPPER, input.exclude_uppercase);
    add(DIGITS, input.exclude_numbers);
    add(PUNCTUATION, input.exclude_punctuation);
    if input.include_space.unwrap_or(false) {
        add(" ", None);
    }
    if classes.is_empty() {
        return Err(errors::invalid_parameter(
            "The password must include at least one character type. You excluded all of them.",
        ));
    }
    let length = length as usize;
    let require_each = input.require_each_included_type.unwrap_or(true);
    if require_each && length < classes.len() {
        return Err(errors::invalid_parameter(
            "The password length is too short to include every included character type.",
        ));
    }
    let rng = SystemRandom::new();
    let all: Vec<char> = classes.iter().flatten().copied().collect();
    loop {
        let password: Vec<char> = (0..length).map(|_| all[random_index(&rng, all.len())]).collect();
        if !require_each || classes.iter().all(|class| password.iter().any(|c| class.contains(c))) {
            return Ok(password.into_iter().collect());
        }
    }
}

impl SecretsManager {
    pub(crate) fn get_random_password(
        &self,
        ctx: &RequestContext,
        input: types::GetRandomPasswordRequest,
    ) -> Result<types::GetRandomPasswordResponse, ServiceError> {
        ctx.authorize("secretsmanager:GetRandomPassword", "*", ConditionContext::new())?;
        Ok(types::GetRandomPasswordResponse { random_password: Some(generate(&input)?) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honours_exclusions_and_requires_each_type() {
        let input = types::GetRandomPasswordRequest {
            password_length: Some(64),
            exclude_punctuation: Some(true),
            exclude_characters: Some("abc".into()),
            ..Default::default()
        };
        for _ in 0..50 {
            let p = generate(&input).unwrap();
            assert_eq!(p.len(), 64);
            assert!(p.chars().all(|c| c.is_ascii_alphanumeric() && !"abc".contains(c)));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
        }
    }

    #[test]
    fn rejects_excluding_everything() {
        let input = types::GetRandomPasswordRequest {
            exclude_lowercase: Some(true),
            exclude_uppercase: Some(true),
            exclude_numbers: Some(true),
            exclude_punctuation: Some(true),
            ..Default::default()
        };
        assert!(generate(&input).is_err());
    }
}
