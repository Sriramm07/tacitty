//! Group names: `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`, like aliases but
//! without `/`.
//!
//! Every alias belongs to exactly one group. Groups only organise aliases
//! for listing and exporting: alias names stay unique across the whole
//! vault, so `@proddb` means the same thing whichever group it is in. A
//! group exists while it holds at least one alias or is the vault's default
//! group (the one new aliases go into, initially [`DEFAULT`]).

/// The group every vault starts with, and the one aliases from an older
/// vault format are put in.
pub const DEFAULT: &str = "default";
pub const MAX_GROUP_LEN: usize = 64;

pub fn validate(s: &str) -> Result<(), String> {
    let b = s.as_bytes();
    if b.is_empty() {
        return Err("group name is empty".into());
    }
    if b.len() > MAX_GROUP_LEN {
        return Err(format!(
            "group name is longer than {MAX_GROUP_LEN} characters"
        ));
    }
    if !b[0].is_ascii_alphanumeric() {
        return Err("group name must start with a letter or digit".into());
    }
    if !b
        .iter()
        .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
    {
        return Err("group name may only contain letters, digits and . _ -".into());
    }
    Ok(())
}

pub fn is_valid(s: &str) -> bool {
    validate(s).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_good() {
        for g in ["default", "prod", "a", "Team-1.x_y", "9", &"g".repeat(64)] {
            assert!(is_valid(g), "{g}");
        }
    }

    #[test]
    fn rejects_bad() {
        for g in [
            "",
            "-x",
            ".x",
            "_x",
            "a/b",
            "a b",
            "a@b",
            "é",
            "prod\n",
            "\u{1b}[31m",
            &"g".repeat(65),
        ] {
            assert!(!is_valid(g), "{g:?}");
        }
    }
}
