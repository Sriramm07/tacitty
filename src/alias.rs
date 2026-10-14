//! Alias syntax: `^[A-Za-z0-9][A-Za-z0-9._/-]{0,63}$`, plus a few extra
//! restrictions so an alias can never be abused as a path (pass backend) or
//! smuggle a `..` segment.

pub const MAX_ALIAS_LEN: usize = 64;

/// May this byte appear anywhere in an alias?
pub fn is_alias_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-')
}

/// May this byte start an alias?
pub fn is_alias_start_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

pub fn validate(s: &str) -> Result<(), String> {
    let b = s.as_bytes();
    if b.is_empty() {
        return Err("alias is empty".into());
    }
    if b.len() > MAX_ALIAS_LEN {
        return Err(format!("alias is longer than {MAX_ALIAS_LEN} characters"));
    }
    if !is_alias_start_byte(b[0]) {
        return Err("alias must start with a letter or digit".into());
    }
    if !b.iter().all(|&c| is_alias_byte(c)) {
        return Err("alias may only contain letters, digits and . _ / -".into());
    }
    if s.contains("..") || s.contains("//") || s.ends_with('/') {
        return Err("alias must not contain '..', '//' or end with '/'".into());
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
        for a in ["prod-db", "a", "x.y_z/1", "A9", &"a".repeat(64)] {
            assert!(is_valid(a), "{a}");
        }
    }

    #[test]
    fn rejects_bad() {
        for a in [
            "",
            "-x",
            ".x",
            "/x",
            "a b",
            "a@b",
            "a..b",
            "a//b",
            "a/",
            "é",
            &"a".repeat(65),
            "a\n",
        ] {
            assert!(!is_valid(a), "{a:?}");
        }
    }
}
