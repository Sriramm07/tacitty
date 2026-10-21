//! The argument-classification logic behind `tacitty run`.
//!
//! `tacitty run <command> [args...]` runs `<command>`, first replacing any
//! `@alias` argument with the real secret from the vault, so the user types
//! `@alias` instead of the password. The resolved secret DOES end up in the
//! child's argv (visible in `ps` / `/proc/<pid>/cmdline`) — an accepted,
//! documented tradeoff for this command. The point is only to keep the
//! secret out of shell history, terminal scrollback, the clipboard and off
//! the screen; it is not hidden from `ps`.
//!
//! Deciding what becomes a secret is security-critical, so it lives here as
//! a pure function of (argument, trigger) that can be unit-tested
//! exhaustively. Substitution happens only when an argument's *value* is
//! exactly the trigger followed by a valid alias name — never as a
//! substring, so an email (`user@example.com`) or an scp path
//! (`user@host:/path`) is left untouched.

use crate::alias;

/// What to do with a single argument of the child command line.
#[derive(Debug, PartialEq, Eq)]
pub enum ArgAction {
    /// Leave the argument exactly as typed.
    Passthrough,
    /// Replace the argument with this literal text, with no vault lookup.
    /// Produced by the `@@` (doubled-trigger) escape; any `--flag=` prefix
    /// is already folded in (so `--p=@@x` yields `--p=@x`).
    Escape(String),
    /// Resolve `name` in the vault and substitute its secret. `flag` is the
    /// `--flag=` prefix to keep in front of the secret (empty for a
    /// whole-argument alias).
    Alias { flag: String, name: String },
}

/// Classify one argument against the trigger byte (`cfg.trigger_byte()`).
///
/// The rules, applied in order:
/// - For a `-x`/`--x` argument that contains `=`, only the part after the
///   FIRST `=` is a candidate; the flag itself is always kept. Otherwise the
///   whole argument is the candidate value.
/// - A value that starts with two triggers (`@@...`) is an escape: the
///   literal is one trigger + the rest, with no lookup.
/// - A value that is one trigger + a valid alias name is resolved.
/// - Anything else (a bare `@`, `@bad name`, `user@host`, a non-trigger
///   argument) is passed through untouched.
pub fn classify_arg(arg: &str, trigger: u8) -> ArgAction {
    // For `-x=value` style flags, split off the flag (up to and including
    // the first `=`) and test only the value after it.
    let (flag, value) = match arg.strip_prefix('-') {
        Some(_) => match arg.find('=') {
            Some(i) => (&arg[..=i], &arg[i + 1..]),
            None => ("", arg),
        },
        None => ("", arg),
    };

    // The value must *start* with the trigger to be anything but passthrough.
    if value.as_bytes().first() != Some(&trigger) {
        return ArgAction::Passthrough;
    }
    // The trigger is a single ASCII byte (enforced by `Config::validate`), so
    // byte index 1 is always a char boundary.
    let rest = &value[1..];

    // `@@...` escapes to a literal single trigger + the rest, no lookup.
    if rest.as_bytes().first() == Some(&trigger) {
        return ArgAction::Escape(format!("{flag}{rest}"));
    }

    // `@name` with a valid alias name: resolve it.
    if alias::validate(rest).is_ok() {
        return ArgAction::Alias {
            flag: flag.to_string(),
            name: rest.to_string(),
        };
    }

    // A bare `@`, `@bad name`, `@..`, etc.: not a valid alias, pass through.
    ArgAction::Passthrough
}

#[cfg(test)]
mod tests {
    use super::*;

    const AT: u8 = b'@';

    fn alias(flag: &str, name: &str) -> ArgAction {
        ArgAction::Alias {
            flag: flag.to_string(),
            name: name.to_string(),
        }
    }

    #[test]
    fn whole_arg_alias_resolves() {
        assert_eq!(classify_arg("@smtp", AT), alias("", "smtp"));
        assert_eq!(classify_arg("@prod-db", AT), alias("", "prod-db"));
        assert_eq!(classify_arg("@x.y_z/1", AT), alias("", "x.y_z/1"));
    }

    #[test]
    fn flag_value_alias_keeps_the_flag() {
        assert_eq!(classify_arg("--p=@smtp", AT), alias("--p=", "smtp"));
        assert_eq!(
            classify_arg("--auth-password=@smtp", AT),
            alias("--auth-password=", "smtp")
        );
        assert_eq!(classify_arg("-o=@smtp", AT), alias("-o=", "smtp"));
    }

    #[test]
    fn doubled_trigger_is_a_literal_escape() {
        assert_eq!(classify_arg("@@x", AT), ArgAction::Escape("@x".to_string()));
        assert_eq!(
            classify_arg("@@smtp", AT),
            ArgAction::Escape("@smtp".to_string())
        );
        // The remainder of an escape is NOT required to be a valid alias.
        assert_eq!(
            classify_arg("@@bad name", AT),
            ArgAction::Escape("@bad name".to_string())
        );
    }

    #[test]
    fn flag_value_doubled_trigger_keeps_flag_and_escapes() {
        assert_eq!(
            classify_arg("--p=@@x", AT),
            ArgAction::Escape("--p=@x".to_string())
        );
        assert_eq!(
            classify_arg("--auth-password=@@smtp", AT),
            ArgAction::Escape("--auth-password=@smtp".to_string())
        );
    }

    #[test]
    fn email_is_passed_through() {
        assert_eq!(classify_arg("user@example.com", AT), ArgAction::Passthrough);
    }

    #[test]
    fn scp_style_arg_is_passed_through() {
        assert_eq!(classify_arg("user@host:/path", AT), ArgAction::Passthrough);
    }

    #[test]
    fn bare_trigger_is_passed_through() {
        assert_eq!(classify_arg("@", AT), ArgAction::Passthrough);
    }

    #[test]
    fn invalid_alias_chars_pass_through() {
        assert_eq!(classify_arg("@bad name", AT), ArgAction::Passthrough);
        assert_eq!(classify_arg("@a..b", AT), ArgAction::Passthrough);
        assert_eq!(classify_arg("@.hidden", AT), ArgAction::Passthrough);
    }

    #[test]
    fn non_trigger_args_pass_through() {
        for a in ["swaks", "-tls", "--auth-password", "plainword", "-", "--"] {
            assert_eq!(classify_arg(a, AT), ArgAction::Passthrough, "{a}");
        }
    }

    #[test]
    fn a_hyphen_flag_without_equals_is_never_substituted() {
        // The value only exists after a `=`; `-@smtp` is a flag, not an alias.
        assert_eq!(classify_arg("-@smtp", AT), ArgAction::Passthrough);
    }

    #[test]
    fn a_custom_trigger_char_works() {
        let hash = b'#';
        assert_eq!(classify_arg("#smtp", hash), alias("", "smtp"));
        assert_eq!(classify_arg("--p=#smtp", hash), alias("--p=", "smtp"));
        assert_eq!(
            classify_arg("##x", hash),
            ArgAction::Escape("#x".to_string())
        );
        // With `#` as the trigger, an `@` argument is just text.
        assert_eq!(classify_arg("@smtp", hash), ArgAction::Passthrough);
        // And an email is still left alone.
        assert_eq!(
            classify_arg("user@example.com", hash),
            ArgAction::Passthrough
        );
    }
}
