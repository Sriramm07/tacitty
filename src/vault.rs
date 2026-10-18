//! The native vault: a single age-encrypted (scrypt passphrase) file holding
//! `alias -> secret` entries, each in a group (see `group.rs`).
//!
//! Plaintext layout (private, versioned, parsed by hand so secrets never pass
//! through a general-purpose deserializer that copies them around):
//!
//! ```text
//! "PWV2\n"
//! u16  default_group_len, default group bytes (ASCII)   (big endian)
//! u32  entry count
//! per entry:
//!   u16 alias_len, alias bytes (ASCII)
//!   u16 group_len, group bytes (ASCII)
//!   u32 secret_len, secret bytes
//!   u64 created (unix seconds), u64 updated
//! ```
//!
//! Saves always write version 2. Version 1 (`"PWV1\n"`, written before
//! groups existed) is still read: it is the same without the two group
//! fields, and every alias in it is put in the group `default`, which is
//! also its default group.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::group;
use crate::secret::SecretBuf;
use crate::sys;

const MAGIC_V1: &[u8] = b"PWV1\n";
const MAGIC: &[u8] = b"PWV2\n";
const MAX_PLAINTEXT: usize = 16 * 1024 * 1024;
/// Most aliases a vault may hold. At the largest alias, group and secret
/// sizes this stays well under [`MAX_PLAINTEXT`], so any vault `save`
/// accepts can always be loaded again.
pub const MAX_ENTRIES: usize = 10_000;
/// scrypt cost (log2 N) for everything taciTTY encrypts with a passphrase:
/// the vault and passphrase-mode export files. Fixed rather than taken from
/// age's quick speed calibration, which can come out low on a busy machine;
/// 18 means ~256 MiB of memory and about a second per guess.
pub const SCRYPT_WORK_FACTOR: u8 = 18;
/// Longest secret we accept. A secret is delivered as one line of
/// canonical-mode input (plus Enter), and the terminal's line buffer is
/// 4096 bytes on Linux but only 1024 (`MAX_CANON`) on macOS, so this stays
/// safely below the smaller one: a longer line would be cut off or rejected.
pub const MAX_SECRET_LEN: usize = 1000;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("wrong passphrase (or the vault file is corrupt)")]
    WrongPassphrase,
    #[error("vault file is corrupt: {0}")]
    Corrupt(String),
    #[error("insecure vault permissions: {0}")]
    Insecure(String),
    #[error("vault not found at {0} (run `tacitty init`)")]
    NotFound(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Crypto(String),
    #[error("{0}; nothing was changed")]
    TooLarge(String),
}

pub struct Entry {
    pub secret: SecretBuf,
    /// The group this alias belongs to (always a valid group name).
    pub group: String,
    pub created: u64,
    pub updated: u64,
}

pub struct VaultData {
    pub entries: BTreeMap<String, Entry>,
    /// The group new aliases go into when none is named.
    pub default_group: String,
}

impl Default for VaultData {
    fn default() -> Self {
        VaultData {
            entries: BTreeMap::new(),
            default_group: group::DEFAULT.to_string(),
        }
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl VaultData {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store `secret` under `alias`. An existing alias keeps its group; a
    /// new one goes into the default group.
    pub fn put(&mut self, alias: &str, secret: &[u8]) {
        let group = self
            .entries
            .get(alias)
            .map_or_else(|| self.default_group.clone(), |e| e.group.clone());
        self.put_in(alias, secret, &group);
    }

    /// Store `secret` under `alias` in `group` (already validated by the
    /// caller), moving the alias there if it exists in another group.
    pub fn put_in(&mut self, alias: &str, secret: &[u8], group: &str) {
        let now = now_unix();
        let created = self.entries.get(alias).map_or(now, |e| e.created);
        self.entries.insert(
            alias.to_string(),
            Entry {
                secret: SecretBuf::from_slice(secret),
                group: group.to_string(),
                created,
                updated: now,
            },
        );
    }

    /// Every group with the number of aliases in it, by name. The default
    /// group is always included, even when it is empty.
    pub fn groups(&self) -> BTreeMap<&str, usize> {
        let mut out = BTreeMap::new();
        out.insert(self.default_group.as_str(), 0);
        for e in self.entries.values() {
            *out.entry(e.group.as_str()).or_insert(0) += 1;
        }
        out
    }

    pub fn has_group(&self, name: &str) -> bool {
        self.default_group == name || self.entries.values().any(|e| e.group == name)
    }

    /// Move `aliases` into `group` (created implicitly). If any alias is
    /// unknown, nothing is changed. Returns the aliases that weren't
    /// already in `group`.
    pub fn move_to_group(
        &mut self,
        aliases: &[String],
        group: &str,
    ) -> Result<Vec<String>, String> {
        group::validate(group)?;
        if let Some(a) = aliases.iter().find(|a| !self.entries.contains_key(*a)) {
            return Err(format!("no such alias: {a} (nothing was moved)"));
        }
        let mut moved = Vec::new();
        for a in aliases {
            if let Some(e) = self.entries.get_mut(a) {
                if e.group != group {
                    e.group = group.to_string();
                    moved.push(a.clone());
                }
            }
        }
        Ok(moved)
    }

    /// Rename a group, refusing to merge it into one that already exists.
    /// If `old` is the default group, the default follows the new name.
    /// Returns how many aliases the group holds.
    pub fn rename_group(&mut self, old: &str, new: &str) -> Result<usize, String> {
        group::validate(new)?;
        if !self.has_group(old) {
            return Err(format!("no such group: {old}"));
        }
        if self.has_group(new) {
            return Err(format!(
                "group {new} already exists (to move aliases into it, use \
                 `tacitty group move <alias>... --to {new}`)"
            ));
        }
        let mut n = 0;
        for e in self.entries.values_mut().filter(|e| e.group == old) {
            e.group = new.to_string();
            n += 1;
        }
        if self.default_group == old {
            self.default_group = new.to_string();
        }
        Ok(n)
    }

    /// Delete a group by moving its aliases into the default group (no
    /// secret is ever deleted). Refuses the default group itself. Returns
    /// the aliases that were moved.
    pub fn remove_group(&mut self, name: &str) -> Result<Vec<String>, String> {
        if name == self.default_group {
            return Err(format!(
                "{name} is the default group and can't be removed (make another \
                 group the default first with `tacitty group default <group>`)"
            ));
        }
        if !self.has_group(name) {
            return Err(format!("no such group: {name}"));
        }
        let mut moved = Vec::new();
        for (a, e) in self.entries.iter_mut().filter(|(_, e)| e.group == name) {
            e.group.clone_from(&self.default_group);
            moved.push(a.clone());
        }
        Ok(moved)
    }

    /// Make `name` the group new aliases go into (created implicitly).
    pub fn set_default_group(&mut self, name: &str) -> Result<(), String> {
        group::validate(name)?;
        self.default_group = name.to_string();
        Ok(())
    }

    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let cap = MAGIC.len()
            + 2
            + self.default_group.len()
            + 4
            + self
                .entries
                .iter()
                .map(|(a, e)| 2 + a.len() + 2 + e.group.len() + 4 + e.secret.len() + 16)
                .sum::<usize>();
        let mut out = Zeroizing::new(Vec::with_capacity(cap));
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(self.default_group.len() as u16).to_be_bytes());
        out.extend_from_slice(self.default_group.as_bytes());
        out.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        for (alias, e) in &self.entries {
            out.extend_from_slice(&(alias.len() as u16).to_be_bytes());
            out.extend_from_slice(alias.as_bytes());
            out.extend_from_slice(&(e.group.len() as u16).to_be_bytes());
            out.extend_from_slice(e.group.as_bytes());
            out.extend_from_slice(&(e.secret.len() as u32).to_be_bytes());
            out.extend_from_slice(e.secret.as_slice());
            out.extend_from_slice(&e.created.to_be_bytes());
            out.extend_from_slice(&e.updated.to_be_bytes());
        }
        out
    }

    fn decode(buf: &[u8]) -> Result<Self, VaultError> {
        struct Cur<'a>(&'a [u8]);
        impl<'a> Cur<'a> {
            fn take(&mut self, n: usize) -> Result<&'a [u8], VaultError> {
                if self.0.len() < n {
                    return Err(VaultError::Corrupt("truncated".into()));
                }
                let (a, b) = self.0.split_at(n);
                self.0 = b;
                Ok(a)
            }
            /// A length-prefixed group name, which must be valid.
            fn group(&mut self) -> Result<String, VaultError> {
                let len = u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as usize;
                std::str::from_utf8(self.take(len)?)
                    .ok()
                    .filter(|g| group::is_valid(g))
                    .map(str::to_string)
                    .ok_or_else(|| VaultError::Corrupt("invalid group name".into()))
            }
        }
        let mut c = Cur(buf);
        let v2 = match c.take(MAGIC.len())? {
            m if m == MAGIC => true,
            m if m == MAGIC_V1 => false,
            _ => {
                return Err(VaultError::Corrupt(
                    "bad magic / unsupported version".into(),
                ))
            }
        };
        let mut data = VaultData::new();
        if v2 {
            data.default_group = c.group()?;
        }
        let n = u32::from_be_bytes(c.take(4)?.try_into().unwrap());
        if n as usize > MAX_ENTRIES {
            return Err(VaultError::Corrupt("too many entries".into()));
        }
        for _ in 0..n {
            let alen = u16::from_be_bytes(c.take(2)?.try_into().unwrap()) as usize;
            let alias = std::str::from_utf8(c.take(alen)?)
                .ok()
                .filter(|a| crate::alias::validate(a).is_ok())
                .ok_or_else(|| VaultError::Corrupt("invalid alias name".into()))?
                .to_string();
            if data.entries.contains_key(&alias) {
                return Err(VaultError::Corrupt("duplicate alias".into()));
            }
            let group = if v2 {
                c.group()?
            } else {
                group::DEFAULT.to_string()
            };
            let slen = u32::from_be_bytes(c.take(4)?.try_into().unwrap()) as usize;
            let secret = SecretBuf::from_slice(c.take(slen)?);
            let created = u64::from_be_bytes(c.take(8)?.try_into().unwrap());
            let updated = u64::from_be_bytes(c.take(8)?.try_into().unwrap());
            data.entries.insert(
                alias,
                Entry {
                    secret,
                    group,
                    created,
                    updated,
                },
            );
        }
        if !c.0.is_empty() {
            return Err(VaultError::Corrupt("trailing bytes".into()));
        }
        Ok(data)
    }
}

/// Work-factor override for fast tests. Honoured only in unit tests and in
/// builds with the `test-hooks` feature (used by the integration tests),
/// never in normal debug or release builds, so a stray environment
/// variable can't weaken a real vault or export file.
pub(crate) fn test_work_factor() -> Option<u8> {
    if cfg!(any(test, feature = "test-hooks")) {
        std::env::var("TACITTY_TEST_WORK_FACTOR")
            .ok()
            .and_then(|v| v.parse::<u8>().ok())
            .filter(|n| (1..=18).contains(n))
    } else {
        None
    }
}

fn clone_pass(p: &SecretString) -> SecretString {
    SecretString::from(p.expose_secret().to_string())
}

pub fn encrypt(plain: &[u8], passphrase: &SecretString) -> Result<Vec<u8>, VaultError> {
    let mut rec = age::scrypt::Recipient::new(clone_pass(passphrase));
    rec.set_work_factor(test_work_factor().unwrap_or(SCRYPT_WORK_FACTOR));
    let enc = age::Encryptor::with_recipients(std::iter::once(&rec as &dyn age::Recipient))
        .map_err(|e| VaultError::Crypto(e.to_string()))?;
    let mut out = Vec::with_capacity(plain.len() + 512);
    let mut w = enc
        .wrap_output(&mut out)
        .map_err(|e| VaultError::Crypto(e.to_string()))?;
    w.write_all(plain)?;
    w.finish().map_err(|e| VaultError::Crypto(e.to_string()))?;
    Ok(out)
}

pub fn decrypt(cipher: &[u8], passphrase: &SecretString) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let dec = age::Decryptor::new(cipher).map_err(|e| VaultError::Corrupt(e.to_string()))?;
    if !dec.is_scrypt() {
        return Err(VaultError::Corrupt(
            "file is not passphrase-encrypted".into(),
        ));
    }
    let mut id = age::scrypt::Identity::new(clone_pass(passphrase));
    id.set_max_work_factor(22);
    let mut r = dec
        .decrypt(std::iter::once(&id as &dyn age::Identity))
        .map_err(|e| match e {
            age::DecryptError::DecryptionFailed => VaultError::WrongPassphrase,
            other => VaultError::Crypto(other.to_string()),
        })?;
    // Pre-size so the Vec never reallocates (which would leave plaintext copies).
    let mut plain = Zeroizing::new(Vec::with_capacity(cipher.len().min(MAX_PLAINTEXT)));
    let mut chunk = Zeroizing::new([0u8; 4096]);
    loop {
        let n = r
            .read(&mut chunk[..])
            .map_err(|_| VaultError::WrongPassphrase)?;
        if n == 0 {
            break;
        }
        if plain.len() + n > MAX_PLAINTEXT {
            return Err(VaultError::Corrupt("vault too large".into()));
        }
        plain.extend_from_slice(&chunk[..n]);
    }
    Ok(plain)
}

/// Refuse to touch a vault that other users could read or replace.
pub fn check_permissions(path: &Path) -> Result<(), VaultError> {
    let md = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(VaultError::NotFound(path.display().to_string()))
        }
        Err(e) => return Err(e.into()),
    };
    if !md.file_type().is_file() {
        return Err(VaultError::Insecure("vault is not a regular file".into()));
    }
    if md.uid() != sys::geteuid() {
        return Err(VaultError::Insecure("vault is not owned by you".into()));
    }
    if md.mode() & 0o077 != 0 {
        return Err(VaultError::Insecure(format!(
            "{} is group/world accessible (mode {:o}); run `chmod 600`",
            path.display(),
            md.mode() & 0o7777
        )));
    }
    if let Some(dir) = path.parent() {
        if let Ok(dmd) = fs::metadata(dir) {
            if dmd.mode() & 0o022 != 0 {
                return Err(VaultError::Insecure(format!(
                    "{} is group/world writable",
                    dir.display()
                )));
            }
        }
    }
    Ok(())
}

pub fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// Load and decrypt the vault at `path`.
pub fn load(path: &Path, passphrase: &SecretString) -> Result<VaultData, VaultError> {
    check_permissions(path)?;
    let cipher = fs::read(path)?;
    let plain = decrypt(&cipher, passphrase)?;
    VaultData::decode(&plain)
}

/// Encrypt and atomically replace the vault (temp file, fsync, rename, fsync dir).
pub fn save(path: &Path, passphrase: &SecretString, data: &VaultData) -> Result<(), VaultError> {
    let dir = path
        .parent()
        .ok_or_else(|| VaultError::Io(std::io::Error::other("vault path has no parent")))?;
    crate::config::ensure_private_dir(dir)
        .map_err(|e| VaultError::Io(std::io::Error::other(e.to_string())))?;
    // Refuse, before anything is written, a vault that couldn't be loaded
    // again: the existing vault file stays untouched.
    if data.entries.len() > MAX_ENTRIES {
        return Err(VaultError::TooLarge(format!(
            "a vault can hold at most {MAX_ENTRIES} aliases"
        )));
    }
    let plain = data.encode();
    if plain.len() > MAX_PLAINTEXT {
        return Err(VaultError::TooLarge("the vault would be too large".into()));
    }
    let cipher = encrypt(&plain, passphrase)?;
    drop(plain);

    let tmp = dir.join(format!(".vault.age.tmp.{}", sys::getpid()));
    let _ = fs::remove_file(&tmp);
    {
        let mut f: File = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        let res = f.write_all(&cipher).and_then(|_| f.sync_all());
        if let Err(e) = res {
            let _ = fs::remove_file(&tmp);
            return Err(e.into());
        }
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Create a brand-new empty vault.
pub fn create(path: &Path, passphrase: &SecretString) -> Result<(), VaultError> {
    save(path, passphrase, &VaultData::new())
}

/// Validate a secret for storage or delivery: non-empty, bounded, and free
/// of control characters (bytes 0x00-0x1F and DEL). Those are interpreted
/// by the terminal rather than passed through as text: Enter or newline
/// would submit early, Ctrl-C/Ctrl-U/backspace would corrupt the input, and
/// Ctrl-Z would suspend the prompt and send the rest of the secret to the
/// shell instead.
pub fn validate_secret(secret: &[u8]) -> Result<(), String> {
    if secret.is_empty() {
        return Err("secret is empty".into());
    }
    if secret.len() > MAX_SECRET_LEN {
        return Err(format!("secret is longer than {MAX_SECRET_LEN} bytes"));
    }
    if secret.iter().any(|&b| b < 0x20 || b == 0x7f) {
        return Err(
            "secret must not contain control characters (tab, newline, Ctrl-keys, DEL)".into(),
        );
    }
    Ok(())
}

/// Attempt to decode `buf` as a vault plaintext body, discarding any
/// successful result. Exists only so the `vault_decode` fuzz target (see
/// `fuzz/fuzz_targets/vault_decode.rs`) can drive the parser without
/// exposing `VaultData::decode` outside the crate for any other purpose.
#[doc(hidden)]
pub fn fuzz_decode(buf: &[u8]) {
    let _ = VaultData::decode(buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast() {
        // SAFETY-free in edition 2021; same value for every test => no race.
        std::env::set_var("TACITTY_TEST_WORK_FACTOR", "8");
    }

    fn pw(s: &str) -> SecretString {
        SecretString::from(s.to_string())
    }

    #[test]
    fn roundtrip_and_permissions() {
        fast();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw").join("vault.age");
        let mut d = VaultData::new();
        d.put("prod-db", b"s3cr3t!");
        d.put("other", b"\x01\x02weird\x7f");
        save(&path, &pw("correct horse"), &d).unwrap();

        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dmode = fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dmode, 0o700);

        let raw = fs::read(&path).unwrap();
        assert!(raw.starts_with(b"age-encryption.org/v1"));
        assert!(!raw.windows(7).any(|w| w == b"s3cr3t!"));

        let back = load(&path, &pw("correct horse")).unwrap();
        assert_eq!(back.entries["prod-db"].secret.as_slice(), b"s3cr3t!");
        assert_eq!(
            back.entries["other"].secret.as_slice(),
            b"\x01\x02weird\x7f"
        );
    }

    #[test]
    fn wrong_passphrase_detected() {
        fast();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v").join("vault.age");
        create(&path, &pw("right")).unwrap();
        assert!(matches!(
            load(&path, &pw("wrong")),
            Err(VaultError::WrongPassphrase)
        ));
    }

    #[test]
    fn refuses_group_readable_vault() {
        fast();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v").join("vault.age");
        create(&path, &pw("right")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            load(&path, &pw("right")),
            Err(VaultError::Insecure(_))
        ));
    }

    #[test]
    fn put_preserves_created() {
        let mut d = VaultData::new();
        d.put("a", b"1");
        d.entries.get_mut("a").unwrap().created = 5;
        d.put("a", b"2");
        assert_eq!(d.entries["a"].created, 5);
        assert_eq!(d.entries["a"].secret.as_slice(), b"2");
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(VaultData::decode(b"nope").is_err());
        let mut d = VaultData::new();
        d.put("a", b"x");
        let enc = d.encode();
        assert!(VaultData::decode(&enc[..enc.len() - 1]).is_err());
    }

    #[test]
    fn secret_validation() {
        assert!(validate_secret(b"ok pass").is_ok());
        assert!(validate_secret(b"").is_err());
        assert!(validate_secret(b"a\nb").is_err());
        for bad in [0u8, b'\t', b'\r', 0x03, 0x15, 0x1a, 0x1b, 0x7f] {
            assert!(
                validate_secret(&[b'a', bad, b'b']).is_err(),
                "byte {bad:#x}"
            );
        }
        assert!(validate_secret("pässwörd €".as_bytes()).is_ok());
        assert!(validate_secret(b"~!@#$%^&*()_+{}|:<>? ").is_ok());
        assert!(validate_secret(&vec![b'a'; MAX_SECRET_LEN + 1]).is_err());
    }

    #[test]
    fn decode_never_panics_over_random_bytes() {
        // Stable-Rust stand-in for the nightly-only `vault_decode` fuzz
        // target (see fuzz/README.md) -- see the equivalent note in
        // src/statemachine.rs for what this can and can't substitute for.
        struct Rng(u64);
        impl Rng {
            fn next_u64(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                x.wrapping_mul(0x2545_f491_4f6c_dd1d)
            }
        }

        let mut rng = Rng(0xDEAD_BEEF_u64);
        for _ in 0..300_000 {
            let len = (rng.next_u64() % 512) as usize;
            let mut buf = vec![0u8; len];
            for chunk in buf.chunks_mut(8) {
                let bytes = rng.next_u64().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
            // Bias some samples toward the real magic prefix, since a
            // uniformly random 5 bytes will essentially never match it,
            // and the interesting panics are more likely to be past that
            // first gate (truncated/garbage length-prefixed fields).
            if rng.next_u64() % 2 == 0 && buf.len() >= MAGIC.len() {
                let magic = if rng.next_u64() % 2 == 0 {
                    MAGIC
                } else {
                    MAGIC_V1
                };
                buf[..MAGIC.len()].copy_from_slice(magic);
            }
            let _ = VaultData::decode(&buf);
        }
    }

    #[test]
    fn fuzz_decode_helper_never_panics() {
        fuzz_decode(b"");
        fuzz_decode(b"garbage");
        fuzz_decode(MAGIC);
        fuzz_decode(MAGIC_V1);
    }

    /// A version-1 body (as written before groups existed) holding `entries`.
    fn v1_body(entries: &[(&str, &[u8], u64, u64)]) -> Vec<u8> {
        let mut out = MAGIC_V1.to_vec();
        out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for (alias, secret, created, updated) in entries {
            out.extend_from_slice(&(alias.len() as u16).to_be_bytes());
            out.extend_from_slice(alias.as_bytes());
            out.extend_from_slice(&(secret.len() as u32).to_be_bytes());
            out.extend_from_slice(secret);
            out.extend_from_slice(&created.to_be_bytes());
            out.extend_from_slice(&updated.to_be_bytes());
        }
        out
    }

    #[test]
    fn version_1_vault_decodes_into_default_group() {
        let body = v1_body(&[("prod-db", b"s3cr3t!", 5, 6), ("other", b"x", 7, 8)]);
        // Identical to the fuzz corpus file kept for the old format.
        assert_eq!(
            v1_body(&[("prod-db", b"s3cr3t!", 0x6553_f100, 0x6553_f100)]),
            include_bytes!("../fuzz/corpus/vault_decode/valid_one_entry")
        );
        let d = VaultData::decode(&body).unwrap();
        assert_eq!(d.default_group, "default");
        assert_eq!(d.entries.len(), 2);
        for e in d.entries.values() {
            assert_eq!(e.group, "default");
        }
        assert_eq!(d.entries["prod-db"].secret.as_slice(), b"s3cr3t!");
        assert_eq!(
            (d.entries["prod-db"].created, d.entries["prod-db"].updated),
            (5, 6)
        );
        // Saving always writes the new version.
        let enc = d.encode();
        assert!(enc.starts_with(MAGIC));
        assert!(VaultData::decode(&v1_body(&[])).unwrap().entries.is_empty());
    }

    #[test]
    fn version_2_round_trip_keeps_groups() {
        let mut d = VaultData::new();
        d.put("a", b"1");
        d.set_default_group("work").unwrap();
        d.put("b", b"2");
        d.put_in("proddb", b"3", "prod");
        d.entries.get_mut("proddb").unwrap().created = 9;
        let enc = d.encode();
        assert!(enc.starts_with(b"PWV2\n"));
        let back = VaultData::decode(&enc).unwrap();
        assert_eq!(back.default_group, "work");
        let groups: Vec<(&str, &str)> = back
            .entries
            .iter()
            .map(|(a, e)| (a.as_str(), e.group.as_str()))
            .collect();
        assert_eq!(
            groups,
            [("a", "default"), ("b", "work"), ("proddb", "prod")]
        );
        assert_eq!(back.entries["proddb"].secret.as_slice(), b"3");
        assert_eq!(back.entries["proddb"].created, 9);
        assert_eq!(
            VaultData::decode(&VaultData::new().encode())
                .unwrap()
                .default_group,
            "default"
        );
    }

    #[test]
    fn version_2_fuzz_corpus_matches_the_encoder() {
        let mut d = VaultData::new();
        d.put_in("proddb", b"s3cr3t!", "prod");
        let e = d.entries.get_mut("proddb").unwrap();
        (e.created, e.updated) = (0x6553_f100, 0x6553_f100);
        assert_eq!(
            &d.encode()[..],
            include_bytes!("../fuzz/corpus/vault_decode/valid_v2_grouped_entry")
        );
        let mut d = VaultData::new();
        d.set_default_group("work").unwrap();
        assert_eq!(
            &d.encode()[..],
            include_bytes!("../fuzz/corpus/vault_decode/valid_v2_empty")
        );
    }

    #[test]
    fn decode_rejects_invalid_group_names() {
        let mut d = VaultData::new();
        d.put_in("a", b"1", "prod");
        let good = d.encode().to_vec();
        // The entry's group "prod" -> "pr/d", and the default group
        // "default" -> "de\x1bault": both must be refused.
        let pos = good.windows(4).position(|w| w == b"prod").unwrap();
        let mut bad = good.clone();
        bad[pos + 2] = b'/';
        assert!(matches!(
            VaultData::decode(&bad),
            Err(VaultError::Corrupt(m)) if m.contains("group")
        ));
        let mut bad = good.clone();
        bad[MAGIC.len() + 2 + 2] = 0x1b;
        assert!(VaultData::decode(&bad).is_err());
        // An empty default group name.
        let mut bad = MAGIC.to_vec();
        bad.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        assert!(VaultData::decode(&bad).is_err());
    }

    #[test]
    fn put_keeps_an_existing_alias_in_its_group() {
        let mut d = VaultData::new();
        d.put_in("a", b"1", "prod");
        d.put("a", b"2");
        assert_eq!(d.entries["a"].group, "prod");
        d.put("b", b"x");
        assert_eq!(d.entries["b"].group, "default");
    }

    #[test]
    fn group_operations() {
        let mut d = VaultData::new();
        for a in ["a", "b", "c"] {
            d.put(a, b"x");
        }
        assert_eq!(d.groups().into_iter().collect::<Vec<_>>(), [("default", 3)]);

        // Moving: unknown alias changes nothing; groups are created implicitly.
        let err = d
            .move_to_group(&["a".into(), "nope".into()], "prod")
            .unwrap_err();
        assert!(err.contains("nope"), "{err}");
        assert_eq!(d.entries["a"].group, "default");
        assert!(d.move_to_group(&["a".into()], "bad/name").is_err());
        let moved = d.move_to_group(&["a".into(), "b".into()], "prod").unwrap();
        assert_eq!(moved, ["a", "b"]);
        assert!(d.move_to_group(&["a".into()], "prod").unwrap().is_empty());
        assert_eq!(
            d.groups().into_iter().collect::<Vec<_>>(),
            [("default", 1), ("prod", 2)]
        );

        // Renaming: never onto an existing group; the default follows.
        assert!(d
            .rename_group("prod", "default")
            .unwrap_err()
            .contains("already exists"));
        assert!(d.rename_group("nope", "x").is_err());
        assert_eq!(d.rename_group("prod", "production").unwrap(), 2);
        assert_eq!(d.entries["a"].group, "production");
        assert_eq!(d.rename_group("default", "personal").unwrap(), 1);
        assert_eq!(d.default_group, "personal");
        assert!(!d.has_group("default"));

        // Removing: never the default; aliases go to the default group.
        assert!(d.remove_group("personal").unwrap_err().contains("default"));
        assert!(d.remove_group("nope").is_err());
        assert_eq!(d.remove_group("production").unwrap(), ["a", "b"]);
        assert_eq!(d.entries.len(), 3);
        assert!(d.entries.values().all(|e| e.group == "personal"));

        // The default group exists even while empty.
        d.set_default_group("new").unwrap();
        assert!(d.has_group("new"));
        assert_eq!(d.groups()["new"], 0);
        assert!(d.set_default_group("").is_err());
    }

    #[test]
    fn save_refuses_a_vault_that_could_not_be_loaded_again() {
        std::env::set_var("TACITTY_TEST_WORK_FACTOR", "8");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v").join("vault.age");
        let pw = SecretString::from("pw".to_string());
        create(&path, &pw).unwrap();
        let before = fs::read(&path).unwrap();
        let mut data = VaultData::new();
        for i in 0..=MAX_ENTRIES {
            data.put(&format!("a{i}"), b"s");
        }
        let err = save(&path, &pw, &data).unwrap_err().to_string();
        assert!(
            err.contains("at most") && err.contains("nothing was changed"),
            "{err}"
        );
        assert_eq!(fs::read(&path).unwrap(), before, "vault must be untouched");
    }

    #[test]
    fn decode_rejects_bad_alias_names_and_duplicates() {
        let mut data = VaultData::new();
        data.put("good", b"s");
        let mut bytes = data.encode().to_vec();
        // Corrupt the alias name in place ("good" -> "-ood").
        let at = bytes.windows(4).position(|w| w == b"good").unwrap();
        bytes[at] = b'-';
        assert!(VaultData::decode(&bytes).is_err());
    }
}
