//! The native vault: a single age-encrypted (scrypt passphrase) file holding
//! `alias -> secret` entries.
//!
//! Plaintext layout (private, versioned, parsed by hand so secrets never pass
//! through a general-purpose deserializer that copies them around):
//!
//! ```text
//! "PWV1\n"
//! u32  entry count                       (big endian)
//! per entry:
//!   u16 alias_len, alias bytes (ASCII)
//!   u32 secret_len, secret bytes
//!   u64 created (unix seconds), u64 updated
//! ```

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::secret::SecretBuf;
use crate::sys;

const MAGIC: &[u8] = b"PWV1\n";
const MAX_PLAINTEXT: usize = 16 * 1024 * 1024;
/// Longest secret we accept (keeps the worst-case quoted payload well below
/// the kernel's 4096-byte canonical line limit).
pub const MAX_SECRET_LEN: usize = 1024;

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
}

pub struct Entry {
    pub secret: SecretBuf,
    pub created: u64,
    pub updated: u64,
}

#[derive(Default)]
pub struct VaultData {
    pub entries: BTreeMap<String, Entry>,
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

    pub fn put(&mut self, alias: &str, secret: &[u8]) {
        let now = now_unix();
        let created = self.entries.get(alias).map_or(now, |e| e.created);
        self.entries.insert(
            alias.to_string(),
            Entry {
                secret: SecretBuf::from_slice(secret),
                created,
                updated: now,
            },
        );
    }

    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let cap = MAGIC.len()
            + 4
            + self
                .entries
                .iter()
                .map(|(a, e)| 2 + a.len() + 4 + e.secret.len() + 16)
                .sum::<usize>();
        let mut out = Zeroizing::new(Vec::with_capacity(cap));
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        for (alias, e) in &self.entries {
            out.extend_from_slice(&(alias.len() as u16).to_be_bytes());
            out.extend_from_slice(alias.as_bytes());
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
        }
        let mut c = Cur(buf);
        if c.take(MAGIC.len())? != MAGIC {
            return Err(VaultError::Corrupt(
                "bad magic / unsupported version".into(),
            ));
        }
        let n = u32::from_be_bytes(c.take(4)?.try_into().unwrap());
        let mut data = VaultData::new();
        for _ in 0..n {
            let alen = u16::from_be_bytes(c.take(2)?.try_into().unwrap()) as usize;
            let alias = std::str::from_utf8(c.take(alen)?)
                .map_err(|_| VaultError::Corrupt("non-UTF-8 alias".into()))?
                .to_string();
            let slen = u32::from_be_bytes(c.take(4)?.try_into().unwrap()) as usize;
            let secret = SecretBuf::from_slice(c.take(slen)?);
            let created = u64::from_be_bytes(c.take(8)?.try_into().unwrap());
            let updated = u64::from_be_bytes(c.take(8)?.try_into().unwrap());
            data.entries.insert(
                alias,
                Entry {
                    secret,
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

/// Work-factor override for fast tests. Honoured ONLY in debug builds.
fn test_work_factor() -> Option<u8> {
    if cfg!(debug_assertions) {
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
    if let Some(n) = test_work_factor() {
        rec.set_work_factor(n);
    }
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
    let plain = data.encode();
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

/// Validate a secret for storage: non-empty, bounded, and free of bytes that
/// can never be delivered through a terminal line (`\n`, `\r`, NUL).
pub fn validate_secret(secret: &[u8]) -> Result<(), String> {
    if secret.is_empty() {
        return Err("secret is empty".into());
    }
    if secret.len() > MAX_SECRET_LEN {
        return Err(format!("secret is longer than {MAX_SECRET_LEN} bytes"));
    }
    if secret.iter().any(|&b| matches!(b, b'\n' | b'\r' | 0)) {
        return Err("secret must not contain newline, carriage return or NUL".into());
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
                buf[..MAGIC.len()].copy_from_slice(MAGIC);
            }
            let _ = VaultData::decode(&buf);
        }
    }

    #[test]
    fn fuzz_decode_helper_never_panics() {
        fuzz_decode(b"");
        fuzz_decode(b"garbage");
        fuzz_decode(MAGIC);
    }
}
