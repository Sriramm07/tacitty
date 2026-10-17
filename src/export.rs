//! Sharing aliases with other people: `tacitty export` / `tacitty import`.
//!
//! An export file is a standard [age](https://age-encryption.org/v1) file
//! (so `age -d` / `rage -d` can open it too) whose plaintext is a FIDO
//! Alliance Credential Exchange Format (CXF) v1.0 JSON document:
//!
//! ```text
//! { "version": {"major":1,"minor":0}, "exporterRpId": "tacitty",
//!   "exporterDisplayName": "taciTTY", "timestamp": <unix secs>,
//!   "accounts": [ { "id", "username": "", "email": "",
//!     "collections": [ { "id", "title": "<group>", "items": [ { "item": "<item id>" } ] } ],
//!     "items": [ { "id", "creationAt", "modifiedAt", "title": "<alias>",
//!       "credentials": [ { "type": "basic-auth", "password":
//!         { "fieldType": "concealed-string", "value": "<secret>" } } ] } ] } ] }
//! ```
//!
//! Groups travel as CXF collections: one per exported group, titled with
//! the group name and linking (by item id) to the aliases in it. On import
//! an item goes into the group named by the first collection that links to
//! it, if that title is a valid group name, unless the importer picks a
//! group with `--group`.
//!
//! It is encrypted either with a passphrase (age scrypt) or to one or more
//! public keys (age X25519 `age1...`, `ssh-ed25519`, `ssh-rsa`), optionally
//! ASCII-armored. Nothing here talks to a network: moving the file is up to
//! the user.
//!
//! Secrets stay in self-wiping buffers throughout: the JSON is serialized
//! straight into a [`SecretBuf`], the decrypted plaintext is read into one,
//! and on import each password is captured as a borrowed [`RawValue`] (raw
//! JSON text inside that buffer, not a copy) and unescaped by hand into its
//! own [`SecretBuf`]. Letting serde_json decode the string instead would
//! unescape it through the deserializer's internal scratch `Vec`, which is
//! never wiped. The structs are flat for the reason given on
//! `agent::Request`.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age_core::format::{FileKey, Stanza};
use base64::Engine as _;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::alias;
use crate::group;
use crate::secret::SecretBuf;
use crate::sys;
use crate::vault::{self, VaultData};

/// `exporterRpId` written into every export.
pub const EXPORTER_RP_ID: &str = "tacitty";
/// `exporterDisplayName` written into every export.
pub const EXPORTER_DISPLAY_NAME: &str = "taciTTY";
/// Shortest export passphrase accepted: once the file has been shared,
/// the passphrase is all that protects it against offline guessing.
pub const MIN_PASSPHRASE_CHARS: usize = 12;
/// Upper bound on an export file, its plaintext, and a key file. Far above
/// anything a real vault produces (secrets are at most 1 KiB each).
const MAX_FILE: usize = 16 * 1024 * 1024;
const MAX_KEY_FILE: u64 = 1024 * 1024;
const ARMOR_BEGIN: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";

#[derive(Debug, Error)]
pub enum ExportError {
    #[error("{0}")]
    Invalid(String),
    #[error("wrong passphrase (or the file is corrupt)")]
    WrongPassphrase,
    #[error("none of the identities can decrypt this file")]
    NoMatchingIdentity,
    #[error("{0}")]
    Format(String),
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Crypto(String),
}

// ---------------------------------------------------------------------------
// CXF encoding
// ---------------------------------------------------------------------------

/// One vault entry to export. Borrowed: the secret stays in the vault's
/// own buffer until it is serialized.
pub struct ExportEntry<'a> {
    pub alias: &'a str,
    pub group: &'a str,
    pub secret: &'a [u8],
    pub created: u64,
    pub updated: u64,
}

#[derive(Serialize, Deserialize)]
struct Version {
    major: u64,
    #[serde(default)]
    minor: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HeaderOut<'a> {
    version: Version,
    exporter_rp_id: &'static str,
    exporter_display_name: &'static str,
    timestamp: u64,
    accounts: [AccountOut<'a>; 1],
}

#[derive(Serialize)]
struct AccountOut<'a> {
    id: String,
    username: &'static str,
    email: &'static str,
    collections: Vec<CollectionOut<'a>>,
    items: Vec<ItemOut<'a>>,
}

/// A CXF Collection: one per exported group.
#[derive(Serialize)]
struct CollectionOut<'a> {
    id: String,
    title: &'a str,
    items: Vec<LinkedItemOut>,
}

/// A CXF LinkedItem: the `id` of an item in the same account.
#[derive(Serialize)]
struct LinkedItemOut {
    item: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ItemOut<'a> {
    id: String,
    creation_at: u64,
    modified_at: u64,
    title: &'a str,
    credentials: [CredentialOut<'a>; 1],
}

#[derive(Serialize)]
struct CredentialOut<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    password: FieldOut<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FieldOut<'a> {
    field_type: &'static str,
    value: &'a str,
}

/// A fresh random CXF identifier: 16 bytes, base64url without padding.
/// Random rather than derived from the alias, so ids carry no information.
fn random_id() -> Result<String, ExportError> {
    let mut raw = [0u8; 16];
    sys::getrandom(&mut raw)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw))
}

/// Serialize `entries` as a CXF document into a self-wiping buffer.
/// Fails (naming the alias) if a secret isn't valid UTF-8, since CXF
/// strings can't carry arbitrary bytes.
pub fn encode_cxf(entries: &[ExportEntry<'_>], timestamp: u64) -> Result<SecretBuf, ExportError> {
    let mut items = Vec::with_capacity(entries.len());
    let mut groups: BTreeMap<&str, Vec<LinkedItemOut>> = BTreeMap::new();
    for e in entries {
        let value = std::str::from_utf8(e.secret).map_err(|_| {
            ExportError::Invalid(format!(
                "@{}: secret is not valid UTF-8 text, which the export format can't \
                 represent; nothing was exported",
                e.alias
            ))
        })?;
        let id = random_id()?;
        groups
            .entry(e.group)
            .or_default()
            .push(LinkedItemOut { item: id.clone() });
        items.push(ItemOut {
            id,
            creation_at: e.created,
            modified_at: e.updated,
            title: e.alias,
            credentials: [CredentialOut {
                kind: "basic-auth",
                password: FieldOut {
                    field_type: "concealed-string",
                    value,
                },
            }],
        });
    }
    let mut collections = Vec::with_capacity(groups.len());
    for (title, items) in groups {
        collections.push(CollectionOut {
            id: random_id()?,
            title,
            items,
        });
    }
    let header = HeaderOut {
        version: Version { major: 1, minor: 0 },
        exporter_rp_id: EXPORTER_RP_ID,
        exporter_display_name: EXPORTER_DISPLAY_NAME,
        timestamp,
        accounts: [AccountOut {
            id: random_id()?,
            username: "",
            email: "",
            collections,
            items,
        }],
    };
    let mut out = SecretBuf::with_capacity(
        512 + entries
            .iter()
            .map(|e| 384 + e.alias.len() + e.group.len() + 2 * e.secret.len())
            .sum::<usize>(),
    );
    serde_json::to_writer(&mut out, &header)
        .map_err(|e| ExportError::Format(format!("encoding export: {e}")))?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// CXF decoding
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct HeaderIn<'a> {
    version: Version,
    #[serde(default, borrow)]
    accounts: Vec<AccountIn<'a>>,
}

#[derive(Deserialize)]
struct AccountIn<'a> {
    #[serde(default)]
    id: String,
    #[serde(default)]
    collections: Vec<CollectionIn>,
    #[serde(default, borrow)]
    items: Vec<ItemIn<'a>>,
}

/// A CXF Collection. Nesting depth is bounded by serde_json's recursion
/// limit.
#[derive(Deserialize)]
struct CollectionIn {
    #[serde(default)]
    title: String,
    #[serde(default)]
    items: Vec<LinkedItemIn>,
    #[serde(default, rename = "subCollections")]
    sub_collections: Vec<CollectionIn>,
}

#[derive(Deserialize)]
struct LinkedItemIn {
    #[serde(default)]
    item: String,
    /// The owning account's id; absent means the collection's own account.
    #[serde(default)]
    account: Option<String>,
}

#[derive(Deserialize)]
struct ItemIn<'a> {
    #[serde(default)]
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default, borrow)]
    credentials: Vec<CredentialIn<'a>>,
}

#[derive(Deserialize)]
struct CredentialIn<'a> {
    #[serde(rename = "type", default)]
    kind: String,
    /// Kept as raw JSON: only interpreted once `kind` says it is a
    /// basic-auth password, so an unknown credential type with a
    /// differently shaped `password` field can't fail the whole import.
    #[serde(default, borrow)]
    password: Option<&'a RawValue>,
}

#[derive(Deserialize)]
struct FieldIn<'a> {
    #[serde(default, borrow)]
    value: Option<&'a RawValue>,
}

/// An alias ready to be added to a vault.
pub struct ImportedItem {
    pub alias: String,
    pub secret: SecretBuf,
    /// The group named by the first collection that links to this item,
    /// if there is one and its title is a valid group name.
    pub collection: Option<String>,
}

/// An item that was not imported. `title` is already safe to print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub title: String,
    pub reason: String,
}

pub struct Decoded {
    pub items: Vec<ImportedItem>,
    pub skipped: Vec<Skipped>,
    /// Titles (safe to print) of collections holding imported items that
    /// aren't valid group names; those items get no `collection`.
    pub bad_collections: Vec<String>,
}

/// Map each `(account id, item id)` to the title of the first collection
/// (depth first, in file order) that links to it.
fn index_collections<'h>(
    account: &'h str,
    collections: &'h [CollectionIn],
    out: &mut HashMap<(&'h str, &'h str), &'h str>,
) {
    for c in collections {
        for link in &c.items {
            let owner = link.account.as_deref().unwrap_or(account);
            out.entry((owner, link.item.as_str()))
                .or_insert(c.title.as_str());
        }
        index_collections(account, &c.sub_collections, out);
    }
}

/// Make an untrusted title safe to print on a terminal: printable ASCII is
/// kept, everything else (escape sequences, bidi controls, ...) is shown
/// escaped, and long titles are cut short.
pub fn display_title(title: &str) -> String {
    if title.is_empty() {
        return "(untitled)".into();
    }
    let mut out = String::new();
    for (n, c) in title.chars().enumerate() {
        if n == 64 {
            out.push_str("...");
            break;
        }
        if c.is_ascii_graphic() || c == ' ' {
            out.push(c);
        } else {
            out.extend(c.escape_default());
        }
    }
    out
}

/// Decode a JSON string literal (quotes included, already validated as
/// JSON by serde_json) straight into a self-wiping buffer. `None` if it
/// isn't a string or has a malformed escape.
fn unescape_json_string(raw: &str) -> Option<SecretBuf> {
    fn hex4(b: &[u8]) -> Option<u32> {
        if b.len() != 4 || !b.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        b.iter()
            .try_fold(0u32, |acc, &d| Some(acc << 4 | (d as char).to_digit(16)?))
    }
    let inner = raw
        .trim()
        .as_bytes()
        .strip_prefix(b"\"")?
        .strip_suffix(b"\"")?;
    let mut out = SecretBuf::with_capacity(inner.len());
    let mut i = 0;
    while i < inner.len() {
        let c = inner[i];
        if c != b'\\' {
            out.push(c);
            i += 1;
            continue;
        }
        let esc = *inner.get(i + 1)?;
        i += 2;
        let byte = match esc {
            b'"' => b'"',
            b'\\' => b'\\',
            b'/' => b'/',
            b'b' => 0x08,
            b'f' => 0x0c,
            b'n' => b'\n',
            b'r' => b'\r',
            b't' => b'\t',
            b'u' => {
                let hi = hex4(inner.get(i..i + 4)?)?;
                i += 4;
                let cp = match hi {
                    0xD800..=0xDBFF => {
                        if inner.get(i..i + 2)? != b"\\u" {
                            return None;
                        }
                        let lo = hex4(inner.get(i + 2..i + 6)?)?;
                        if !(0xDC00..=0xDFFF).contains(&lo) {
                            return None;
                        }
                        i += 6;
                        0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                    }
                    0xDC00..=0xDFFF => return None,
                    _ => hi,
                };
                let mut tmp = [0u8; 4];
                out.extend_from_slice(char::from_u32(cp)?.encode_utf8(&mut tmp).as_bytes());
                tmp.zeroize();
                continue;
            }
            _ => return None,
        };
        out.push(byte);
    }
    Some(out)
}

/// The password of a `basic-auth` credential, or why there isn't a usable one.
fn basic_auth_password(raw: &RawValue) -> Result<SecretBuf, String> {
    let field: FieldIn<'_> = serde_json::from_str(raw.get())
        .map_err(|_| "its password field is malformed".to_string())?;
    let value = field
        .value
        .ok_or_else(|| "its password field has no value".to_string())?;
    let secret =
        unescape_json_string(value.get()).ok_or_else(|| "its password is not text".to_string())?;
    if std::str::from_utf8(secret.as_slice()).is_err() {
        return Err("its password is not valid UTF-8".into());
    }
    Ok(secret)
}

/// Parse a CXF document. Items that can't become an alias are returned in
/// [`Decoded::skipped`] with a reason; unknown fields, credential types and
/// enum values are ignored, as CXF requires of importers. Reasons never
/// contain secret material.
pub fn decode_cxf(plain: &[u8]) -> Result<Decoded, ExportError> {
    // serde_json's own messages can quote the offending value, so only its
    // position is reported.
    let header: HeaderIn<'_> = serde_json::from_slice(plain).map_err(|e| {
        ExportError::Format(format!(
            "the decrypted file is not a valid CXF document (JSON error at line {}, column {})",
            e.line(),
            e.column()
        ))
    })?;
    if header.version.major != 1 {
        return Err(ExportError::Format(format!(
            "unsupported CXF version {}.{} (this taciTTY reads version 1.x)",
            header.version.major, header.version.minor
        )));
    }
    let mut out = Decoded {
        items: Vec::new(),
        skipped: Vec::new(),
        bad_collections: Vec::new(),
    };
    let mut in_collection = HashMap::new();
    for a in &header.accounts {
        index_collections(&a.id, &a.collections, &mut in_collection);
    }
    let items = header
        .accounts
        .iter()
        .flat_map(|a| a.items.iter().map(move |i| (a.id.as_str(), i)));
    for (account, item) in items {
        let title = display_title(&item.title);
        let mut skip = |reason: String| {
            out.skipped.push(Skipped {
                title: title.clone(),
                reason,
            })
        };
        let Some(raw) = item
            .credentials
            .iter()
            .filter(|c| c.kind == "basic-auth")
            .find_map(|c| c.password)
        else {
            let mut kinds: Vec<String> = item
                .credentials
                .iter()
                .map(|c| display_title(&c.kind))
                .collect();
            kinds.dedup();
            skip(if kinds.is_empty() {
                "it has no credentials".into()
            } else {
                format!("no password credential (has: {})", kinds.join(", "))
            });
            continue;
        };
        let secret = match basic_auth_password(raw) {
            Ok(s) => s,
            Err(reason) => {
                skip(reason);
                continue;
            }
        };
        if let Err(e) = alias::validate(&item.title) {
            skip(format!("title is not a valid alias name ({e})"));
            continue;
        }
        if let Err(e) = vault::validate_secret(secret.as_slice()) {
            skip(format!("its password can't be used: {e}"));
            continue;
        }
        if out.items.iter().any(|i| i.alias == item.title) {
            skip("appears more than once in the file (kept the first)".into());
            continue;
        }
        let collection = match in_collection.get(&(account, item.id.as_str())) {
            Some(c) if group::is_valid(c) => Some(c.to_string()),
            Some(c) => {
                let shown = display_title(c);
                if !out.bad_collections.contains(&shown) {
                    out.bad_collections.push(shown);
                }
                None
            }
            None => None,
        };
        out.items.push(ImportedItem {
            alias: item.title.clone(),
            secret,
            collection,
        });
    }
    Ok(out)
}

/// One alias written by [`merge_into`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Imported {
    pub alias: String,
    pub group: String,
    /// It already existed and was replaced (`--overwrite`).
    pub replaced: bool,
}

/// What [`merge_into`] did.
#[derive(Debug, Default)]
pub struct ImportReport {
    pub imported: Vec<Imported>,
    pub skipped: Vec<Skipped>,
}

/// Add decoded items to `data`. Each goes into `group` if given, else the
/// group its collection names, else the vault's default group; a replaced
/// alias moves to that group too. Existing aliases are left alone (and
/// reported) unless `overwrite`. Timestamps are those of the import: the
/// file's are only informational. `group` must already be validated.
pub fn merge_into(
    data: &mut VaultData,
    decoded: Decoded,
    overwrite: bool,
    group: Option<&str>,
) -> ImportReport {
    let mut report = ImportReport {
        skipped: decoded.skipped,
        ..Default::default()
    };
    for item in decoded.items {
        let exists = data.entries.contains_key(&item.alias);
        if exists && !overwrite {
            report.skipped.push(Skipped {
                title: item.alias,
                reason: "already in your vault (use --overwrite to replace it)".into(),
            });
            continue;
        }
        let target = group
            .or(item.collection.as_deref())
            .unwrap_or(&data.default_group)
            .to_string();
        data.put_in(&item.alias, item.secret.as_slice(), &target);
        report.imported.push(Imported {
            alias: item.alias,
            group: target,
            replaced: exists,
        });
    }
    report
}

// ---------------------------------------------------------------------------
// Recipients and identities
// ---------------------------------------------------------------------------

pub type BoxedRecipient = Box<dyn age::Recipient + Send>;

/// A key as it may appear in an error message: public, but long.
fn short_key(s: &str) -> String {
    let s = display_title(s);
    if s.chars().count() > 30 {
        format!("{}...", s.chars().take(30).collect::<String>())
    } else {
        s
    }
}

/// Parse one public key: an age X25519 recipient (`age1...`) or an SSH
/// public key in authorized_keys form (`ssh-ed25519 AAAA... [comment]`,
/// `ssh-rsa ...` of at least 2048 bits).
pub fn parse_recipient(s: &str) -> Result<BoxedRecipient, String> {
    if looks_private(s) {
        return Err(PRIVATE_KEY_GIVEN.into());
    }
    let mut words = s.split_whitespace();
    let Some(first) = words.next() else {
        return Err("empty key".into());
    };
    if first.starts_with("age1") {
        if words.next().is_some() {
            return Err(format!(
                "unexpected text after the age key `{}`",
                short_key(first)
            ));
        }
        return first
            .parse::<age::x25519::Recipient>()
            .map(|r| Box::new(r) as BoxedRecipient)
            .map_err(|_| {
                format!(
                    "`{}` is not a valid age X25519 recipient (age plugin and \
                     post-quantum recipients aren't supported)",
                    short_key(first)
                )
            });
    }
    let not_a_key = || {
        format!(
            "`{}` is not an age key (age1...) or an SSH public key \
             (ssh-ed25519 / ssh-rsa)",
            short_key(s.trim())
        )
    };
    // The comment, if any, is dropped: only "type base64" is parsed.
    let Some(body) = words.next() else {
        return Err(not_a_key());
    };
    use age::ssh::ParseRecipientKeyError as E;
    match format!("{first} {body}").parse::<age::ssh::Recipient>() {
        Ok(r) => Ok(Box::new(r)),
        Err(E::Unsupported(t)) => Err(format!(
            "unsupported SSH key type `{}` (use ssh-ed25519 or ssh-rsa)",
            display_title(&t)
        )),
        Err(E::RsaModulusTooSmall) => Err("ssh-rsa key is shorter than 2048 bits".into()),
        Err(E::RsaModulusTooLarge) => Err("ssh-rsa key is larger than supported".into()),
        Err(_) => Err(not_a_key()),
    }
}

const PRIVATE_KEY_GIVEN: &str = "this is a private key, not a public key (give the \
     public one: age1... or the contents of a .pub file)";

/// Does this look like private key material? Such text is never repeated
/// back in an error message, not even shortened.
fn looks_private(s: &str) -> bool {
    let s = s.trim_start();
    s.get(..15)
        .is_some_and(|p| p.eq_ignore_ascii_case("AGE-SECRET-KEY-"))
        || s.contains("PRIVATE KEY")
}

/// Resolve one `--with-key` value. Text starting with `age1`,
/// `ssh-ed25519 ` or `ssh-rsa ` is a public key; anything else is the path
/// of a key file (see [`parse_recipients`]).
pub fn recipients_from_arg(value: &str) -> Result<Vec<BoxedRecipient>, String> {
    let v = value.trim();
    if ["age1", "ssh-ed25519 ", "ssh-rsa "]
        .iter()
        .any(|p| v.starts_with(p))
    {
        return parse_recipient(v).map(|r| vec![r]);
    }
    let path = Path::new(value);
    if fs::symlink_metadata(path).is_ok() {
        return read_recipients_file(path);
    }
    if looks_private(v) {
        return Err(PRIVATE_KEY_GIVEN.into());
    }
    // Another kind of key (ecdsa, ...): let the parser say why it can't be used.
    if v.contains(char::is_whitespace) && (v.starts_with("ssh-") || v.starts_with("ecdsa-")) {
        return parse_recipient(v).map(|r| vec![r]);
    }
    Err(format!(
        "`{}` is not a public key (age1..., ssh-ed25519 or ssh-rsa) or an existing key file",
        display_title(value)
    ))
}

/// Parse a recipients file (authorized_keys / GitHub `.keys` style): one
/// key per line, blank lines and `#` comments skipped. Any other line that
/// isn't a usable key is an error rather than being dropped, so nobody is
/// silently left out.
pub fn parse_recipients(text: &str, source: &str) -> Result<Vec<BoxedRecipient>, String> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        out.push(parse_recipient(line).map_err(|e| format!("{source}, line {}: {e}", n + 1))?);
    }
    if out.is_empty() {
        return Err(format!("{source} contains no keys"));
    }
    Ok(out)
}

/// Read and parse a recipients file.
pub fn read_recipients_file(path: &Path) -> Result<Vec<BoxedRecipient>, String> {
    let text =
        read_limited(path, MAX_KEY_FILE).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let text =
        String::from_utf8(text).map_err(|_| format!("{} is not a text file", path.display()))?;
    parse_recipients(&text, &path.display().to_string())
}

fn read_limited(path: &Path, max: u64) -> io::Result<Vec<u8>> {
    let f = File::open(path)?;
    let mut buf = Vec::new();
    f.take(max + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        return Err(io::Error::other("file is too large"));
    }
    Ok(buf)
}

/// Asks the user for an SSH key's passphrase; `None` if they can't be asked.
pub type AskPassphrase = fn(&str) -> Option<SecretString>;

/// A passphrase-protected SSH private key that only asks for its
/// passphrase when the file was actually encrypted to it (age's own
/// wrapper asks for every stanza of every file, matching or not).
struct LockedSshKey {
    key: age::ssh::Identity,
    /// age's stanza tag for this key: base64 of SHA-256(public key)[..4].
    tag: String,
    label: String,
    ask: AskPassphrase,
}

impl LockedSshKey {
    fn new(key: age::ssh::Identity, label: String, ask: AskPassphrase) -> Option<Self> {
        use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
        let public = age::ssh::Recipient::try_from(key.clone()).ok()?.to_string();
        let blob = STANDARD.decode(public.split_once(' ')?.1).ok()?;
        let tag = STANDARD_NO_PAD.encode(&Sha256::digest(&blob)[..4]);
        Some(LockedSshKey {
            key,
            tag,
            label,
            ask,
        })
    }
}

impl age::Identity for LockedSshKey {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
        self.unwrap_stanzas(std::slice::from_ref(stanza))
    }

    fn unwrap_stanzas(&self, stanzas: &[Stanza]) -> Option<Result<FileKey, age::DecryptError>> {
        let mine = stanzas.iter().any(|s| {
            matches!(s.tag.as_str(), "ssh-ed25519" | "ssh-rsa") && s.args.first() == Some(&self.tag)
        });
        let age::ssh::Identity::Encrypted(enc) = &self.key else {
            return None;
        };
        if !mine {
            return None;
        }
        let pass = (self.ask)(&format!("Passphrase for SSH key {}: ", self.label))?;
        let unlocked: age::ssh::Identity = match enc.decrypt(pass) {
            Ok(k) => k.into(),
            Err(e) => return Some(Err(e)),
        };
        age::Identity::unwrap_stanzas(&unlocked, stanzas)
    }
}

/// Load the identities in `path`: an age identity file (`AGE-SECRET-KEY-1...`
/// lines) or an OpenSSH / PEM `ssh-ed25519` or `ssh-rsa` private key. For a
/// passphrase-protected SSH key, `ask` is called only if a file to decrypt
/// was actually encrypted to that key.
pub fn load_identities(
    path: &Path,
    ask: AskPassphrase,
) -> Result<Vec<Box<dyn age::Identity>>, ExportError> {
    let label = path.display().to_string();
    let data = Zeroizing::new(
        read_limited(path, MAX_KEY_FILE)
            .map_err(|e| ExportError::Invalid(format!("reading {label}: {e}")))?,
    );
    let has = |needle: &[u8]| data.windows(needle.len()).any(|w| w == needle);
    if has(b"AGE-SECRET-KEY-1") {
        let ids = age::IdentityFile::from_buffer(&data[..])
            .and_then(|f| f.into_identities().map_err(io::Error::other))
            .map_err(|e| ExportError::Invalid(format!("{label}: {e}")))?;
        return Ok(ids
            .into_iter()
            .map(|i| i as Box<dyn age::Identity>)
            .collect());
    }
    if has(b"PRIVATE KEY-----") {
        let key =
            age::ssh::Identity::from_buffer(&data[..], Some(label.clone())).map_err(|_| {
                ExportError::Invalid(format!("{label}: not a readable SSH private key"))
            })?;
        return match key {
            age::ssh::Identity::Unencrypted(_) => Ok(vec![Box::new(key)]),
            age::ssh::Identity::Encrypted(_) => {
                let locked = LockedSshKey::new(key, label.clone(), ask).ok_or_else(|| {
                    ExportError::Invalid(format!("{label}: unsupported SSH private key"))
                })?;
                Ok(vec![Box::new(locked)])
            }
            age::ssh::Identity::Unsupported(_) => Err(ExportError::Invalid(format!(
                "{label}: unsupported SSH key type (only ssh-ed25519 and ssh-rsa keys can \
                 decrypt age files)"
            ))),
        };
    }
    let hint = if data.starts_with(b"ssh-") || data.starts_with(b"age1") {
        " (this looks like a public key; pass the matching private key)"
    } else {
        ""
    };
    Err(ExportError::Invalid(format!(
        "{label} is not an age identity file or an SSH private key{hint}"
    )))
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

/// How an export is protected.
pub enum Protection {
    Passphrase(SecretString),
    Recipients(Vec<BoxedRecipient>),
}

/// Check an export passphrase before using it.
pub fn check_passphrase(p: &SecretString) -> Result<(), String> {
    let n = p.expose_secret().chars().count();
    if n == 0 {
        return Err("export passphrase must not be empty".into());
    }
    if n < MIN_PASSPHRASE_CHARS {
        return Err(format!(
            "export passphrase must be at least {MIN_PASSPHRASE_CHARS} characters long \
             (it is all that protects the file once it has been shared)"
        ));
    }
    Ok(())
}

/// Encrypt `plain` as an age file, binary or ASCII-armored.
pub fn encrypt(plain: &[u8], protection: &Protection, armor: bool) -> Result<Vec<u8>, ExportError> {
    let crypto = |e: age::EncryptError| ExportError::Crypto(e.to_string());
    let scrypt;
    let recipients: Vec<&dyn age::Recipient> = match protection {
        Protection::Passphrase(p) => {
            let mut r =
                age::scrypt::Recipient::new(SecretString::from(p.expose_secret().to_string()));
            if let Some(n) = vault::test_work_factor() {
                r.set_work_factor(n);
            }
            scrypt = r;
            vec![&scrypt]
        }
        Protection::Recipients(rs) if rs.is_empty() => {
            return Err(ExportError::Invalid("no recipients given".into()))
        }
        Protection::Recipients(rs) => rs.iter().map(|r| &**r as &dyn age::Recipient).collect(),
    };
    let enc = age::Encryptor::with_recipients(recipients.into_iter()).map_err(crypto)?;
    let mut out = Vec::with_capacity(plain.len() * 2 + 1024);
    let format = if armor {
        Format::AsciiArmor
    } else {
        Format::Binary
    };
    let armored = ArmoredWriter::wrap_output(&mut out, format)?;
    let mut w = enc.wrap_output(armored)?;
    w.write_all(plain)?;
    w.finish()?.finish()?;
    Ok(out)
}

/// What an export file's age header says about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileKind {
    pub armored: bool,
    /// Passphrase (scrypt) encrypted, as opposed to encrypted to public keys.
    pub passphrase: bool,
}

pub fn inspect(cipher: &[u8]) -> Result<FileKind, ExportError> {
    let start = cipher
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(cipher.len());
    let armored = cipher[start..].starts_with(ARMOR_BEGIN);
    let dec = age::Decryptor::new(ArmoredReader::new(cipher)).map_err(not_age)?;
    Ok(FileKind {
        armored,
        passphrase: dec.is_scrypt(),
    })
}

fn not_age(_: age::DecryptError) -> ExportError {
    ExportError::Format("not an age-encrypted file (or it is damaged)".into())
}

fn decrypt_error(e: age::DecryptError) -> ExportError {
    use age::DecryptError as D;
    match e {
        D::DecryptionFailed => ExportError::WrongPassphrase,
        D::NoMatchingKeys => ExportError::NoMatchingIdentity,
        D::KeyDecryptionFailed => {
            ExportError::Crypto("could not unlock the SSH private key (wrong passphrase?)".into())
        }
        D::ExcessiveWork { .. } => ExportError::Crypto(
            "the file's passphrase work factor is higher than taciTTY allows".into(),
        ),
        D::InvalidHeader | D::InvalidMac | D::UnknownFormat => {
            ExportError::Format("the file is damaged or was modified".into())
        }
        other => ExportError::Crypto(other.to_string()),
    }
}

/// Decrypt a passphrase-encrypted export.
pub fn decrypt_with_passphrase(
    cipher: &[u8],
    passphrase: &SecretString,
) -> Result<SecretBuf, ExportError> {
    let mut id =
        age::scrypt::Identity::new(SecretString::from(passphrase.expose_secret().to_string()));
    id.set_max_work_factor(22);
    decrypt(cipher, std::iter::once(&id as &dyn age::Identity))
}

/// Decrypt a public-key-encrypted export with any of `identities`.
pub fn decrypt_with_identities(
    cipher: &[u8],
    identities: &[Box<dyn age::Identity>],
) -> Result<SecretBuf, ExportError> {
    decrypt(cipher, identities.iter().map(|i| &**i))
}

fn decrypt<'a>(
    cipher: &[u8],
    identities: impl Iterator<Item = &'a dyn age::Identity>,
) -> Result<SecretBuf, ExportError> {
    let dec = age::Decryptor::new(ArmoredReader::new(cipher)).map_err(not_age)?;
    let mut r = dec.decrypt(identities).map_err(decrypt_error)?;
    let mut plain = SecretBuf::with_capacity(cipher.len().min(MAX_FILE));
    let mut chunk = Zeroizing::new([0u8; 4096]);
    loop {
        let n = r
            .read(&mut chunk[..])
            .map_err(|_| ExportError::Format("the file is damaged or was modified".into()))?;
        if n == 0 {
            break;
        }
        if plain.len() + n > MAX_FILE {
            return Err(ExportError::Format("the file is too large".into()));
        }
        plain.extend_from_slice(&chunk[..n]);
    }
    Ok(plain)
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/// Read an export file (ciphertext; bounded in size).
pub fn read_export_file(path: &Path) -> Result<Vec<u8>, ExportError> {
    read_limited(path, MAX_FILE as u64)
        .map_err(|e| ExportError::Invalid(format!("reading {}: {e}", path.display())))
}

/// Can an export be written to `path`? Checked up front so nobody types
/// passphrases only to be told the file exists.
pub fn check_output_path(path: &Path, force: bool) -> Result<(), ExportError> {
    if path.as_os_str() == "-" {
        return Err(ExportError::Invalid(
            "refusing to write the export to stdout; give a file name with -o".into(),
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(_) if !force => Err(ExportError::Invalid(format!(
            "{} already exists (pass --force to replace it)",
            path.display()
        ))),
        Ok(md) if !md.file_type().is_file() => Err(ExportError::Invalid(format!(
            "refusing to replace {}: not a regular file",
            path.display()
        ))),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn create_private(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = create_private(path)?;
    let res = f.write_all(bytes).and_then(|_| f.sync_all());
    if res.is_err() {
        let _ = fs::remove_file(path);
    }
    res
}

/// Write an export file with mode 0600. A new file is created exclusively
/// (never following a symlink); with `force` an existing regular file is
/// replaced atomically via a temp file in the same directory.
pub fn write_export_file(path: &Path, bytes: &[u8], force: bool) -> Result<(), ExportError> {
    check_output_path(path, force)?;
    let exists = fs::symlink_metadata(path).is_ok();
    if !exists {
        return write_synced(path, bytes)
            .map_err(|e| ExportError::Invalid(format!("writing {}: {e}", path.display())));
    }
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .ok_or_else(|| ExportError::Invalid(format!("{} is not a file name", path.display())))?;
    let tmp = dir.join(format!(
        ".{}.tacitty-tmp.{}",
        name.to_string_lossy(),
        sys::getpid()
    ));
    let _ = fs::remove_file(&tmp);
    write_synced(&tmp, bytes)
        .map_err(|e| ExportError::Invalid(format!("writing {}: {e}", tmp.display())))?;
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(ExportError::Invalid(format!(
            "replacing {}: {e}",
            path.display()
        )));
    }
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fast() {
        // Same value as vault.rs's tests use => no race between tests.
        std::env::set_var("TACITTY_TEST_WORK_FACTOR", "8");
    }

    fn pw(s: &str) -> SecretString {
        SecretString::from(s.to_string())
    }

    fn entries<'a>(list: &'a [(&'a str, &'a [u8])]) -> Vec<ExportEntry<'a>> {
        list.iter()
            .map(|(alias, secret)| ExportEntry {
                alias,
                group: "default",
                secret,
                created: 100,
                updated: 200,
            })
            .collect()
    }

    fn sample() -> SecretBuf {
        let list: [(&str, &[u8]); 3] = [
            ("proddb", b"s3cr3t!"),
            ("root/pw", "qu\"ote\\back/sl\u{e4}sh \u{1F511}".as_bytes()),
            ("x", b"~!@#$%^&*()_+{}|:<>? "),
        ];
        encode_cxf(&entries(&list), 1_700_000_000).unwrap()
    }

    fn secret_of<'a>(d: &'a Decoded, alias: &str) -> &'a [u8] {
        d.items
            .iter()
            .find(|i| i.alias == alias)
            .unwrap()
            .secret
            .as_slice()
    }

    #[test]
    fn cxf_round_trip() {
        let plain = sample();
        let v: serde_json::Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(v["version"]["major"], 1);
        assert_eq!(v["version"]["minor"], 0);
        assert_eq!(v["exporterRpId"], "tacitty");
        assert_eq!(v["exporterDisplayName"], "taciTTY");
        assert_eq!(v["timestamp"], 1_700_000_000u64);
        let acct = &v["accounts"][0];
        assert_eq!(acct["username"], "");
        let item = &acct["items"][0];
        let colls = acct["collections"].as_array().unwrap();
        assert_eq!(colls.len(), 1);
        assert_eq!(colls[0]["title"], "default");
        assert_eq!(colls[0]["items"].as_array().unwrap().len(), 3);
        assert_eq!(colls[0]["items"][0]["item"], item["id"]);
        assert_eq!(item["title"], "proddb");
        assert_eq!(item["creationAt"], 100);
        assert_eq!(item["modifiedAt"], 200);
        let id = item["id"].as_str().unwrap();
        assert!(id.len() <= 86 && !id.contains(['=', '+', '/']), "{id}");
        assert_ne!(id, acct["items"][1]["id"].as_str().unwrap());
        let cred = &item["credentials"][0];
        assert_eq!(cred["type"], "basic-auth");
        assert_eq!(cred["password"]["fieldType"], "concealed-string");
        assert_eq!(cred["password"]["value"], "s3cr3t!");

        let d = decode_cxf(&plain).unwrap();
        assert!(d.skipped.is_empty(), "{:?}", d.skipped);
        assert_eq!(d.items.len(), 3);
        assert_eq!(secret_of(&d, "proddb"), b"s3cr3t!");
        assert_eq!(
            secret_of(&d, "root/pw"),
            "qu\"ote\\back/sl\u{e4}sh \u{1F511}".as_bytes()
        );
        assert_eq!(secret_of(&d, "x"), b"~!@#$%^&*()_+{}|:<>? ");
    }

    #[test]
    fn non_utf8_secret_is_refused_by_name() {
        let list: [(&str, &[u8]); 1] = [("binary", b"\xff\xfe")];
        let err = encode_cxf(&entries(&list), 0).unwrap_err().to_string();
        assert!(err.contains("@binary"), "{err}");
    }

    #[test]
    fn unescape_handles_json_escapes() {
        let s = unescape_json_string(r#""a\"b\\c\/d\u00e4\ud83d\udd11\n""#).unwrap();
        assert_eq!(s.as_slice(), "a\"b\\c/d\u{e4}\u{1F511}\n".as_bytes());
        for bad in [
            r#""\ud83d""#,
            r#""\udd11""#,
            r#""\x""#,
            r#""\u12""#,
            r#""\u+0041""#,
            "123",
            r#""a\"#,
        ] {
            assert!(unescape_json_string(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn passphrase_round_trip_and_wrong_passphrase() {
        fast();
        let prot = Protection::Passphrase(pw("long enough passphrase"));
        let cipher = encrypt(&sample(), &prot, false).unwrap();
        assert!(cipher.starts_with(b"age-encryption.org/v1\n"));
        assert!(!cipher.windows(7).any(|w| w == b"s3cr3t!"));
        assert_eq!(
            inspect(&cipher).unwrap(),
            FileKind {
                armored: false,
                passphrase: true
            }
        );
        let plain = decrypt_with_passphrase(&cipher, &pw("long enough passphrase")).unwrap();
        assert_eq!(
            secret_of(&decode_cxf(&plain).unwrap(), "proddb"),
            b"s3cr3t!"
        );
        assert!(matches!(
            decrypt_with_passphrase(&cipher, &pw("not the passphrase")),
            Err(ExportError::WrongPassphrase)
        ));
    }

    #[test]
    fn passphrase_rules() {
        assert!(check_passphrase(&pw("")).unwrap_err().contains("empty"));
        assert!(check_passphrase(&pw("elevenchars"))
            .unwrap_err()
            .contains("at least 12"));
        assert!(check_passphrase(&pw("twelve chars")).is_ok());
        // Counted in characters, not bytes.
        assert!(check_passphrase(&pw("\u{e4}\u{e4}\u{e4}\u{e4}\u{e4}\u{e4}")).is_err());
    }

    fn write_identity(dir: &Path, id: &age::x25519::Identity) -> std::path::PathBuf {
        let path = dir.join("key.txt");
        let text = format!("# created: test\n{}\n", id.to_string().expose_secret());
        fs::write(&path, text).unwrap();
        path
    }

    fn no_ask(_: &str) -> Option<SecretString> {
        panic!("should not ask for a passphrase")
    }

    #[test]
    fn x25519_round_trip_and_wrong_identity() {
        let dir = tempfile::tempdir().unwrap();
        let id = age::x25519::Identity::generate();
        let r = parse_recipient(&id.to_public().to_string()).unwrap();
        let cipher = encrypt(&sample(), &Protection::Recipients(vec![r]), false).unwrap();
        assert!(cipher.starts_with(b"age-encryption.org/v1\n"));
        assert!(!inspect(&cipher).unwrap().passphrase);

        let ids = load_identities(&write_identity(dir.path(), &id), no_ask).unwrap();
        let plain = decrypt_with_identities(&cipher, &ids).unwrap();
        assert_eq!(
            secret_of(&decode_cxf(&plain).unwrap(), "proddb"),
            b"s3cr3t!"
        );

        let other = tempfile::tempdir().unwrap();
        let wrong = age::x25519::Identity::generate();
        let ids = load_identities(&write_identity(other.path(), &wrong), no_ask).unwrap();
        assert!(matches!(
            decrypt_with_identities(&cipher, &ids),
            Err(ExportError::NoMatchingIdentity)
        ));
    }

    #[test]
    fn armored_round_trip() {
        fast();
        let prot = Protection::Passphrase(pw("long enough passphrase"));
        let cipher = encrypt(&sample(), &prot, true).unwrap();
        assert!(cipher.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----\n"));
        assert!(cipher.is_ascii());
        assert_eq!(
            inspect(&cipher).unwrap(),
            FileKind {
                armored: true,
                passphrase: true
            }
        );
        let plain = decrypt_with_passphrase(&cipher, &pw("long enough passphrase")).unwrap();
        assert_eq!(decode_cxf(&plain).unwrap().items.len(), 3);
    }

    /// A throwaway SSH key from `ssh-keygen`, or `None` (test skipped) if
    /// it isn't installed.
    fn ssh_keygen(dir: &Path, kind: &str, passphrase: &str) -> Option<std::path::PathBuf> {
        let key = dir.join(format!("id_{kind}"));
        let mut cmd = std::process::Command::new("ssh-keygen");
        cmd.args(["-q", "-t", kind, "-N", passphrase, "-C", "test@host", "-f"])
            .arg(&key);
        if kind == "rsa" {
            cmd.args(["-b", "2048"]);
        }
        match cmd.status() {
            Ok(s) if s.success() => Some(key),
            _ => {
                eprintln!("note: ssh-keygen not available, skipping SSH {kind} test");
                None
            }
        }
    }

    #[test]
    fn ssh_ed25519_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let Some(key) = ssh_keygen(dir.path(), "ed25519", "") else {
            return;
        };
        let public = fs::read_to_string(key.with_extension("pub")).unwrap();
        assert!(public.trim_end().ends_with("test@host"));
        let recipients = parse_recipients(&public, "key.pub").unwrap();
        let cipher = encrypt(&sample(), &Protection::Recipients(recipients), false).unwrap();
        let ids = load_identities(&key, no_ask).unwrap();
        let plain = decrypt_with_identities(&cipher, &ids).unwrap();
        assert_eq!(
            secret_of(&decode_cxf(&plain).unwrap(), "proddb"),
            b"s3cr3t!"
        );
    }

    #[test]
    fn ssh_rsa_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let Some(key) = ssh_keygen(dir.path(), "rsa", "") else {
            return;
        };
        let public = fs::read_to_string(key.with_extension("pub")).unwrap();
        let r = parse_recipient(&public).unwrap();
        let cipher = encrypt(&sample(), &Protection::Recipients(vec![r]), true).unwrap();
        let ids = load_identities(&key, no_ask).unwrap();
        let plain = decrypt_with_identities(&cipher, &ids).unwrap();
        assert_eq!(decode_cxf(&plain).unwrap().items.len(), 3);
    }

    static ASKED: AtomicUsize = AtomicUsize::new(0);

    fn ask_right(_: &str) -> Option<SecretString> {
        ASKED.fetch_add(1, Ordering::SeqCst);
        Some(pw("key passphrase"))
    }

    fn ask_wrong(_: &str) -> Option<SecretString> {
        Some(pw("nope"))
    }

    #[test]
    fn encrypted_ssh_key_asks_only_when_it_matches() {
        let dir = tempfile::tempdir().unwrap();
        let Some(key) = ssh_keygen(dir.path(), "ed25519", "key passphrase") else {
            return;
        };
        let public = fs::read_to_string(key.with_extension("pub")).unwrap();
        let cipher = encrypt(
            &sample(),
            &Protection::Recipients(vec![parse_recipient(&public).unwrap()]),
            false,
        )
        .unwrap();

        // A file for someone else: no prompt, clean "no identity" error.
        let other = age::x25519::Identity::generate();
        let not_mine = encrypt(
            &sample(),
            &Protection::Recipients(vec![Box::new(other.to_public())]),
            false,
        )
        .unwrap();
        let ids = load_identities(&key, ask_right).unwrap();
        assert!(matches!(
            decrypt_with_identities(&not_mine, &ids),
            Err(ExportError::NoMatchingIdentity)
        ));
        assert_eq!(ASKED.load(Ordering::SeqCst), 0);

        let plain = decrypt_with_identities(&cipher, &ids).unwrap();
        assert_eq!(ASKED.load(Ordering::SeqCst), 1);
        assert_eq!(decode_cxf(&plain).unwrap().items.len(), 3);

        let ids = load_identities(&key, ask_wrong).unwrap();
        let err = decrypt_with_identities(&cipher, &ids).unwrap_err();
        assert!(err.to_string().contains("SSH private key"), "{err}");
    }

    #[test]
    fn recipients_file_parsing() {
        let a = age::x25519::Identity::generate().to_public().to_string();
        let b = age::x25519::Identity::generate().to_public().to_string();
        let text = format!("# team keys\n\n{a}\n   \n  # indented comment\n{b}\n");
        assert_eq!(parse_recipients(&text, "team.keys").unwrap().len(), 2);

        let err = parse_recipients(&format!("{a}\n# c\nnot-a-key\n"), "team.keys")
            .err()
            .unwrap();
        assert!(err.contains("team.keys, line 3"), "{err}");
        assert!(err.contains("not an age key"), "{err}");

        assert!(parse_recipients("# nothing\n\n", "empty.keys")
            .err()
            .unwrap()
            .contains("no keys"));
        assert!(parse_recipient("age1notavalidkey")
            .err()
            .unwrap()
            .contains("not a valid age"));
        assert!(parse_recipient(&format!("{a} trailing"))
            .err()
            .unwrap()
            .contains("unexpected text"));

        // A well-formed key of a type age can't encrypt to.
        let mut blob = Vec::new();
        for part in [&b"ecdsa-sha2-nistp256"[..], b"nistp256", &[4u8; 65]] {
            blob.extend_from_slice(&(part.len() as u32).to_be_bytes());
            blob.extend_from_slice(part);
        }
        let ecdsa = format!(
            "ecdsa-sha2-nistp256 {} me@host",
            base64::engine::general_purpose::STANDARD.encode(&blob)
        );
        let err = parse_recipients(&format!("{a}\n{ecdsa}\n"), "k")
            .err()
            .unwrap();
        assert!(
            err.contains("line 2") && err.contains("unsupported SSH key type"),
            "{err}"
        );
    }

    fn doc(items: &str) -> Vec<u8> {
        format!(
            r#"{{"version":{{"major":1,"minor":0}},"exporterRpId":"x","exporterDisplayName":"X",
               "timestamp":1,"accounts":[{{"id":"AA","username":"","email":"",
               "collections":[],"items":[{items}]}}]}}"#
        )
        .into_bytes()
    }

    fn item(title: &str, creds: &str) -> String {
        let title = serde_json::to_string(title).unwrap();
        format!(r#"{{"id":"AQ","title":{title},"credentials":[{creds}]}}"#)
    }

    fn basic(value: &str) -> String {
        format!(
            r#"{{"type":"basic-auth","password":{{"fieldType":"concealed-string","value":{value}}}}}"#
        )
    }

    #[test]
    fn invalid_items_are_skipped_without_showing_secrets() {
        let items = [
            item("good", &basic(r#""fine-secret""#)),
            item("bad alias!", &basic(r#""hidden-one""#)),
            item("ctl", &basic(r#""hidden\u0003two""#)),
            item("newline", &basic(r#""hidden\nthree""#)),
            item("empty", &basic(r#""""#)),
            item("notext", &basic("42")),
            item("good", &basic(r#""second-copy""#)),
            item("\u{1b}[31mevil", &basic(r#""x""#)),
            item("totp-only", r#"{"type":"totp","secret":"JBSWY3DP"}"#),
            item("nocreds", ""),
        ]
        .join(",");
        let d = decode_cxf(&doc(&items)).unwrap();
        assert_eq!(d.items.len(), 1);
        assert_eq!(secret_of(&d, "good"), b"fine-secret");
        let skipped: Vec<&str> = d.skipped.iter().map(|s| s.title.as_str()).collect();
        assert_eq!(
            skipped,
            [
                "bad alias!",
                "ctl",
                "newline",
                "empty",
                "notext",
                "good",
                "\\u{1b}[31mevil",
                "totp-only",
                "nocreds"
            ]
        );
        let all = format!("{:?}", d.skipped);
        for secret in ["hidden", "second-copy", "JBSWY3DP"] {
            assert!(!all.contains(secret), "{all}");
        }
        assert!(d.skipped[0].reason.contains("not a valid alias"));
        assert!(d.skipped[1].reason.contains("control characters"));
        assert!(d.skipped[5].reason.contains("more than once"));
        assert!(d.skipped[7].reason.contains("totp"));
    }

    #[test]
    fn unknown_fields_and_types_are_ignored() {
        let items = format!(
            r#"{{"id":"AQ","title":"svc","subtitle":"s","favorite":true,"tags":["a"],
                 "scope":{{"urls":["https://x"],"androidApps":[]}},"extensions":[{{"name":"z"}}],
                 "credentials":[
                   {{"type":"future-thing","password":12,"data":{{"deep":[1,2,{{"x":null}}]}}}},
                   {{"type":"basic-auth","username":{{"fieldType":"string","value":"me"}},
                     "password":{{"fieldType":"some-new-type","id":"Ag","label":"pw",
                                  "value":"p\u00e4ss","extra":[true]}}}},
                   {{"type":"note","content":{{"fieldType":"string","value":"n"}}}}]}},
               {}"#,
            item("empty-pw", r#"{"type":"basic-auth"}"#)
        );
        let text = String::from_utf8(doc(&items)).unwrap().replace(
            r#""timestamp":1"#,
            r#""timestamp":1,"newTopLevel":{"a":[1]}"#,
        );
        let d = decode_cxf(text.as_bytes()).unwrap();
        assert_eq!(d.items.len(), 1);
        assert_eq!(secret_of(&d, "svc"), "p\u{e4}ss".as_bytes());
        assert_eq!(d.skipped.len(), 1);
        assert_eq!(d.skipped[0].title, "empty-pw");
    }

    #[test]
    fn bad_documents_are_rejected_without_quoting_them() {
        let err = decode_cxf(br#"{"version":{"major":2,"minor":0},"accounts":[]}"#)
            .err()
            .unwrap();
        assert!(err.to_string().contains("version 2.0"), "{err}");
        let err = decode_cxf(br#"{"version":"hunter2"}"#).err().unwrap();
        assert!(!err.to_string().contains("hunter2"), "{err}");
        assert!(decode_cxf(b"not json").is_err());
    }

    #[test]
    fn merge_skips_existing_unless_overwrite() {
        let decode = || {
            let list: [(&str, &[u8]); 2] = [("a", b"new-a"), ("b", b"new-b")];
            decode_cxf(&encode_cxf(&entries(&list), 0).unwrap()).unwrap()
        };
        let mut data = VaultData::new();
        data.put("a", b"old-a");
        let r = merge_into(&mut data, decode(), false, None);
        assert_eq!(r.imported.len(), 1);
        assert_eq!(r.imported[0].alias, "b");
        assert!(!r.imported[0].replaced);
        assert_eq!(r.skipped.len(), 1);
        assert!(r.skipped[0].reason.contains("--overwrite"));
        assert_eq!(data.entries["a"].secret.as_slice(), b"old-a");

        let r = merge_into(&mut data, decode(), true, None);
        let replaced: Vec<&str> = r
            .imported
            .iter()
            .filter(|i| i.replaced)
            .map(|i| i.alias.as_str())
            .collect();
        assert_eq!(replaced, ["a", "b"]);
        assert_eq!(data.entries["a"].secret.as_slice(), b"new-a");
    }

    fn grouped(list: &[(&'static str, &'static str)]) -> SecretBuf {
        let entries: Vec<ExportEntry<'_>> = list
            .iter()
            .map(|&(alias, group)| ExportEntry {
                alias,
                group,
                secret: b"pw",
                created: 1,
                updated: 2,
            })
            .collect();
        encode_cxf(&entries, 0).unwrap()
    }

    fn groups_of(data: &VaultData) -> Vec<(&str, &str)> {
        data.entries
            .iter()
            .map(|(a, e)| (a.as_str(), e.group.as_str()))
            .collect()
    }

    #[test]
    fn collections_carry_groups_through_a_round_trip() {
        let plain = grouped(&[("proddb", "prod"), ("rootpw", "prod"), ("home", "personal")]);
        let v: serde_json::Value = serde_json::from_slice(&plain).unwrap();
        let acct = &v["accounts"][0];
        let colls = acct["collections"].as_array().unwrap();
        let titles: Vec<&str> = colls.iter().map(|c| c["title"].as_str().unwrap()).collect();
        assert_eq!(titles, ["personal", "prod"]);
        for c in colls {
            assert!(c["id"].as_str().is_some_and(|id| !id.is_empty()));
        }
        let prod: Vec<&serde_json::Value> = colls[1]["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| &l["item"])
            .collect();
        assert_eq!(prod, [&acct["items"][0]["id"], &acct["items"][1]["id"]]);

        let d = decode_cxf(&plain).unwrap();
        assert!(d.bad_collections.is_empty());
        let mut data = VaultData::new();
        data.set_default_group("mine").unwrap();
        let r = merge_into(&mut data, d, false, None);
        assert_eq!(r.imported.len(), 3);
        assert_eq!(
            groups_of(&data),
            [("home", "personal"), ("proddb", "prod"), ("rootpw", "prod")]
        );
    }

    #[test]
    fn group_override_puts_everything_in_one_group() {
        let plain = grouped(&[("proddb", "prod"), ("home", "personal")]);
        let mut data = VaultData::new();
        let r = merge_into(
            &mut data,
            decode_cxf(&plain).unwrap(),
            false,
            Some("shared"),
        );
        assert!(r.imported.iter().all(|i| i.group == "shared"));
        assert_eq!(groups_of(&data), [("home", "shared"), ("proddb", "shared")]);
    }

    #[test]
    fn items_in_no_collection_go_to_the_default_group() {
        // `doc` writes no collections, as some other exporters do.
        let items = [item("a", &basic(r#""x""#)), item("b", &basic(r#""y""#))].join(",");
        let d = decode_cxf(&doc(&items)).unwrap();
        assert!(d.items.iter().all(|i| i.collection.is_none()));
        let mut data = VaultData::new();
        data.set_default_group("inbox").unwrap();
        merge_into(&mut data, d, false, None);
        assert_eq!(groups_of(&data), [("a", "inbox"), ("b", "inbox")]);
    }

    #[test]
    fn collection_lookup_rules() {
        // Items: "a" (id A1), "b" (id B1), "c" (id C1), "d" (id D1).
        let items = ["a", "b", "c", "d"]
            .iter()
            .map(|t| {
                format!(
                    r#"{{"id":"{}1","title":"{t}","credentials":[{}]}}"#,
                    t.to_uppercase(),
                    basic(r#""pw""#)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        // "a" is in two collections (the first wins); "b" is only in a
        // nested one; "c" is in one with an invalid title; "d" is linked
        // only under another account's id, so it is in no collection here.
        let collections = r#"[
            {"id":"K1","title":"first","items":[{"item":"A1"}],
             "subCollections":[{"id":"K2","title":"nested","items":[{"item":"B1"}]}]},
            {"id":"K3","title":"second","items":[{"item":"A1"},{"item":"D1","account":"OTHER"}]},
            {"id":"K4","title":"bad name/\u001b","items":[{"item":"C1"}]}
        ]"#;
        let text = String::from_utf8(doc(&items)).unwrap().replace(
            r#""collections":[]"#,
            &format!(r#""collections":{collections}"#),
        );
        let d = decode_cxf(text.as_bytes()).unwrap();
        let coll: Vec<(&str, Option<&str>)> = d
            .items
            .iter()
            .map(|i| (i.alias.as_str(), i.collection.as_deref()))
            .collect();
        assert_eq!(
            coll,
            [
                ("a", Some("first")),
                ("b", Some("nested")),
                ("c", None),
                ("d", None)
            ]
        );
        assert_eq!(d.bad_collections, ["bad name/\\u{1b}"]);
    }

    #[test]
    fn with_key_accepts_a_key_a_file_or_reports_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let a = age::x25519::Identity::generate().to_public().to_string();
        let b = age::x25519::Identity::generate().to_public().to_string();

        // A key given directly.
        assert_eq!(recipients_from_arg(&a).unwrap().len(), 1);
        assert_eq!(recipients_from_arg(&format!("  {a}\n")).unwrap().len(), 1);

        // A key file, one key per line.
        let file = dir.path().join("team.keys");
        fs::write(&file, format!("# team\n{a}\n\n{b}\n")).unwrap();
        assert_eq!(
            recipients_from_arg(file.to_str().unwrap()).unwrap().len(),
            2
        );
        let bad_file = dir.path().join("bad.keys");
        fs::write(&bad_file, format!("{a}\nnonsense\n")).unwrap();
        let err = recipients_from_arg(bad_file.to_str().unwrap())
            .err()
            .unwrap();
        assert!(err.contains("bad.keys, line 2"), "{err}");

        // Garbage: named in the error.
        let err = recipients_from_arg("no-such-file.pub").err().unwrap();
        assert!(err.contains("`no-such-file.pub`"), "{err}");
        assert!(err.contains("not a public key"), "{err}");
        let err = recipients_from_arg("age1garbage").err().unwrap();
        assert!(err.contains("not a valid age"), "{err}");
        let err = recipients_from_arg("ssh-ed25519 AAAAnotbase64!! me@host")
            .err()
            .unwrap();
        assert!(err.contains("not an age key"), "{err}");

        // A private key, given directly or in a file, is never echoed back.
        let secret = age::x25519::Identity::generate();
        let secret = secret.to_string();
        let secret = secret.expose_secret();
        let err = recipients_from_arg(secret).err().unwrap();
        assert!(err.contains("private key"), "{err}");
        assert!(!err.contains(&secret[15..25]), "{err}");
        let id_file = dir.path().join("key.txt");
        fs::write(&id_file, format!("# public key: {a}\n{secret}\n")).unwrap();
        let err = recipients_from_arg(id_file.to_str().unwrap())
            .err()
            .unwrap();
        assert!(
            err.contains("line 2") && err.contains("private key"),
            "{err}"
        );
        assert!(!err.contains(&secret[15..25]), "{err}");
    }

    #[test]
    fn output_file_rules() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.tacitty");
        write_export_file(&path, b"one", false).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(write_export_file(&path, b"two", false)
            .unwrap_err()
            .to_string()
            .contains("--force"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_export_file(&path, b"two", true).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            1,
            "temp file left"
        );

        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(write_export_file(&link, b"x", true)
            .unwrap_err()
            .to_string()
            .contains("not a regular file"));
        assert!(check_output_path(Path::new("-"), true).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"two");
    }

    #[test]
    fn identity_file_errors_are_clear() {
        let dir = tempfile::tempdir().unwrap();
        let pubkey = dir.path().join("id.pub");
        fs::write(&pubkey, "ssh-ed25519 AAAA me@host\n").unwrap();
        let err = load_identities(&pubkey, no_ask).err().unwrap().to_string();
        assert!(err.contains("public key"), "{err}");
        let missing = load_identities(&dir.path().join("nope"), no_ask)
            .err()
            .unwrap()
            .to_string();
        assert!(missing.contains("reading"), "{missing}");
    }
}
