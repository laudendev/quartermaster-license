//! Signed update manifest: which versions of a product exist, what changed in
//! each, and where to download them.
//!
//! The manifest is a JSON file served as `releases.json` with a detached
//! signature file `releases.json.sig`. The signature is an Ed25519 signature over
//! [`MANIFEST_DOMAIN`] followed by the exact bytes of the manifest, encoded as
//! unpadded RFC 4648 base32 (like the trial tokens). Apps verify the signature
//! first and only then parse the JSON, so nothing from an unsigned file is ever
//! interpreted. Several public keys may be trusted at once (rotation, backup key).
//!
//! This module only verifies and decides; it never touches the network or the
//! disk. The app downloads the two files, calls [`verify_manifest`], shows
//! [`offers`], and checks a downloaded installer with [`check_artifact`].

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::io::Read;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Signed in front of every manifest, so a manifest signature can never stand
/// for any other Quartermaster signature.
pub const MANIFEST_DOMAIN: &[u8] = b"quartermaster-update-manifest\0";

/// The only manifest format this code understands. A manifest with a different
/// number is reported as [`UpdateError::UnsupportedFormat`] (the app should tell
/// the user to update by hand).
pub const FORMAT: u32 = 1;

/// Platform keys used in [`VersionEntry::assets`].
pub const PLATFORM_WINDOWS: &str = "windows-x64";
pub const PLATFORM_MACOS: &str = "macos-universal";
pub const PLATFORM_LINUX_DEB: &str = "linux-deb";
pub const PLATFORM_LINUX_RPM: &str = "linux-rpm";

/// Largest manifest accepted.
pub const MAX_MANIFEST_BYTES: usize = 2 * 1024 * 1024;

const MAX_VERSIONS: usize = 500;
const MAX_NOTES_BYTES: usize = 20_000;
const MAX_SECURITY_NOTE_BYTES: usize = 2_000;
const MAX_DATE_BYTES: usize = 32;
const MAX_ASSET_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// How far in the future `signed_at` may be (a computer whose clock is behind).
const CLOCK_SKEW_SECS: i64 = 86_400;

/// A release version: exactly `major.minor.patch`, no pre-release or build part.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

fn number(part: &str) -> Option<u32> {
    if part.is_empty() || part.len() > 9 || !part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if part.len() > 1 && part.starts_with('0') {
        return None;
    }
    part.parse().ok()
}

impl Version {
    /// Parses `1.2.3`. Anything else (`v1.2.3`, `1.2`, `1.2.3-rc.1`, leading
    /// zeros, spaces) is `None`.
    pub fn parse(text: &str) -> Option<Version> {
        let mut parts = text.split('.');
        let major = number(parts.next()?)?;
        let minor = number(parts.next()?)?;
        let patch = number(parts.next()?)?;
        if parts.next().is_some() {
            return None;
        }
        Some(Version {
            major,
            minor,
            patch,
        })
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// One downloadable installer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asset {
    pub url: String,
    /// Lowercase hex SHA-256 of the file.
    pub sha256: String,
    pub size: u64,
}

/// One released version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionEntry {
    pub version: String,
    /// Display only, for example `2026-10-23`.
    pub date: String,
    /// The licence major this version requires. A major-1 licence covers 0.x and
    /// 1.x, so those versions say 1.
    pub license_major: u16,
    /// Version of the on-disk settings format this version reads and writes.
    pub state_format: u32,
    #[serde(default)]
    pub withdrawn: bool,
    #[serde(default)]
    pub security_note: Option<String>,
    /// Plain text release notes. Show them through [`sanitize_text`], never as HTML.
    pub notes: String,
    /// Installers by platform key (see the `PLATFORM_` constants).
    pub assets: BTreeMap<String, Asset>,
}

/// The signed list of releases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    pub product: String,
    pub signed_at: i64,
    pub expires_at: i64,
    /// The oldest version a user may move to.
    pub floor: String,
    /// The newest version, never withdrawn.
    pub latest: String,
    pub versions: Vec<VersionEntry>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum UpdateError {
    /// Not a signature or manifest this code can read.
    Malformed,
    InvalidSignature,
    UnsupportedFormat,
    Expired,
    NotYetValid,
    /// Signed and readable, but inconsistent or unsafe; the text says why.
    Invalid(&'static str),
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => write!(f, "the update information could not be read"),
            Self::InvalidSignature => write!(f, "the update information is not signed by us"),
            Self::UnsupportedFormat => write!(f, "the update information needs a newer app"),
            Self::Expired => write!(f, "the update information is out of date"),
            Self::NotYetValid => write!(f, "the update information is dated in the future"),
            Self::Invalid(why) => write!(f, "the update information is not valid ({why})"),
        }
    }
}

impl std::error::Error for UpdateError {}

fn normalize(text: &str) -> String {
    text.to_uppercase()
        .chars()
        .filter(|c| !matches!(c, '-' | ' ' | '\n' | '\r' | '\t'))
        .collect()
}

/// The exact bytes a signer signs for `manifest`.
pub fn signing_message(manifest: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(MANIFEST_DOMAIN.len() + manifest.len());
    msg.extend_from_slice(MANIFEST_DOMAIN);
    msg.extend_from_slice(manifest);
    msg
}

/// True for `https://` addresses whose host is exactly one of `hosts`: no user
/// information, no port, no spaces, control characters or backslashes.
pub fn url_host_allowed(url: &str, hosts: &[&str]) -> bool {
    if url.bytes().any(|b| b <= 0x20 || b == 0x7F || b == b'\\') {
        return false;
    }
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty()
        || !authority
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return false;
    }
    hosts.iter().any(|h| h.eq_ignore_ascii_case(authority))
}

fn check_asset(asset: &Asset, hosts: &[&str]) -> Result<(), UpdateError> {
    if !url_host_allowed(&asset.url, hosts) {
        return Err(UpdateError::Invalid("download address not allowed"));
    }
    if asset.sha256.len() != 64
        || !asset
            .sha256
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(UpdateError::Invalid("bad file hash"));
    }
    if asset.size == 0 || asset.size > MAX_ASSET_BYTES {
        return Err(UpdateError::Invalid("bad file size"));
    }
    Ok(())
}

fn validate(m: &Manifest, product: &str, now: i64, hosts: &[&str]) -> Result<(), UpdateError> {
    if m.format != FORMAT {
        return Err(UpdateError::UnsupportedFormat);
    }
    if m.product != product {
        return Err(UpdateError::Invalid("wrong product"));
    }
    if m.expires_at <= m.signed_at {
        return Err(UpdateError::Invalid("expiry is not after signing"));
    }
    if now > m.expires_at {
        return Err(UpdateError::Expired);
    }
    if m.signed_at > now.saturating_add(CLOCK_SKEW_SECS) {
        return Err(UpdateError::NotYetValid);
    }
    let floor = Version::parse(&m.floor).ok_or(UpdateError::Invalid("bad floor"))?;
    let latest = Version::parse(&m.latest).ok_or(UpdateError::Invalid("bad latest"))?;
    if m.versions.is_empty() || m.versions.len() > MAX_VERSIONS {
        return Err(UpdateError::Invalid("bad number of versions"));
    }
    let mut seen = HashSet::new();
    let mut latest_found = false;
    for entry in &m.versions {
        let version = Version::parse(&entry.version).ok_or(UpdateError::Invalid("bad version"))?;
        if !seen.insert(version) {
            return Err(UpdateError::Invalid("duplicate version"));
        }
        if entry.license_major == 0 || entry.state_format == 0 {
            return Err(UpdateError::Invalid("bad licence or state number"));
        }
        if entry.notes.len() > MAX_NOTES_BYTES
            || entry.date.len() > MAX_DATE_BYTES
            || entry
                .security_note
                .as_ref()
                .is_some_and(|s| s.len() > MAX_SECURITY_NOTE_BYTES)
        {
            return Err(UpdateError::Invalid("text too long"));
        }
        for asset in entry.assets.values() {
            check_asset(asset, hosts)?;
        }
        if version == latest {
            if entry.withdrawn {
                return Err(UpdateError::Invalid("latest is withdrawn"));
            }
            latest_found = true;
        }
    }
    if !latest_found {
        return Err(UpdateError::Invalid("latest is not listed"));
    }
    if latest < floor {
        return Err(UpdateError::Invalid("latest is below the floor"));
    }
    Ok(())
}

/// Verifies the signed manifest and returns it. `now` is Unix seconds.
/// `allowed_hosts` are the only hosts a download address may use.
///
/// The signature is checked against every key in `keys`; the JSON is parsed
/// only after one matches.
pub fn verify_manifest(
    keys: &[VerifyingKey],
    product: &str,
    json: &[u8],
    signature: &str,
    now: i64,
    allowed_hosts: &[&str],
) -> Result<Manifest, UpdateError> {
    if keys.is_empty() || json.is_empty() || json.len() > MAX_MANIFEST_BYTES {
        return Err(UpdateError::Malformed);
    }
    let raw = base32::decode(
        base32::Alphabet::Rfc4648 { padding: false },
        &normalize(signature),
    )
    .ok_or(UpdateError::Malformed)?;
    let signature = Signature::from_slice(&raw).map_err(|_| UpdateError::Malformed)?;
    let message = signing_message(json);
    if !keys.iter().any(|k| k.verify(&message, &signature).is_ok()) {
        return Err(UpdateError::InvalidSignature);
    }
    let manifest: Manifest = serde_json::from_slice(json).map_err(|_| UpdateError::Malformed)?;
    validate(&manifest, product, now, allowed_hosts)?;
    Ok(manifest)
}

/// Where a version stands relative to the one that is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Newer,
    Current,
    Older,
}

/// One row of the version list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer<'a> {
    pub entry: &'a VersionEntry,
    pub version: Version,
    pub direction: Direction,
    /// The version needs a licence major the user does not hold.
    pub needs_new_license: bool,
    pub is_latest: bool,
}

/// The versions to show, newest first: everything from the manifest's floor up,
/// without withdrawn versions (the running one is kept even if withdrawn, so the
/// user can see where they are). `max_license_major` is the highest licence
/// major the user may run: their licence's, or this build's during a trial.
pub fn offers(m: &Manifest, current: Version, max_license_major: u16) -> Vec<Offer<'_>> {
    let Some(floor) = Version::parse(&m.floor) else {
        return Vec::new();
    };
    let latest = Version::parse(&m.latest);
    let mut out: Vec<Offer<'_>> = m
        .versions
        .iter()
        .filter_map(|entry| {
            let version = Version::parse(&entry.version)?;
            if version < floor || (entry.withdrawn && version != current) {
                return None;
            }
            let direction = match version.cmp(&current) {
                Ordering::Greater => Direction::Newer,
                Ordering::Equal => Direction::Current,
                Ordering::Less => Direction::Older,
            };
            Some(Offer {
                entry,
                version,
                direction,
                needs_new_license: entry.license_major > max_license_major,
                is_latest: Some(version) == latest,
            })
        })
        .collect();
    out.sort_by_key(|o| std::cmp::Reverse(o.version));
    out
}

/// When the running version has been withdrawn, the newest version that is not
/// withdrawn and that the user's licence allows. `None` when the running version
/// is fine or is not in the manifest.
pub fn nudge(m: &Manifest, current: Version, max_license_major: u16) -> Option<&VersionEntry> {
    let running = m
        .versions
        .iter()
        .find(|e| Version::parse(&e.version) == Some(current))?;
    if !running.withdrawn {
        return None;
    }
    m.versions
        .iter()
        .filter(|e| !e.withdrawn && e.license_major <= max_license_major)
        .filter_map(|e| Some((Version::parse(&e.version)?, e)))
        .max_by_key(|(v, _)| *v)
        .map(|(_, e)| e)
}

/// The installer of `entry` for `platform` (one of the `PLATFORM_` constants).
pub fn asset<'a>(entry: &'a VersionEntry, platform: &str) -> Option<&'a Asset> {
    entry.assets.get(platform)
}

/// What to do with the user's settings when switching versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatePlan {
    /// The target reads the current settings (same format, or newer and it migrates).
    Keep,
    /// The target is older than the settings format in use: restore the snapshot
    /// taken before the update and tell the user what will be lost.
    RestoreSnapshot,
}

pub fn state_plan(current_format: u32, target_format: u32) -> StatePlan {
    if target_format < current_format {
        StatePlan::RestoreSnapshot
    } else {
        StatePlan::Keep
    }
}

#[derive(Debug)]
pub enum ArtifactError {
    Io(std::io::Error),
    WrongSize,
    WrongHash,
}

/// Checks a downloaded installer against its manifest entry while reading it
/// once: the size must match exactly (a longer stream is refused as soon as it
/// exceeds it) and so must the SHA-256.
pub fn check_artifact<R: Read>(mut reader: R, asset: &Asset) -> Result<(), ArtifactError> {
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = match reader.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ArtifactError::Io(e)),
        };
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > asset.size {
            return Err(ArtifactError::WrongSize);
        }
        hasher.update(&buf[..n]);
    }
    if total != asset.size {
        return Err(ArtifactError::WrongSize);
    }
    if hex::encode(hasher.finalize()) != asset.sha256 {
        return Err(ArtifactError::WrongHash);
    }
    Ok(())
}

fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{061C}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

/// Text from the manifest made safe to show: control characters other than
/// newline and tab, zero-width and text-direction characters are removed, and at
/// most `max_chars` characters are kept.
pub fn sanitize_text(text: &str, max_chars: usize) -> String {
    text.chars()
        .filter(|c| (!c.is_control() || matches!(c, '\n' | '\t')) && !is_invisible(*c))
        .take(max_chars)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;
    const HOSTS: &[&str] = &["popfocus.lauden.dev"];

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    fn sign(k: &SigningKey, json: &[u8]) -> String {
        let signature = k.sign(&signing_message(json));
        base32::encode(
            base32::Alphabet::Rfc4648 { padding: false },
            &signature.to_bytes(),
        )
    }

    fn ver(text: &str) -> Version {
        Version::parse(text).unwrap()
    }

    fn make_asset(v: &str) -> Asset {
        Asset {
            url: format!("https://popfocus.lauden.dev/download/v{v}/popfocus_{v}_x64-setup.exe"),
            sha256: "a".repeat(64),
            size: 1000,
        }
    }

    fn entry(v: &str, license_major: u16, state_format: u32, withdrawn: bool) -> VersionEntry {
        let mut assets = BTreeMap::new();
        assets.insert(PLATFORM_WINDOWS.to_string(), make_asset(v));
        VersionEntry {
            version: v.to_string(),
            date: "2026-10-23".to_string(),
            license_major,
            state_format,
            withdrawn,
            security_note: None,
            notes: format!("Notes for {v}"),
            assets,
        }
    }

    fn manifest() -> Manifest {
        Manifest {
            format: FORMAT,
            product: "POPF".to_string(),
            signed_at: NOW - 1000,
            expires_at: NOW + 90 * DAY,
            floor: "0.1.13".to_string(),
            latest: "0.1.15".to_string(),
            versions: vec![
                entry("0.1.12", 1, 1, false),
                entry("0.1.13", 1, 1, false),
                entry("0.1.14", 1, 1, false),
                entry("0.1.15", 1, 2, false),
            ],
        }
    }

    fn verify_at(m: &Manifest, now: i64) -> Result<Manifest, UpdateError> {
        let k = key(1);
        let json = serde_json::to_vec(m).unwrap();
        let sig = sign(&k, &json);
        verify_manifest(&[k.verifying_key()], "POPF", &json, &sig, now, HOSTS)
    }

    #[test]
    fn a_signed_manifest_verifies() {
        let got = verify_at(&manifest(), NOW).unwrap();
        assert_eq!(got, manifest());
    }

    #[test]
    fn any_key_of_the_list_verifies() {
        let json = serde_json::to_vec(&manifest()).unwrap();
        let keys = [key(1).verifying_key(), key(2).verifying_key()];
        let by_second = sign(&key(2), &json);
        assert!(verify_manifest(&keys, "POPF", &json, &by_second, NOW, HOSTS).is_ok());
        let by_stranger = sign(&key(3), &json);
        assert_eq!(
            verify_manifest(&keys, "POPF", &json, &by_stranger, NOW, HOSTS),
            Err(UpdateError::InvalidSignature)
        );
    }

    #[test]
    fn a_tampered_manifest_or_signature_is_rejected() {
        let k = key(1);
        let json = serde_json::to_vec(&manifest()).unwrap();
        let sig = sign(&k, &json);
        let keys = [k.verifying_key()];

        let tampered = std::str::from_utf8(&json)
            .unwrap()
            .replace("Notes for 0.1.14", "Notes for 0.1.99")
            .into_bytes();
        assert_eq!(tampered.len(), json.len());
        assert_eq!(
            verify_manifest(&keys, "POPF", &tampered, &sig, NOW, HOSTS),
            Err(UpdateError::InvalidSignature)
        );

        let mut bad = sig.clone();
        let first = if bad.starts_with('A') { "B" } else { "A" };
        bad.replace_range(0..1, first);
        assert_eq!(
            verify_manifest(&keys, "POPF", &json, &bad, NOW, HOSTS),
            Err(UpdateError::InvalidSignature)
        );
    }

    #[test]
    fn a_signature_without_the_domain_is_rejected() {
        let k = key(1);
        let json = serde_json::to_vec(&manifest()).unwrap();
        let bare = k.sign(&json);
        let sig = base32::encode(
            base32::Alphabet::Rfc4648 { padding: false },
            &bare.to_bytes(),
        );
        assert_eq!(
            verify_manifest(&[k.verifying_key()], "POPF", &json, &sig, NOW, HOSTS),
            Err(UpdateError::InvalidSignature)
        );
    }

    #[test]
    fn junk_is_malformed() {
        let k = key(1);
        let keys = [k.verifying_key()];
        let json = serde_json::to_vec(&manifest()).unwrap();
        let sig = sign(&k, &json);
        assert_eq!(
            verify_manifest(&keys, "POPF", &json, "", NOW, HOSTS),
            Err(UpdateError::Malformed)
        );
        assert_eq!(
            verify_manifest(&keys, "POPF", &json, "!!!", NOW, HOSTS),
            Err(UpdateError::Malformed)
        );
        assert_eq!(
            verify_manifest(&keys, "POPF", b"", &sig, NOW, HOSTS),
            Err(UpdateError::Malformed)
        );
        assert_eq!(
            verify_manifest(&[], "POPF", &json, &sig, NOW, HOSTS),
            Err(UpdateError::Malformed)
        );
        let huge = vec![b' '; MAX_MANIFEST_BYTES + 1];
        assert_eq!(
            verify_manifest(&keys, "POPF", &huge, &sig, NOW, HOSTS),
            Err(UpdateError::Malformed)
        );
        let not_json = b"not json";
        let signed_junk = sign(&k, not_json);
        assert_eq!(
            verify_manifest(&keys, "POPF", not_json, &signed_junk, NOW, HOSTS),
            Err(UpdateError::Malformed)
        );
    }

    #[test]
    fn expired_and_future_manifests_are_rejected() {
        let m = manifest();
        assert!(verify_at(&m, m.expires_at).is_ok());
        assert_eq!(verify_at(&m, m.expires_at + 1), Err(UpdateError::Expired));

        let mut future = manifest();
        future.signed_at = NOW + 2 * DAY;
        future.expires_at = NOW + 100 * DAY;
        assert_eq!(verify_at(&future, NOW), Err(UpdateError::NotYetValid));

        let mut slight = manifest();
        slight.signed_at = NOW + 3600;
        assert!(verify_at(&slight, NOW).is_ok());
    }

    #[test]
    fn another_format_is_reported_only_when_it_is_signed() {
        let mut m = manifest();
        m.format = 2;
        assert_eq!(verify_at(&m, NOW), Err(UpdateError::UnsupportedFormat));
        let json = serde_json::to_vec(&m).unwrap();
        let by_stranger = sign(&key(9), &json);
        assert_eq!(
            verify_manifest(
                &[key(1).verifying_key()],
                "POPF",
                &json,
                &by_stranger,
                NOW,
                HOSTS
            ),
            Err(UpdateError::InvalidSignature)
        );
    }

    #[test]
    fn inconsistent_or_unsafe_manifests_are_invalid() {
        type Change = fn(&mut Manifest);
        let cases: Vec<(&str, Change)> = vec![
            ("duplicate version", |m| {
                m.versions.push(entry("0.1.14", 1, 1, false))
            }),
            ("latest not listed", |m| m.latest = "0.1.99".to_string()),
            ("latest withdrawn", |m| m.versions[3].withdrawn = true),
            ("bad version", |m| m.versions[0].version = "0.1".to_string()),
            ("bad floor", |m| m.floor = "abc".to_string()),
            ("floor above latest", |m| m.floor = "0.2.0".to_string()),
            ("http address", |m| {
                m.versions[1].assets.get_mut(PLATFORM_WINDOWS).unwrap().url =
                    "http://popfocus.lauden.dev/x".to_string()
            }),
            ("other host", |m| {
                m.versions[1].assets.get_mut(PLATFORM_WINDOWS).unwrap().url =
                    "https://evil.example/x".to_string()
            }),
            ("user information", |m| {
                m.versions[1].assets.get_mut(PLATFORM_WINDOWS).unwrap().url =
                    "https://popfocus.lauden.dev@evil.example/x".to_string()
            }),
            ("short hash", |m| {
                m.versions[1]
                    .assets
                    .get_mut(PLATFORM_WINDOWS)
                    .unwrap()
                    .sha256 = "abc".to_string()
            }),
            ("uppercase hash", |m| {
                m.versions[1]
                    .assets
                    .get_mut(PLATFORM_WINDOWS)
                    .unwrap()
                    .sha256 = "A".repeat(64)
            }),
            ("zero size", |m| {
                m.versions[1].assets.get_mut(PLATFORM_WINDOWS).unwrap().size = 0
            }),
            ("wrong product", |m| m.product = "LAMP".to_string()),
            ("expiry not after signing", |m| m.expires_at = m.signed_at),
            ("zero state format", |m| m.versions[0].state_format = 0),
            ("zero licence major", |m| m.versions[0].license_major = 0),
            ("notes too long", |m| {
                m.versions[0].notes = "x".repeat(MAX_NOTES_BYTES + 1)
            }),
            ("no versions", |m| m.versions.clear()),
        ];
        for (name, change) in cases {
            let mut m = manifest();
            change(&mut m);
            assert!(
                matches!(verify_at(&m, NOW), Err(UpdateError::Invalid(_))),
                "{name}"
            );
        }
    }

    #[test]
    fn versions_parse_and_order() {
        assert_eq!(
            Version::parse("0.1.13"),
            Some(Version {
                major: 0,
                minor: 1,
                patch: 13
            })
        );
        assert!(Version::parse("10.20.30").is_some());
        assert!(Version::parse("0.0.0").is_some());
        for bad in [
            "",
            "0.1",
            "0.1.13.1",
            "v0.1.13",
            "0.1.13-rc.1",
            "0.01.3",
            "0.1.",
            "-1.0.0",
            "0.1.1234567890",
            " 0.1.13",
        ] {
            assert_eq!(Version::parse(bad), None, "{bad:?}");
        }
        assert!(ver("0.1.9") < ver("0.1.13"));
        assert!(ver("0.2.0") > ver("0.1.99"));
        assert!(ver("1.0.0") > ver("0.99.99"));
        assert_eq!(ver("0.1.13").to_string(), "0.1.13");
    }

    #[test]
    fn offers_follow_the_floor_withdrawals_and_the_licence() {
        let m = manifest();
        let list = offers(&m, ver("0.1.14"), 1);
        let versions: Vec<String> = list.iter().map(|o| o.version.to_string()).collect();
        assert_eq!(versions, ["0.1.15", "0.1.14", "0.1.13"]);
        let directions: Vec<Direction> = list.iter().map(|o| o.direction).collect();
        assert_eq!(
            directions,
            [Direction::Newer, Direction::Current, Direction::Older]
        );
        assert_eq!(list.iter().filter(|o| o.is_latest).count(), 1);
        assert!(list[0].is_latest);
        assert!(list.iter().all(|o| !o.needs_new_license));

        let mut hidden = manifest();
        hidden.versions[1].withdrawn = true;
        let list = offers(&hidden, ver("0.1.14"), 1);
        let versions: Vec<String> = list.iter().map(|o| o.version.to_string()).collect();
        assert_eq!(versions, ["0.1.15", "0.1.14"]);

        let mut on_withdrawn = manifest();
        on_withdrawn.versions[2].withdrawn = true;
        let list = offers(&on_withdrawn, ver("0.1.14"), 1);
        assert!(list.iter().any(|o| o.direction == Direction::Current));

        let mut next_major = manifest();
        next_major.versions.push(entry("2.0.0", 2, 3, false));
        let paid = offers(&next_major, ver("0.1.14"), 1);
        assert!(paid[0].version == ver("2.0.0") && paid[0].needs_new_license);
        let covered = offers(&next_major, ver("0.1.14"), 2);
        assert!(!covered[0].needs_new_license);
    }

    #[test]
    fn a_version_below_the_floor_can_only_move_up() {
        let m = manifest();
        let list = offers(&m, ver("0.1.12"), 1);
        assert!(!list.is_empty());
        assert!(list.iter().all(|o| o.direction == Direction::Newer));
    }

    #[test]
    fn a_withdrawn_running_version_gets_a_nudge() {
        let mut m = manifest();
        m.versions[2].withdrawn = true;
        let target = nudge(&m, ver("0.1.14"), 1).unwrap();
        assert_eq!(target.version, "0.1.15");

        m.versions.push(entry("2.0.0", 2, 3, false));
        assert_eq!(nudge(&m, ver("0.1.14"), 1).unwrap().version, "0.1.15");
        assert_eq!(nudge(&m, ver("0.1.14"), 2).unwrap().version, "2.0.0");

        assert!(nudge(&m, ver("0.1.15"), 1).is_none());
        assert!(nudge(&m, ver("0.1.20"), 1).is_none());
    }

    #[test]
    fn settings_are_kept_unless_the_target_is_older_than_their_format() {
        assert_eq!(state_plan(1, 1), StatePlan::Keep);
        assert_eq!(state_plan(2, 1), StatePlan::RestoreSnapshot);
        assert_eq!(state_plan(1, 2), StatePlan::Keep);
    }

    #[test]
    fn assets_are_found_by_platform() {
        let e = entry("0.1.14", 1, 1, false);
        assert!(asset(&e, PLATFORM_WINDOWS).is_some());
        assert!(asset(&e, PLATFORM_LINUX_DEB).is_none());
        assert_ne!(PLATFORM_MACOS, PLATFORM_LINUX_RPM);
    }

    #[test]
    fn artifacts_are_checked_for_size_and_hash() {
        // sha256("abc"), the standard test vector.
        let abc = Asset {
            url: "https://popfocus.lauden.dev/x".to_string(),
            sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_string(),
            size: 3,
        };
        assert!(check_artifact(std::io::Cursor::new(b"abc"), &abc).is_ok());
        assert!(matches!(
            check_artifact(std::io::Cursor::new(b"abd"), &abc),
            Err(ArtifactError::WrongHash)
        ));
        assert!(matches!(
            check_artifact(std::io::Cursor::new(b"ab"), &abc),
            Err(ArtifactError::WrongSize)
        ));
        assert!(matches!(
            check_artifact(std::io::Cursor::new(b"abcd"), &abc),
            Err(ArtifactError::WrongSize)
        ));
    }

    #[test]
    fn only_exact_https_hosts_are_allowed() {
        for ok in [
            "https://popfocus.lauden.dev/download/v0.1.14/x.exe",
            "https://POPFOCUS.lauden.dev/x",
            "https://popfocus.lauden.dev",
        ] {
            assert!(url_host_allowed(ok, HOSTS), "{ok}");
        }
        for bad in [
            "http://popfocus.lauden.dev/x",
            "https://popfocus.lauden.dev.evil.example/x",
            "https://popfocus.lauden.dev@evil.example/",
            "https://popfocus.lauden.dev:8443/x",
            "https://popfocus.lauden.dev\\@evil.example/",
            "https://popfocus.lauden.dev /x",
            "",
            "https:///x",
            "ftp://popfocus.lauden.dev/x",
            "//popfocus.lauden.dev/x",
        ] {
            assert!(!url_host_allowed(bad, HOSTS), "{bad:?}");
        }
    }

    #[test]
    fn shown_text_loses_control_and_direction_characters() {
        assert_eq!(
            sanitize_text("a\u{202E}b\u{0007}c\td\n\u{200B}e\r", 100),
            "abc\td\ne"
        );
        assert_eq!(sanitize_text("h\u{e9}llo", 3), "h\u{e9}l");
        assert_eq!(sanitize_text("", 10), "");
    }
}
