//! Signed free-trial tokens, version 2: a trial bound to a computer's set of
//! hardware signals (see [`crate::hardware`]) instead of one fingerprint.
//!
//! Same length as v1, with the version byte 2 and a binding in place of the
//! fingerprint, then a 64-byte Ed25519 signature over [`DOMAIN`] and the
//! payload, encoded as unpadded RFC 4648 base32:
//!
//! - `[0]` version (2)
//! - `[1..5]` product code, 4 ASCII bytes
//! - `[5..37]` binding: [`binding`] of the signal hashes the app submitted
//! - `[37..45]` `started_at`, Unix seconds, big-endian
//! - `[45..53]` `ends_at`, Unix seconds, big-endian
//!
//! [`crate::trial::verify_trial`] accepts only version 1 and [`verify_trial_v2`]
//! only version 2, so neither can be mistaken for the other.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::trial::{TrialError, DOMAIN};

const PAYLOAD_LEN: usize = 53;
const SIG_LEN: usize = 64;
const RAW_LEN: usize = PAYLOAD_LEN + SIG_LEN;
const VERSION: u8 = 2;

/// Hashed in front of a binding so it can never equal any other SHA-256 value
/// in the system.
pub const BINDING_DOMAIN: &[u8] = b"quartermaster-trial-binding\0";

/// One computer's free trial of one product, as signed by Quartermaster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrialV2 {
    pub product: String,
    pub binding: [u8; 32],
    pub started_at: i64,
    pub ends_at: i64,
}

/// `SHA-256(BINDING_DOMAIN || product || signals)`, the signals sorted bytewise
/// and de-duplicated. Order and repeats do not matter. Identical to
/// Quartermaster's `license.TrialBinding`.
pub fn binding(product: &str, signals: &[[u8; 32]]) -> [u8; 32] {
    let mut sorted: Vec<[u8; 32]> = signals.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut hasher = Sha256::new();
    hasher.update(BINDING_DOMAIN);
    hasher.update(product.as_bytes());
    for signal in &sorted {
        hasher.update(signal);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

impl TrialV2 {
    /// Length of the trial in seconds.
    pub fn duration_secs(&self) -> i64 {
        self.ends_at - self.started_at
    }

    /// True when this token was issued for `product` and `issued_for` (the
    /// signal hashes saved beside it) really are the set it is bound to, and
    /// this computer still shares at least one of them (`current`). A reinstall
    /// or a replaced part keeps matching; a copied token on other hardware, or
    /// an edited signal list, does not. Mirrors the server's matching rule.
    pub fn covers(&self, product: &str, issued_for: &[[u8; 32]], current: &[[u8; 32]]) -> bool {
        self.product == product
            && !issued_for.is_empty()
            && binding(product, issued_for) == self.binding
            && current.iter().any(|c| issued_for.contains(c))
    }
}

fn normalize(token: &str) -> String {
    token
        .to_uppercase()
        .chars()
        .filter(|c| !matches!(c, '-' | ' ' | '\n' | '\r' | '\t'))
        .collect()
}

fn message(payload: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(DOMAIN.len() + payload.len());
    msg.extend_from_slice(DOMAIN);
    msg.extend_from_slice(payload);
    msg
}

/// Reads a payload that has already passed its signature check.
fn parse_payload(payload: &[u8]) -> Result<TrialV2, TrialError> {
    if payload.len() != PAYLOAD_LEN {
        return Err(TrialError::Malformed);
    }
    if payload[0] != VERSION {
        return Err(TrialError::UnsupportedVersion);
    }
    let product = String::from_utf8(payload[1..5].to_vec()).map_err(|_| TrialError::Malformed)?;
    let mut bound = [0u8; 32];
    bound.copy_from_slice(&payload[5..37]);
    let started_at = i64::from_be_bytes(
        payload[37..45]
            .try_into()
            .map_err(|_| TrialError::Malformed)?,
    );
    let ends_at = i64::from_be_bytes(
        payload[45..53]
            .try_into()
            .map_err(|_| TrialError::Malformed)?,
    );
    if ends_at < started_at {
        return Err(TrialError::Malformed);
    }
    Ok(TrialV2 {
        product,
        binding: bound,
        started_at,
        ends_at,
    })
}

/// Verifies `token` against `pub_key` and returns the trial it records.
pub fn verify_trial_v2(pub_key: &VerifyingKey, token: &str) -> Result<TrialV2, TrialError> {
    let raw = base32::decode(
        base32::Alphabet::Rfc4648 { padding: false },
        &normalize(token),
    )
    .ok_or(TrialError::Malformed)?;
    if raw.len() != RAW_LEN {
        return Err(TrialError::Malformed);
    }
    let (payload, sig_bytes) = raw.split_at(PAYLOAD_LEN);
    if payload[0] != VERSION {
        return Err(TrialError::UnsupportedVersion);
    }
    let signature = Signature::from_slice(sig_bytes).map_err(|_| TrialError::Malformed)?;
    pub_key
        .verify(&message(payload), &signature)
        .map_err(|_| TrialError::InvalidSignature)?;
    parse_payload(payload)
}

/// Like [`verify_trial_v2`], trying each key in turn (for key rotation).
pub fn verify_trial_v2_any(pubs: &[VerifyingKey], token: &str) -> Result<TrialV2, TrialError> {
    if pubs.is_empty() {
        return Err(TrialError::Malformed);
    }
    let mut last_err = TrialError::InvalidSignature;
    for pub_key in pubs {
        match verify_trial_v2(pub_key, token) {
            Ok(trial) => return Ok(trial),
            Err(e @ TrialError::Malformed) | Err(e @ TrialError::UnsupportedVersion) => {
                return Err(e);
            }
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    // Shared with Quartermaster's Go tests (license/trial_v2_vector_test.go):
    // seed 00..1f, POPF, three signals (bytes 10.., 40.., 70.. each +0..1f),
    // started 1760000000, 14 days.
    const VECTOR_SEED: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const VECTOR_TOKEN: &str = "AJIE6UCGDQHWFN3ALEGJ34ASFWDJGQ4K5TMYPX5A6GF5STQSOP4NWITA4VZAAAAAABUOO6AAAAAAAADI7HWQAHJQA6AT5DQ7KWRZZXHDLMGYFTKIU262VHCSJX4UUZECIBJ6SLFQHZ3IFC3FY5YIPGWCVE3ZJKTSLGKYBMDYZOD5KRLZELAO6E2F4YBQ";
    const VECTOR_BINDING: &str = "1c0f62b760590c9df0122d8693438aecd987dfa0f18bd94e1273f8db2260e572";
    const START: i64 = 1_760_000_000;
    const END: i64 = START + 14 * 86_400;

    fn signals() -> Vec<[u8; 32]> {
        [0x10u8, 0x40, 0x70]
            .iter()
            .map(|&base| {
                let mut s = [0u8; 32];
                for (i, b) in s.iter_mut().enumerate() {
                    *b = base + i as u8;
                }
                s
            })
            .collect()
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&VECTOR_SEED)
    }

    fn issue(key: &SigningKey, product: &str, bound: [u8; 32], start: i64, end: i64) -> String {
        let mut payload = [0u8; PAYLOAD_LEN];
        payload[0] = VERSION;
        payload[1..5].copy_from_slice(product.as_bytes());
        payload[5..37].copy_from_slice(&bound);
        payload[37..45].copy_from_slice(&start.to_be_bytes());
        payload[45..53].copy_from_slice(&end.to_be_bytes());
        let sig = key.sign(&message(&payload));
        let mut raw = payload.to_vec();
        raw.extend_from_slice(&sig.to_bytes());
        base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &raw)
    }

    fn trial() -> TrialV2 {
        TrialV2 {
            product: "POPF".to_string(),
            binding: binding("POPF", &signals()),
            started_at: START,
            ends_at: END,
        }
    }

    #[test]
    fn binding_matches_the_go_vector() {
        assert_eq!(hex::encode(binding("POPF", &signals())), VECTOR_BINDING);
    }

    #[test]
    fn the_go_payload_parses_to_the_expected_trial() {
        // Signature checking needs real Ed25519 (see the next test); this proves
        // the layout agrees with Go.
        let raw = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, VECTOR_TOKEN)
            .expect("valid base32");
        assert_eq!(raw.len(), RAW_LEN);
        assert_eq!(parse_payload(&raw[..PAYLOAD_LEN]), Ok(trial()));
    }

    #[test]
    fn the_go_token_verifies_here() {
        let trial_got = verify_trial_v2(&key().verifying_key(), VECTOR_TOKEN).expect("verifies");
        assert_eq!(trial_got, trial());
        assert_eq!(trial_got.duration_secs(), 14 * 86_400);
    }

    #[test]
    fn issuing_here_gives_the_same_token_as_go() {
        let token = issue(&key(), "POPF", binding("POPF", &signals()), START, END);
        assert_eq!(token, VECTOR_TOKEN);
    }

    #[test]
    fn round_trip_and_tamper_checks() {
        let k = key();
        let token = issue(&k, "POPF", binding("POPF", &signals()), START, END);
        assert_eq!(verify_trial_v2(&k.verifying_key(), &token), Ok(trial()));
        let raw = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &token).unwrap();
        for i in 0..raw.len() {
            let mut bad = raw.clone();
            bad[i] ^= 0xff;
            let t = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &bad);
            assert!(verify_trial_v2(&k.verifying_key(), &t).is_err(), "byte {i}");
        }
    }

    #[test]
    fn junk_wrong_keys_and_other_versions_are_rejected() {
        let k = key();
        let other = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        let token = issue(&k, "POPF", [7; 32], START, END);
        assert_eq!(
            verify_trial_v2(&other, &token),
            Err(TrialError::InvalidSignature)
        );
        assert_eq!(verify_trial_v2(&other, "AAAA"), Err(TrialError::Malformed));
        assert_eq!(verify_trial_v2(&other, ""), Err(TrialError::Malformed));
        // A correctly signed v1-shaped payload is not a v2 token.
        let mut raw = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &token).unwrap();
        raw[0] = 1;
        let sig = k.sign(&message(&raw[..PAYLOAD_LEN]));
        raw[PAYLOAD_LEN..].copy_from_slice(&sig.to_bytes());
        let v1 = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &raw);
        assert_eq!(
            verify_trial_v2(&k.verifying_key(), &v1),
            Err(TrialError::UnsupportedVersion)
        );
        // Ends before it starts.
        let backwards = issue(&k, "POPF", [7; 32], END, START);
        assert_eq!(
            verify_trial_v2(&k.verifying_key(), &backwards),
            Err(TrialError::Malformed)
        );
    }

    #[test]
    fn verify_any_tries_each_key() {
        let k = key();
        let other = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        let token = issue(&k, "POPF", [7; 32], START, END);
        assert!(verify_trial_v2_any(&[other, k.verifying_key()], &token).is_ok());
        assert_eq!(
            verify_trial_v2_any(&[other], &token),
            Err(TrialError::InvalidSignature)
        );
        assert_eq!(verify_trial_v2_any(&[], &token), Err(TrialError::Malformed));
    }

    #[test]
    fn binding_ignores_order_and_repeats_but_not_content() {
        let s = signals();
        let want = binding("POPF", &s);
        assert_eq!(binding("POPF", &[s[2], s[0], s[1]]), want);
        assert_eq!(binding("POPF", &[s[0], s[1], s[2], s[1], s[0]]), want);
        assert_ne!(binding("POPF", &s[..2]), want);
        assert_ne!(binding("LAMP", &s), want);
    }

    #[test]
    fn covers_needs_the_real_set_and_one_shared_signal() {
        let s = signals();
        let t = trial();
        // Same hardware.
        assert!(t.covers("POPF", &s, &s));
        // One part replaced: two of three signals still shared.
        let mut changed = s.clone();
        changed[2] = [0xee; 32];
        assert!(t.covers("POPF", &s, &changed));
        // Only one left.
        assert!(t.covers("POPF", &s, &[s[1], [0xdd; 32]]));
        // Another computer (nothing shared), as with a cloned disk image.
        assert!(!t.covers("POPF", &s, &[[1; 32], [2; 32]]));
        assert!(!t.covers("POPF", &s, &[]));
        // An edited saved list does not hash to the signed binding.
        let mut forged = s.clone();
        forged.push([0xaa; 32]);
        assert!(!t.covers("POPF", &forged, &forged));
        let other_machine = [[5; 32]];
        assert!(!t.covers("POPF", &other_machine, &other_machine));
        assert!(!t.covers("POPF", &[], &s));
        // Wrong product.
        assert!(!t.covers("LAMP", &s, &s));
    }

    #[test]
    fn duration_is_end_minus_start() {
        assert_eq!(trial().duration_secs(), 14 * 86_400);
    }
}
