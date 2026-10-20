//! Signed free-trial tokens.
//!
//! Quartermaster records one free trial per product per computer and returns
//! it as a token signed with its online trial key, which is separate from the
//! offline license signing key. Apps verify the token offline, like a license
//! key, so editing a stored trial invalidates it.
//!
//! Layout (v1), followed by a 64-byte Ed25519 signature over [`DOMAIN`] and
//! the payload, encoded as unpadded RFC 4648 base32:
//!
//! - `[0]` version (1)
//! - `[1..5]` product code, 4 ASCII bytes
//! - `[5..37]` SHA-256 computer fingerprint (raw bytes)
//! - `[37..45]` `started_at`, Unix seconds, big-endian
//! - `[45..53]` `ends_at`, Unix seconds, big-endian

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

const PAYLOAD_LEN: usize = 53;
const SIG_LEN: usize = 64;
const RAW_LEN: usize = PAYLOAD_LEN + SIG_LEN; // 117
const CURRENT_VERSION: u8 = 1;

/// Signed in front of every trial payload, so a trial signature can never
/// stand for any other Quartermaster signature.
pub const DOMAIN: &[u8] = b"quartermaster-trial\0";

/// One computer's free trial of one product.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trial {
    pub version: u8,
    pub product: String,
    pub fingerprint: [u8; 32],
    pub started_at: i64,
    pub ends_at: i64,
}

impl Trial {
    /// The fingerprint as lowercase hex, the form `fingerprint::fingerprint` returns.
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint)
    }

    /// True when the trial is for `product` on the computer with `fingerprint_hex`.
    pub fn is_for(&self, product: &str, fingerprint_hex: &str) -> bool {
        self.product == product && self.fingerprint_hex().eq_ignore_ascii_case(fingerprint_hex)
    }

    /// Length of the trial in seconds.
    pub fn duration_secs(&self) -> i64 {
        self.ends_at - self.started_at
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum TrialError {
    Malformed,
    UnsupportedVersion,
    InvalidSignature,
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

/// Verifies `token` against `pub_key` and returns the trial it records.
pub fn verify_trial(pub_key: &VerifyingKey, token: &str) -> Result<Trial, TrialError> {
    let raw = base32::decode(
        base32::Alphabet::Rfc4648 { padding: false },
        &normalize(token),
    )
    .ok_or(TrialError::Malformed)?;
    if raw.len() != RAW_LEN {
        return Err(TrialError::Malformed);
    }
    let (payload, sig_bytes) = raw.split_at(PAYLOAD_LEN);
    if payload[0] != CURRENT_VERSION {
        return Err(TrialError::UnsupportedVersion);
    }
    let signature = Signature::from_slice(sig_bytes).map_err(|_| TrialError::Malformed)?;
    pub_key
        .verify(&message(payload), &signature)
        .map_err(|_| TrialError::InvalidSignature)?;

    let product = String::from_utf8(payload[1..5].to_vec()).map_err(|_| TrialError::Malformed)?;
    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(&payload[5..37]);
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
    Ok(Trial {
        version: payload[0],
        product,
        fingerprint,
        started_at,
        ends_at,
    })
}

/// Like [`verify_trial`], trying each key in turn (for key rotation).
pub fn verify_trial_any(pubs: &[VerifyingKey], token: &str) -> Result<Trial, TrialError> {
    if pubs.is_empty() {
        return Err(TrialError::Malformed);
    }
    let mut last_err = TrialError::InvalidSignature;
    for pub_key in pubs {
        match verify_trial(pub_key, token) {
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

    // Shared with Quartermaster's Go tests (license/trial_test.go): the same
    // key and trial must give this exact token on both sides.
    const VECTOR_SEED: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const VECTOR_TOKEN: &str = "AFIE6UCGUCQ2FI5EUWTKPKFJVKV2ZLNOV6YLDMVTWS23NN5YXG5LXPF5X27QAAAAABUOO6AAAAAAAADI7HWQBHOPQMDONAAQ7IDEXGHM44DJEO2BVH47CWI4QL4KR5T5R6PMQ2IEPJKZ7EOVFLLWEK526GNVXODOU4TEEXAD4ACCD4REHXCPA3GWEUDQ";
    const VECTOR_START: i64 = 1_760_000_000;
    const VECTOR_END: i64 = 1_760_000_000 + 14 * 86_400;

    fn vector_fingerprint() -> [u8; 32] {
        let mut fp = [0u8; 32];
        for (i, b) in fp.iter_mut().enumerate() {
            *b = 0xa0 + i as u8;
        }
        fp
    }

    fn vector_key() -> SigningKey {
        SigningKey::from_bytes(&VECTOR_SEED)
    }

    fn issue(key: &SigningKey, product: &str, fp: [u8; 32], start: i64, end: i64) -> String {
        let mut payload = [0u8; PAYLOAD_LEN];
        payload[0] = CURRENT_VERSION;
        payload[1..5].copy_from_slice(product.as_bytes());
        payload[5..37].copy_from_slice(&fp);
        payload[37..45].copy_from_slice(&start.to_be_bytes());
        payload[45..53].copy_from_slice(&end.to_be_bytes());
        let sig = key.sign(&message(&payload));
        let mut raw = payload.to_vec();
        raw.extend_from_slice(&sig.to_bytes());
        base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &raw)
    }

    #[test]
    fn the_go_token_verifies_here() {
        let trial = verify_trial(&vector_key().verifying_key(), VECTOR_TOKEN).expect("verifies");
        assert_eq!(trial.product, "POPF");
        assert_eq!(trial.fingerprint, vector_fingerprint());
        assert_eq!(
            (trial.started_at, trial.ends_at),
            (VECTOR_START, VECTOR_END)
        );
        assert_eq!(trial.duration_secs(), 14 * 86_400);
    }

    #[test]
    fn issuing_here_gives_the_same_token_as_go() {
        let token = issue(
            &vector_key(),
            "POPF",
            vector_fingerprint(),
            VECTOR_START,
            VECTOR_END,
        );
        assert_eq!(token, VECTOR_TOKEN);
    }

    #[test]
    fn every_tampered_byte_is_rejected() {
        let pub_key = vector_key().verifying_key();
        let raw = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, VECTOR_TOKEN)
            .expect("valid base32");
        for i in 0..raw.len() {
            let mut bad = raw.clone();
            bad[i] ^= 0xff;
            let token = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &bad);
            assert!(verify_trial(&pub_key, &token).is_err(), "byte {i} accepted");
        }
    }

    #[test]
    fn a_signature_without_the_domain_is_rejected() {
        let key = vector_key();
        let raw = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, VECTOR_TOKEN)
            .expect("valid base32");
        let payload = &raw[..PAYLOAD_LEN];
        let mut plain = payload.to_vec();
        plain.extend_from_slice(&key.sign(payload).to_bytes());
        let token = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &plain);
        assert_eq!(
            verify_trial(&key.verifying_key(), &token),
            Err(TrialError::InvalidSignature)
        );
    }

    #[test]
    fn wrong_keys_junk_and_new_versions_are_rejected() {
        let other = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        assert_eq!(
            verify_trial(&other, VECTOR_TOKEN),
            Err(TrialError::InvalidSignature)
        );
        assert_eq!(verify_trial(&other, "AAAA"), Err(TrialError::Malformed));
        assert_eq!(verify_trial(&other, ""), Err(TrialError::Malformed));
        let key = vector_key();
        let mut raw = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, VECTOR_TOKEN)
            .expect("valid base32");
        raw[0] = 2;
        let sig = key.sign(&message(&raw[..PAYLOAD_LEN]));
        raw[PAYLOAD_LEN..].copy_from_slice(&sig.to_bytes());
        let token = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &raw);
        assert_eq!(
            verify_trial(&key.verifying_key(), &token),
            Err(TrialError::UnsupportedVersion)
        );
    }

    #[test]
    fn verify_trial_any_tries_each_key() {
        let other = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        let right = vector_key().verifying_key();
        assert!(verify_trial_any(&[other, right], VECTOR_TOKEN).is_ok());
        assert_eq!(
            verify_trial_any(&[other], VECTOR_TOKEN),
            Err(TrialError::InvalidSignature)
        );
        assert_eq!(
            verify_trial_any(&[], VECTOR_TOKEN),
            Err(TrialError::Malformed)
        );
    }

    #[test]
    fn is_for_matches_product_and_fingerprint() {
        let trial = verify_trial(&vector_key().verifying_key(), VECTOR_TOKEN).expect("verifies");
        let hex_fp = hex::encode(vector_fingerprint());
        assert!(trial.is_for("POPF", &hex_fp));
        assert!(trial.is_for("POPF", &hex_fp.to_uppercase()));
        assert!(!trial.is_for("LAMP", &hex_fp));
        assert!(!trial.is_for("POPF", &"00".repeat(32)));
    }
}
