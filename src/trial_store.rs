//! Where an app keeps its version 2 trial: one small text file holding the
//! signed token and the signal hashes it was issued for.
//!
//! ```text
//! quartermaster-trial-v2
//! <token>
//! <64 hex characters per line, one line per signal>
//! ```
//!
//! The token is signed and its binding must equal the binding of the saved
//! signal list, so the list cannot be edited. The file is not tied to one
//! computer by itself: [`StoredTrial::matches`] compares the saved signals with
//! this computer's current ones, which is what makes a copied file (or a disk
//! image) useless on other hardware.

use std::path::Path;

use ed25519_dalek::VerifyingKey;

use crate::trial_v2::{binding, verify_trial_v2_any, TrialV2};

const HEADER: &str = "quartermaster-trial-v2";
/// Most signals a saved trial may list (the server keeps at most 16).
const MAX_SIGNALS: usize = 16;

/// A trial read from disk whose signature and signal list are consistent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTrial {
    pub trial: TrialV2,
    pub signals: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stored {
    /// No file.
    Missing,
    /// A file that does not verify (edited, wrong key, wrong product, junk).
    Invalid,
    Found(StoredTrial),
}

impl StoredTrial {
    /// True when this computer shares at least one signal with the trial.
    pub fn matches(&self, current: &[[u8; 32]]) -> bool {
        self.trial
            .covers(&self.trial.product, &self.signals, current)
    }

    /// True when `current` is exactly the saved set (order and repeats aside).
    pub fn same_set(&self, current: &[[u8; 32]]) -> bool {
        binding(&self.trial.product, current) == self.trial.binding
    }
}

fn parse_hash(line: &str) -> Option<[u8; 32]> {
    let line = line.trim();
    if line.len() != 64 || !line.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&line[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// Splits file text into its token and signal hashes.
fn parse_file(text: &str) -> Option<(String, Vec<[u8; 32]>)> {
    let mut lines = text.lines();
    if lines.next()?.trim() != HEADER {
        return None;
    }
    let token = lines.next()?.trim().to_string();
    if token.is_empty() {
        return None;
    }
    let mut signals = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        signals.push(parse_hash(line)?);
        if signals.len() > MAX_SIGNALS {
            return None;
        }
    }
    (!signals.is_empty()).then_some((token, signals))
}

/// Reads and checks the trial in `dir/file` for `product`.
pub fn read_in(dir: &Path, file: &str, keys: &[VerifyingKey], product: &str) -> Stored {
    let Ok(text) = std::fs::read_to_string(dir.join(file)) else {
        return Stored::Missing;
    };
    let Some((token, signals)) = parse_file(&text) else {
        return Stored::Invalid;
    };
    let Ok(trial) = verify_trial_v2_any(keys, &token) else {
        return Stored::Invalid;
    };
    if trial.product != product || binding(product, &signals) != trial.binding {
        return Stored::Invalid;
    }
    Stored::Found(StoredTrial { trial, signals })
}

/// Saves a token and the signals it was issued for, replacing any earlier
/// file. Written through a temporary file named for this process, so two
/// processes never interleave.
pub fn write_in(dir: &Path, file: &str, token: &str, signals: &[[u8; 32]]) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let mut body = format!("{HEADER}\n{}\n", token.trim());
    for signal in signals {
        body.push_str(&hex::encode(signal));
        body.push('\n');
    }
    let path = dir.join(file);
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, path)
}

/// Whether the app should ask Quartermaster for this computer's trial now.
///
/// - A saved trial that matches this computer: only when the signal set has
///   changed (a part was replaced), so the server learns the new set and the
///   token is re-issued for it.
/// - Anything else (no file, a file that does not verify, or a trial from other
///   hardware, as on a copied disk image): only when an earlier trial existed on
///   this computer (`prior_trial_files`, such as a 0.1.x token), so an update
///   moves it over. A computer with no trial history waits for the user to
///   press the button.
pub fn should_register(stored: &Stored, current: &[[u8; 32]], prior_trial_files: bool) -> bool {
    if current.is_empty() {
        return false;
    }
    match stored {
        Stored::Found(found) if found.matches(current) => !found.same_set(current),
        Stored::Found(_) | Stored::Invalid => true,
        Stored::Missing => prior_trial_files,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trial_v2::binding;
    use ed25519_dalek::{Signer, SigningKey};

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[3u8; 32])
    }

    fn keys() -> Vec<VerifyingKey> {
        vec![key().verifying_key()]
    }

    fn sig(n: u8) -> [u8; 32] {
        [n; 32]
    }

    /// A token as the server would issue it for `signals`.
    fn token_for(product: &str, signals: &[[u8; 32]], start: i64, end: i64) -> String {
        let mut payload = [0u8; 53];
        payload[0] = 2;
        payload[1..5].copy_from_slice(product.as_bytes());
        payload[5..37].copy_from_slice(&binding(product, signals));
        payload[37..45].copy_from_slice(&start.to_be_bytes());
        payload[45..53].copy_from_slice(&end.to_be_bytes());
        let mut msg = crate::trial::DOMAIN.to_vec();
        msg.extend_from_slice(&payload);
        let s = key().sign(&msg);
        let mut raw = payload.to_vec();
        raw.extend_from_slice(&s.to_bytes());
        base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &raw)
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("qlc-store-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn save(dir: &Path, signals: &[[u8; 32]]) -> String {
        let token = token_for("POPF", signals, 1_000, 1_000 + 14 * 86_400);
        write_in(dir, "T.trial2", &token, signals).unwrap();
        token
    }

    #[test]
    fn a_saved_trial_reads_back() {
        let dir = scratch("roundtrip");
        let signals = [sig(1), sig(2), sig(3)];
        save(&dir, &signals);
        match read_in(&dir, "T.trial2", &keys(), "POPF") {
            Stored::Found(found) => {
                assert_eq!(found.signals, signals);
                assert_eq!(found.trial.started_at, 1_000);
                assert!(found.matches(&signals));
                assert!(found.same_set(&[sig(3), sig(2), sig(1), sig(1)]));
            }
            other => panic!("{other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_and_junk_files() {
        let dir = scratch("junk");
        assert_eq!(read_in(&dir, "T.trial2", &keys(), "POPF"), Stored::Missing);
        for text in [
            "",
            "nonsense",
            "quartermaster-trial-v2\n",
            "quartermaster-trial-v2\nTOKEN\n",
            "quartermaster-trial-v2\nTOKEN\nnot-hex\n",
        ] {
            std::fs::write(dir.join("T.trial2"), text).unwrap();
            assert_eq!(
                read_in(&dir, "T.trial2", &keys(), "POPF"),
                Stored::Invalid,
                "{text:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_edited_signal_list_or_token_is_invalid() {
        let dir = scratch("edited");
        let signals = [sig(1), sig(2)];
        let token = save(&dir, &signals);
        // Another computer's signals pasted under the same token.
        write_in(&dir, "T.trial2", &token, &[sig(9)]).unwrap();
        assert_eq!(read_in(&dir, "T.trial2", &keys(), "POPF"), Stored::Invalid);
        // Extra signal added.
        write_in(&dir, "T.trial2", &token, &[sig(1), sig(2), sig(9)]).unwrap();
        assert_eq!(read_in(&dir, "T.trial2", &keys(), "POPF"), Stored::Invalid);
        // Changed token.
        let mut bad = token.clone();
        bad.replace_range(10..11, if &token[10..11] == "A" { "B" } else { "A" });
        write_in(&dir, "T.trial2", &bad, &signals).unwrap();
        assert_eq!(read_in(&dir, "T.trial2", &keys(), "POPF"), Stored::Invalid);
        // Wrong product or wrong key.
        write_in(&dir, "T.trial2", &token, &signals).unwrap();
        assert_eq!(read_in(&dir, "T.trial2", &keys(), "LAMP"), Stored::Invalid);
        let other = vec![SigningKey::from_bytes(&[4u8; 32]).verifying_key()];
        assert_eq!(read_in(&dir, "T.trial2", &other, "POPF"), Stored::Invalid);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn too_many_signals_are_refused() {
        let dir = scratch("many");
        let signals: Vec<[u8; 32]> = (0..17).map(sig).collect();
        let token = token_for("POPF", &signals, 1, 2);
        write_in(&dir, "T.trial2", &token, &signals).unwrap();
        assert_eq!(read_in(&dir, "T.trial2", &keys(), "POPF"), Stored::Invalid);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn found(signals: &[[u8; 32]]) -> Stored {
        Stored::Found(StoredTrial {
            trial: TrialV2 {
                product: "POPF".into(),
                binding: binding("POPF", signals),
                started_at: 1,
                ends_at: 2,
            },
            signals: signals.to_vec(),
        })
    }

    #[test]
    fn same_hardware_needs_no_registration() {
        let s = [sig(1), sig(2), sig(3)];
        assert!(!should_register(&found(&s), &s, false));
        assert!(!should_register(
            &found(&s),
            &[sig(3), sig(1), sig(2)],
            true
        ));
    }

    #[test]
    fn a_replaced_part_registers_the_new_set() {
        let s = [sig(1), sig(2), sig(3)];
        assert!(should_register(
            &found(&s),
            &[sig(1), sig(2), sig(9)],
            false
        ));
        // Fewer signals readable today than at issue time also re-registers
        // (harmless: the server only adds, never removes).
        assert!(should_register(&found(&s), &[sig(1)], false));
    }

    #[test]
    fn a_copied_trial_on_other_hardware_registers() {
        let s = [sig(1), sig(2)];
        assert!(should_register(&found(&s), &[sig(7), sig(8)], false));
        assert!(should_register(&Stored::Invalid, &[sig(7)], false));
    }

    #[test]
    fn no_file_registers_only_with_trial_history() {
        assert!(!should_register(&Stored::Missing, &[sig(1)], false));
        assert!(should_register(&Stored::Missing, &[sig(1)], true));
    }

    #[test]
    fn nothing_registers_without_signals() {
        assert!(!should_register(&Stored::Missing, &[], true));
        assert!(!should_register(&found(&[sig(1)]), &[], true));
    }
}
