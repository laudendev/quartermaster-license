//! Reads the hardware identifiers Pop Focus uses to tell computers apart from
//! the raw SMBIOS table (the firmware's description of the machine).
//!
//! The Windows API `GetSystemFirmwareTable('RSMB', ...)` returns a small header
//! followed by that table, and Linux exposes the same table as
//! `/sys/firmware/dmi/tables/DMI` (root only). This module only parses bytes:
//! it uses no unsafe code, no operating system calls and no dependencies, and
//! it never panics, whatever the input. Callers hash each value on its own
//! (see the identity design) and never send the raw values anywhere.
//!
//! Layout used here (DMTF SMBIOS reference specification; Microsoft's SMBIOS
//! requirements page documents Type 1 serial at offset 07h and UUID at 08h):
//! every structure starts with a 4-byte header (type, formatted length, 2-byte
//! handle), then the formatted area, then a set of NUL-terminated strings that
//! ends with one more NUL. String fields in the formatted area are 1-based
//! indexes into that set, and 0 means "none".
//!
//! - Type 1 (System Information): serial number string at 07h, UUID at 08h (16 bytes).
//! - Type 2 (Baseboard): serial number string at 07h.
//! - Type 127 ends the table.
//!
//! The UUID is returned exactly as stored. Firmware stores its first three
//! fields little-endian, which does not matter here because the bytes are only
//! hashed and compared.

/// Hardware identifiers found in the SMBIOS table. A field is `None` when the
/// table does not have it or the value is missing or a known placeholder (see
/// [`HardwareIds::sanitized`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HardwareIds {
    pub system_uuid: Option<[u8; 16]>,
    pub system_serial: Option<String>,
    pub board_serial: Option<String>,
}

impl HardwareIds {
    /// True when no identifier is present.
    pub fn is_empty(&self) -> bool {
        self.system_uuid.is_none() && self.system_serial.is_none() && self.board_serial.is_none()
    }

    /// Drops values that cannot identify a computer: an all-zero or all-FF
    /// UUID, empty strings, strings of one repeated character, and the
    /// placeholder text some firmware ships ("To be filled by O.E.M.", ...).
    pub fn sanitized(self) -> Self {
        HardwareIds {
            system_uuid: self.system_uuid.filter(valid_uuid),
            system_serial: self.system_serial.filter(|s| valid_serial(s)),
            board_serial: self.board_serial.filter(|s| valid_serial(s)),
        }
    }
}

fn valid_uuid(uuid: &[u8; 16]) -> bool {
    !(uuid.iter().all(|&b| b == 0x00) || uuid.iter().all(|&b| b == 0xFF))
}

/// Text that firmware vendors leave in serial fields they did not fill in.
const PLACEHOLDERS: &[&str] = &[
    "to be filled by o.e.m.",
    "to be filled by oem",
    "o.e.m.",
    "oem",
    "default string",
    "default",
    "none",
    "n/a",
    "na",
    "not applicable",
    "not specified",
    "not available",
    "not defined",
    "unknown",
    "invalid",
    "empty",
    "system serial number",
    "system product name",
    "base board serial number",
    "baseboard serial number",
    "chassis serial number",
    "serial number",
    "1234567890",
    "0123456789",
    "123456789",
    "type2 - board serial number",
];

fn valid_serial(serial: &str) -> bool {
    let s = serial.trim();
    if s.is_empty() {
        return false;
    }
    // Runs of spaces and letter case never hide a placeholder.
    let lower = s
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    if PLACEHOLDERS.contains(&lower.as_str()) {
        return false;
    }
    // "0000000000", "FFFFFFFF", "xxxxxxxx" and the like.
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => chars.any(|c| c != first),
        None => false,
    }
}

/// Parses the buffer returned by `GetSystemFirmwareTable('RSMB', 0, ...)`: an
/// 8-byte header (calling method, major and minor version, DMI revision, then
/// the table length as a little-endian u32) followed by the table.
pub fn parse_rsmb(buf: &[u8]) -> HardwareIds {
    const HEADER: usize = 8;
    if buf.len() < HEADER {
        return HardwareIds::default();
    }
    let declared = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    let available = buf.len() - HEADER;
    let len = declared.min(available);
    parse_table(&buf[HEADER..HEADER + len])
}

/// Parses an SMBIOS structure table (no RSMB header). The first Type 1 and
/// first Type 2 structure win; values are returned as stored, so run
/// [`HardwareIds::sanitized`] before using them.
pub fn parse_table(table: &[u8]) -> HardwareIds {
    let mut ids = HardwareIds::default();
    let mut seen_system = false;
    let mut seen_board = false;
    let mut pos = 0usize;

    while pos + 4 <= table.len() {
        let kind = table[pos];
        let formatted_len = table[pos + 1] as usize;
        if formatted_len < 4 || pos + formatted_len > table.len() {
            break;
        }
        let formatted = &table[pos..pos + formatted_len];
        let strings_start = pos + formatted_len;

        // The string set ends at the first pair of consecutive NULs.
        let mut end = strings_start;
        let found = loop {
            if end + 1 >= table.len() {
                break false;
            }
            if table[end] == 0 && table[end + 1] == 0 {
                break true;
            }
            end += 1;
        };
        if !found {
            break;
        }
        let strings = &table[strings_start..end];

        match kind {
            1 if !seen_system => {
                seen_system = true;
                ids.system_serial = string_at(formatted, 0x07, strings);
                if formatted_len >= 0x18 {
                    let mut uuid = [0u8; 16];
                    uuid.copy_from_slice(&formatted[0x08..0x18]);
                    ids.system_uuid = Some(uuid);
                }
            }
            2 if !seen_board => {
                seen_board = true;
                ids.board_serial = string_at(formatted, 0x07, strings);
            }
            127 => break,
            _ => {}
        }
        pos = end + 2;
    }
    ids
}

/// The string a formatted-area byte points at, or `None` for index 0, an index
/// past the set, an empty string, or a field the structure is too short to have.
fn string_at(formatted: &[u8], offset: usize, strings: &[u8]) -> Option<String> {
    let index = *formatted.get(offset)? as usize;
    if index == 0 || strings.is_empty() {
        return None;
    }
    let raw = strings.split(|&b| b == 0).nth(index - 1)?;
    let text = String::from_utf8_lossy(raw);
    let text = text.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One structure: header, formatted bytes after the header, string set.
    fn structure(kind: u8, after_header: &[u8], strings: &[&str]) -> Vec<u8> {
        let mut out = vec![kind, (4 + after_header.len()) as u8, 0x01, 0x00];
        out.extend_from_slice(after_header);
        if strings.is_empty() {
            out.extend_from_slice(&[0, 0]);
        } else {
            for s in strings {
                out.extend_from_slice(s.as_bytes());
                out.push(0);
            }
            out.push(0);
        }
        out
    }

    /// Type 1 formatted bytes after the header: manufacturer, product,
    /// version, serial string indexes, UUID, wake-up type, SKU, family.
    fn system_info(serial_index: u8, uuid: [u8; 16]) -> Vec<u8> {
        let mut b = vec![1, 2, 3, serial_index];
        b.extend_from_slice(&uuid);
        b.extend_from_slice(&[6, 4, 5]);
        b
    }

    const UUID: [u8; 16] = [
        0x22, 0x6F, 0xFC, 0x79, 0x87, 0x23, 0xED, 0x11, 0x80, 0xF2, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06,
    ];

    fn table() -> Vec<u8> {
        let mut t = structure(0, &[1, 2, 0xF0, 0x0F], &["Vendor BIOS", "1.0"]);
        t.extend(structure(
            1,
            &system_info(4, UUID),
            &["ACME", "Laptop 1", "v1", "SN-TEST-0001", "SKU", "Family"],
        ));
        t.extend(structure(
            2,
            &[1, 2, 3, 4],
            &["ACME", "Board", "v2", "BOARD-TEST-0002"],
        ));
        t.extend(structure(127, &[], &[]));
        t
    }

    fn rsmb(table: &[u8]) -> Vec<u8> {
        let mut out = vec![0, 3, 4, 0];
        out.extend_from_slice(&(table.len() as u32).to_le_bytes());
        out.extend_from_slice(table);
        out
    }

    #[test]
    fn reads_the_system_uuid_and_both_serials() {
        let ids = parse_table(&table());
        assert_eq!(ids.system_uuid, Some(UUID));
        assert_eq!(ids.system_serial.as_deref(), Some("SN-TEST-0001"));
        assert_eq!(ids.board_serial.as_deref(), Some("BOARD-TEST-0002"));
        assert!(!ids.is_empty());
    }

    #[test]
    fn rsmb_wrapper_is_skipped() {
        assert_eq!(parse_rsmb(&rsmb(&table())), parse_table(&table()));
    }

    #[test]
    fn rsmb_length_is_clamped_to_the_buffer_and_honoured() {
        let t = table();
        let mut big = rsmb(&t);
        big[4..8].copy_from_slice(&(t.len() as u32 + 1000).to_le_bytes());
        assert_eq!(parse_rsmb(&big), parse_table(&t));

        // A declared length that ends before the Type 2 structure hides it.
        let cut = t.len() - 40;
        let mut short = rsmb(&t);
        short[4..8].copy_from_slice(&(cut as u32).to_le_bytes());
        assert_eq!(parse_rsmb(&short).board_serial, None);
        assert_eq!(parse_rsmb(&[]), HardwareIds::default());
        assert_eq!(parse_rsmb(&[0; 7]), HardwareIds::default());
    }

    #[test]
    fn string_index_zero_or_out_of_range_is_none() {
        let mut t = structure(1, &system_info(0, UUID), &["ACME", "Laptop", "v1", "SN"]);
        t.extend(structure(2, &[1, 2, 3, 9], &["ACME", "Board", "v2", "X"]));
        let ids = parse_table(&t);
        assert_eq!(ids.system_serial, None);
        assert_eq!(ids.board_serial, None);
        assert_eq!(ids.system_uuid, Some(UUID));
    }

    #[test]
    fn short_type_1_structures_have_no_uuid() {
        // SMBIOS 2.0 Type 1 ends after the serial number (length 08h).
        let t = structure(1, &[1, 2, 3, 4], &["ACME", "Laptop", "v1", "SN-OLD"]);
        let ids = parse_table(&t);
        assert_eq!(ids.system_uuid, None);
        assert_eq!(ids.system_serial.as_deref(), Some("SN-OLD"));
    }

    #[test]
    fn the_first_structure_of_a_kind_wins() {
        let mut t = structure(1, &system_info(1, UUID), &["FIRST"]);
        t.extend(structure(1, &system_info(1, [9; 16]), &["SECOND"]));
        let ids = parse_table(&t);
        assert_eq!(ids.system_serial.as_deref(), Some("FIRST"));
        assert_eq!(ids.system_uuid, Some(UUID));
    }

    #[test]
    fn type_127_ends_the_table() {
        let mut t = structure(127, &[], &[]);
        t.extend(structure(1, &system_info(1, UUID), &["AFTER"]));
        assert!(parse_table(&t).is_empty());
    }

    #[test]
    fn strings_are_trimmed_and_nul_padding_is_ignored() {
        let t = structure(1, &system_info(1, UUID), &["  SN-PAD   "]);
        assert_eq!(parse_table(&t).system_serial.as_deref(), Some("SN-PAD"));
        let blank = structure(1, &system_info(1, UUID), &["    "]);
        assert_eq!(parse_table(&blank).system_serial, None);
    }

    #[test]
    fn non_utf8_strings_do_not_panic() {
        let mut t = structure(1, &system_info(1, UUID), &["x"]);
        let at = t.iter().position(|&b| b == b'x').unwrap();
        t[at] = 0xFF;
        let _ = parse_table(&t);
    }

    #[test]
    fn sanitizing_drops_unusable_values() {
        let bad = HardwareIds {
            system_uuid: Some([0; 16]),
            system_serial: Some("To be filled by O.E.M.".to_string()),
            board_serial: Some("0000000000".to_string()),
        };
        assert!(bad.sanitized().is_empty());

        let ff = HardwareIds {
            system_uuid: Some([0xFF; 16]),
            system_serial: Some("Default string".to_string()),
            board_serial: Some("  None ".to_string()),
        };
        assert!(ff.sanitized().is_empty());

        let good = parse_table(&table()).sanitized();
        assert_eq!(good, parse_table(&table()));
    }

    #[test]
    fn each_placeholder_is_rejected_in_any_case() {
        for p in PLACEHOLDERS {
            assert!(!valid_serial(p), "{p}");
            assert!(!valid_serial(&p.to_ascii_uppercase()), "{p}");
        }
        assert!(valid_serial("PF000TEST"));
        assert!(valid_serial("S/N 1"));
        assert!(!valid_serial("A"), "a single repeated character");
        assert!(!valid_serial(""));
        assert!(valid_uuid(&UUID));
        let mut almost = [0u8; 16];
        almost[15] = 1;
        assert!(valid_uuid(&almost));
        almost = [0xFF; 16];
        almost[0] = 0xFE;
        assert!(valid_uuid(&almost));
    }

    #[test]
    fn truncated_tables_never_panic() {
        let t = rsmb(&table());
        for n in 0..=t.len() {
            let _ = parse_rsmb(&t[..n]);
            let _ = parse_table(&t[..n.min(t.len() - 8)]);
        }
    }

    #[test]
    fn mutated_tables_never_panic() {
        let base = rsmb(&table());
        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..20_000 {
            let mut buf = base.clone();
            let flips = 1 + (next() % 6) as usize;
            for _ in 0..flips {
                let at = (next() as usize) % buf.len();
                buf[at] = next() as u8;
            }
            if next() % 4 == 0 {
                buf.truncate((next() as usize) % (buf.len() + 1));
            }
            let _ = parse_rsmb(&buf);
            let _ = parse_table(&buf);
        }
    }

    #[test]
    fn a_zero_length_structure_stops_parsing() {
        let mut t = vec![1, 0, 0, 0, 0, 0];
        t.extend(table());
        assert!(parse_table(&t).is_empty());
    }
}

#[cfg(test)]
mod denylist_tests {
    use super::*;

    #[test]
    fn extra_spaces_and_case_do_not_hide_a_placeholder() {
        assert!(!valid_serial("To  Be Filled   By O.E.M."));
        assert!(!valid_serial("  TYPE2 - BOARD SERIAL NUMBER "));
        assert!(!valid_serial("Type2 - Board Serial Number"));
        assert!(valid_serial("PF000TEST"));
        assert!(valid_serial("Type2 - Board Serial Number 7"));
    }
}
