//! PCR (Platform Configuration Register) emulation.
//!
//! This module tracks the running state of all 24 PCRs for each active hash
//! algorithm while parsing a TCG 2.0 event log, and exposes the final emulated
//! PCR values in the [`TcgLog`](crate::TcgLog) output.
//!
//! # PCR initial values
//!
//! The TCG PC Client Platform Firmware Profile Specification §3.3.2 defines
//! two starting conditions for PCR 0:
//!
//! | Startup locality | PCR 0 initial value | Other PCRs |
//! |---|---|---|
//! | 0 (normal firmware) | All `0x00` | All `0x00` |
//! | 3 or 4 (H-CRTM / platform firmware) | All `0xFF` | All `0x00` |
//!
//! The [`StartupLocality`](crate::event_data::StartupLocality) `EV_NO_ACTION`
//! event that immediately follows the SpecID header in the log records which
//! locality was used.  If that event is absent the parser defaults to locality
//! 0 (all-zero initialisation).
//!
//! # PCR extension formula
//!
//! Per the TCG specification, extending a PCR with a new digest uses:
//!
//! ```text
//! PCR_new = H( PCR_old || new_digest )
//! ```
//!
//! where `H` is the hash function for that PCR bank (SHA-1, SHA-256, …), and
//! `||` denotes concatenation.
//!
//! # EV_NO_ACTION
//!
//! `EV_NO_ACTION` events are **never** extended into any PCR.  The digests
//! in those events must be all-zero per the TCG spec.

use crate::types::{HashAlgorithmId, to_hex};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use sha1::Digest as Sha1Digest;
use sha2::Digest as Sha2Digest;

/// The maximum valid PCR index per the TCG PC Client Platform Firmware Profile
/// Specification.  PCRs 0–23 are defined; indices ≥ 24 are out of range.
pub const MAX_PCR_INDEX: u32 = 23;

/// Localities at which a TPM2_Startup from H-CRTM firmware causes PCR 0 to be
/// initialised to all `0xFF` bytes instead of all `0x00` bytes.
///
/// Per TCG PC Client Platform Firmware Profile §3.3.2, localities 3 and 4
/// indicate an H-CRTM (Host-based Core Root of Trust for Measurement) startup.
pub const HCRTM_LOCALITIES: &[u8] = &[3, 4];

/// A PCR bank holds the emulated PCR values for a single hash algorithm.
///
/// After parsing completes, [`TcgLog::pcr_tables`](crate::TcgLog::pcr_tables)
/// contains one [`PcrBank`] for each algorithm declared in the SpecID event.
/// PCRs that received no measurements retain their initial value (all `0x00`
/// for PCRs 1–23, and either all `0x00` or all `0xFF` for PCR 0 depending on
/// the startup locality recorded by the
/// [`StartupLocality`](crate::event_data::StartupLocality) event).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PcrBank {
    /// The hash algorithm for this bank.
    pub algorithm: HashAlgorithmId,
    /// Emulated PCR values (hex-encoded), keyed by PCR index (0–23).
    pub pcrs: BTreeMap<u32, String>,
}

impl PcrBank {
    /// Returns the emulated value for `pcr_index` as a hex string.
    ///
    /// Returns `None` if the index is outside the valid range 0–23.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::{TcgLogParser, HashAlgorithmId};
    ///
    /// let raw = tcglog_parser::tests::minimal_tcg2_log();
    /// let log = TcgLogParser::new().parse(&raw).unwrap();
    /// let sha256_bank = log.pcr_tables.iter()
    ///     .find(|b| b.algorithm == HashAlgorithmId::Sha256)
    ///     .unwrap();
    /// // EV_NO_ACTION events are never extended into PCRs, so PCR 0 keeps
    /// // its initial value.
    /// assert!(sha256_bank.get_pcr(0).is_some());
    /// assert!(sha256_bank.get_pcr(24).is_none());
    /// ```
    pub fn get_pcr(&self, pcr_index: u32) -> Option<&str> {
        self.pcrs.get(&pcr_index).map(String::as_str)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal PCR state (used only during parsing)
// ──────────────────────────────────────────────────────────────────────────────

/// Internal state for one PCR entry: current digest value and cap status.
#[derive(Debug, Clone)]
pub(crate) struct PcrEntry {
    pub value: Vec<u8>,
    pub capped: bool,
}

impl PcrEntry {
    fn zeros(digest_size: usize) -> Self {
        Self {
            value: vec![0x00u8; digest_size],
            capped: false,
        }
    }

    fn ones(digest_size: usize) -> Self {
        Self {
            value: vec![0xFFu8; digest_size],
            capped: false,
        }
    }
}

/// Mutable PCR state for all banks during parsing.
///
/// One [`PcrState`] is created per parsing run with all PCRs initialised to
/// all-zero bytes.  After the
/// [`StartupLocality`](crate::event_data::StartupLocality) event is processed,
/// [`set_startup_locality`](PcrState::set_startup_locality) must be called to
/// apply the correct initial value for PCR 0 when the TPM was started from
/// H-CRTM locality (3 or 4).
///
/// After all events have been processed, call
/// [`into_banks`](PcrState::into_banks) to produce the final [`PcrBank`] list
/// for inclusion in [`TcgLog`](crate::TcgLog).
pub(crate) struct PcrState {
    algorithms: Vec<(HashAlgorithmId, usize)>, // (alg, digest_size)
    pcrs: Vec<Vec<PcrEntry>>,                   // [bank_idx][pcr_idx 0..=23]
}

impl PcrState {
    /// Creates a new [`PcrState`] with every PCR initialised to all-zero bytes.
    ///
    /// Call [`set_startup_locality`](Self::set_startup_locality) once the
    /// `StartupLocality` event has been parsed.
    pub fn new(algorithms: &[(HashAlgorithmId, usize)]) -> Self {
        let pcrs = algorithms
            .iter()
            .map(|(_, digest_size)| {
                (0..=MAX_PCR_INDEX)
                    .map(|_| PcrEntry::zeros(*digest_size))
                    .collect::<Vec<_>>()
            })
            .collect();
        Self {
            algorithms: algorithms.to_vec(),
            pcrs,
        }
    }

    /// Applies the startup-locality rule for PCR 0.
    ///
    /// If `locality` is in [`HCRTM_LOCALITIES`] (i.e. 3 or 4), PCR 0 is
    /// re-initialised to all `0xFF` bytes in every algorithm bank, as required
    /// by TCG PC Client Platform Firmware Profile §3.3.2.
    ///
    /// This must be called **before** any PCR extension happens (i.e. as soon
    /// as the `StartupLocality` event is encountered).  Because
    /// `EV_NO_ACTION` events are never extended into PCRs, the startup
    /// locality event always precedes any real measurements.
    ///
    /// Calling this with a locality **not** in `HCRTM_LOCALITIES` is a no-op;
    /// PCR 0 retains its all-zero initialisation.
    pub fn set_startup_locality(&mut self, locality: u8) {
        if HCRTM_LOCALITIES.contains(&locality) {
            for (bank_idx, (_, digest_size)) in self.algorithms.iter().enumerate() {
                self.pcrs[bank_idx][0] = PcrEntry::ones(*digest_size);
            }
        }
        // locality 0 (or any other non-H-CRTM value) → PCR 0 remains zeros.
    }

    /// Returns `true` if `pcr_index` is already capped for any algorithm.
    pub fn is_capped(&self, pcr_index: u32) -> bool {
        if pcr_index > MAX_PCR_INDEX {
            return false;
        }
        self.pcrs
            .first()
            .map(|bank| bank[pcr_index as usize].capped)
            .unwrap_or(false)
    }

    /// Marks `pcr_index` as capped in all algorithm banks.
    pub fn cap(&mut self, pcr_index: u32) {
        if pcr_index > MAX_PCR_INDEX {
            return;
        }
        for bank in &mut self.pcrs {
            bank[pcr_index as usize].capped = true;
        }
    }

    /// Extends `pcr_index` with `digest` for the matching algorithm bank.
    ///
    /// If `alg` is not in the bank list (not declared in the SpecID event),
    /// this is a no-op.
    pub fn extend(&mut self, pcr_index: u32, alg: HashAlgorithmId, digest: &[u8]) {
        if pcr_index > MAX_PCR_INDEX {
            return;
        }
        for (bank_idx, (bank_alg, _)) in self.algorithms.iter().enumerate() {
            if *bank_alg == alg {
                let pcr = &mut self.pcrs[bank_idx][pcr_index as usize];
                let new_val = extend_pcr(alg, &pcr.value, digest);
                if !new_val.is_empty() {
                    pcr.value = new_val;
                }
                break;
            }
        }
    }

    /// Consumes the state and returns the final [`PcrBank`] list.
    pub fn into_banks(self) -> Vec<PcrBank> {
        self.algorithms
            .iter()
            .enumerate()
            .map(|(bank_idx, (alg, _))| {
                let pcrs = self.pcrs[bank_idx]
                    .iter()
                    .enumerate()
                    .map(|(pcr_idx, entry)| (pcr_idx as u32, to_hex(&entry.value)))
                    .collect();
                PcrBank {
                    algorithm: *alg,
                    pcrs,
                }
            })
            .collect()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Cryptographic helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Computes `H(pcr || digest)` using the algorithm's native hash function.
///
/// Returns the new PCR value, or an empty `Vec` if the algorithm is not
/// supported for emulation (e.g. [`HashAlgorithmId::Unknown`]).
pub(crate) fn extend_pcr(alg: HashAlgorithmId, pcr: &[u8], digest: &[u8]) -> Vec<u8> {
    match alg {
        HashAlgorithmId::Sha1 => {
            let mut h = Sha1::new();
            Sha1Digest::update(&mut h, pcr);
            Sha1Digest::update(&mut h, digest);
            Sha1Digest::finalize(h).to_vec()
        }
        HashAlgorithmId::Sha256 => {
            let mut h = Sha256::new();
            Sha2Digest::update(&mut h, pcr);
            Sha2Digest::update(&mut h, digest);
            Sha2Digest::finalize(h).to_vec()
        }
        HashAlgorithmId::Sha384 => {
            let mut h = Sha384::new();
            Sha2Digest::update(&mut h, pcr);
            Sha2Digest::update(&mut h, digest);
            Sha2Digest::finalize(h).to_vec()
        }
        HashAlgorithmId::Sha512 => {
            let mut h = Sha512::new();
            Sha2Digest::update(&mut h, pcr);
            Sha2Digest::update(&mut h, digest);
            Sha2Digest::finalize(h).to_vec()
        }
        // SM3-256 and Unknown: cannot emulate without the right hash function.
        _ => Vec::new(),
    }
}

/// Computes `H(data)` for a given algorithm.
///
/// Returns `None` for algorithms that cannot be emulated (e.g.
/// [`HashAlgorithmId::Unknown`]).
pub(crate) fn hash_bytes(alg: HashAlgorithmId, data: &[u8]) -> Option<Vec<u8>> {
    match alg {
        HashAlgorithmId::Sha1 => {
            let mut h = Sha1::new();
            Sha1Digest::update(&mut h, data);
            Some(Sha1Digest::finalize(h).to_vec())
        }
        HashAlgorithmId::Sha256 => {
            let mut h = Sha256::new();
            Sha2Digest::update(&mut h, data);
            Some(Sha2Digest::finalize(h).to_vec())
        }
        HashAlgorithmId::Sha384 => {
            let mut h = Sha384::new();
            Sha2Digest::update(&mut h, data);
            Some(Sha2Digest::finalize(h).to_vec())
        }
        HashAlgorithmId::Sha512 => {
            let mut h = Sha512::new();
            Sha2Digest::update(&mut h, data);
            Some(Sha2Digest::finalize(h).to_vec())
        }
        _ => None,
    }
}

/// Returns the two known separator digest hex strings for a given algorithm:
/// `(normal, error)` where `normal = H([0x00;4])` and `error = H([0xFF;4])`.
///
/// Returns `None` if the algorithm is not supported for emulation.
pub(crate) fn separator_digests(alg: HashAlgorithmId) -> Option<(String, String)> {
    let normal = hash_bytes(alg, &[0x00, 0x00, 0x00, 0x00])?;
    let error = hash_bytes(alg, &[0xFF, 0xFF, 0xFF, 0xFF])?;
    Some((to_hex(&normal), to_hex(&error)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── extend_pcr ────────────────────────────────────────────────────────────

    #[test]
    fn extend_sha1_all_zeros_produces_known_value() {
        let pcr = vec![0u8; 20];
        let digest = vec![0u8; 20];
        let result = extend_pcr(HashAlgorithmId::Sha1, &pcr, &digest);
        assert_eq!(result.len(), 20);
        // Result must differ from the all-zeros input.
        assert_ne!(result, pcr);
    }

    #[test]
    fn extend_sha256_all_zeros_produces_known_value() {
        let pcr = vec![0u8; 32];
        let digest = vec![0u8; 32];
        let result = extend_pcr(HashAlgorithmId::Sha256, &pcr, &digest);
        assert_eq!(result.len(), 32);
        assert_ne!(result, pcr);
    }

    #[test]
    fn extend_sha384_correct_length() {
        let result = extend_pcr(HashAlgorithmId::Sha384, &vec![0u8; 48], &vec![0u8; 48]);
        assert_eq!(result.len(), 48);
    }

    #[test]
    fn extend_sha512_correct_length() {
        let result = extend_pcr(HashAlgorithmId::Sha512, &vec![0u8; 64], &vec![0u8; 64]);
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn extend_unknown_returns_empty() {
        let result = extend_pcr(HashAlgorithmId::Unknown(0xFFFF), &[0u8; 32], &[0u8; 32]);
        assert!(result.is_empty());
    }

    // ── hash_bytes (known-good values) ────────────────────────────────────────

    #[test]
    fn hash_sha256_four_zero_bytes() {
        let h = hash_bytes(HashAlgorithmId::Sha256, &[0u8; 4]).unwrap();
        assert_eq!(h.len(), 32);
        assert_eq!(
            to_hex(&h),
            "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"
        );
    }

    #[test]
    fn hash_sha1_four_zero_bytes() {
        let h = hash_bytes(HashAlgorithmId::Sha1, &[0u8; 4]).unwrap();
        assert_eq!(h.len(), 20);
        assert_eq!(to_hex(&h), "9069ca78e7450a285173431b3e52c5c25299e473");
    }

    #[test]
    fn hash_sha384_four_zero_bytes() {
        let h = hash_bytes(HashAlgorithmId::Sha384, &[0u8; 4]).unwrap();
        assert_eq!(h.len(), 48);
    }

    #[test]
    fn hash_sha512_four_zero_bytes() {
        let h = hash_bytes(HashAlgorithmId::Sha512, &[0u8; 4]).unwrap();
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn hash_unknown_returns_none() {
        assert!(hash_bytes(HashAlgorithmId::Unknown(0), &[]).is_none());
    }

    // ── separator_digests ─────────────────────────────────────────────────────

    #[test]
    fn separator_digests_sha256() {
        let (normal, error) = separator_digests(HashAlgorithmId::Sha256).unwrap();
        assert_eq!(normal, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119");
        assert_eq!(error, "ad95131bc0b799c0b1af477fb14fcf26a6a9f76079e48bf090acb7e8367bfd0e");
    }

    #[test]
    fn separator_digests_sha1() {
        let (normal, error) = separator_digests(HashAlgorithmId::Sha1).unwrap();
        assert_eq!(normal, "9069ca78e7450a285173431b3e52c5c25299e473");
        assert_eq!(error, "d9be6524a5f5047db5866813acf3277892a7a30a");
    }

    #[test]
    fn separator_digests_unknown_none() {
        assert!(separator_digests(HashAlgorithmId::Unknown(0)).is_none());
    }

    // ── PcrState: initial values ───────────────────────────────────────────────

    #[test]
    fn pcr_state_initial_values_all_zeros_locality0() {
        // Locality 0 (or absent): every PCR including PCR 0 starts at zeros.
        let mut state = PcrState::new(&[(HashAlgorithmId::Sha256, 32)]);
        state.set_startup_locality(0);
        let banks = state.into_banks();
        for pcr_idx in 0..=MAX_PCR_INDEX {
            assert_eq!(banks[0].pcrs[&pcr_idx], "0".repeat(64),
                "PCR {} should be all zeros for locality 0", pcr_idx);
        }
    }

    #[test]
    fn pcr_state_initial_pcr0_all_ones_locality3() {
        // Locality 3 (H-CRTM): PCR 0 starts at all 0xFF; PCRs 1-23 start at zeros.
        let mut state = PcrState::new(&[(HashAlgorithmId::Sha256, 32)]);
        state.set_startup_locality(3);
        let banks = state.into_banks();
        assert_eq!(banks[0].pcrs[&0], "ff".repeat(32),
            "PCR 0 should be all 0xFF for locality 3");
        for pcr_idx in 1..=MAX_PCR_INDEX {
            assert_eq!(banks[0].pcrs[&pcr_idx], "0".repeat(64),
                "PCR {} should still be all zeros for locality 3", pcr_idx);
        }
    }

    #[test]
    fn pcr_state_initial_pcr0_all_ones_locality4() {
        // Locality 4 (H-CRTM variant): same rule as locality 3.
        let mut state = PcrState::new(&[(HashAlgorithmId::Sha1, 20)]);
        state.set_startup_locality(4);
        let banks = state.into_banks();
        assert_eq!(banks[0].pcrs[&0], "ff".repeat(20),
            "PCR 0 should be all 0xFF for locality 4");
        for pcr_idx in 1..=MAX_PCR_INDEX {
            assert_eq!(banks[0].pcrs[&pcr_idx], "0".repeat(40),
                "PCR {} should be zeros for locality 4", pcr_idx);
        }
    }

    #[test]
    fn set_startup_locality_applies_to_all_banks() {
        // When multiple algorithms are active, PCR 0 must be all-0xFF in each.
        let mut state = PcrState::new(&[
            (HashAlgorithmId::Sha1, 20),
            (HashAlgorithmId::Sha256, 32),
        ]);
        state.set_startup_locality(3);
        let banks = state.into_banks();
        assert_eq!(banks[0].pcrs[&0], "ff".repeat(20), "SHA-1 PCR 0 not all FF");
        assert_eq!(banks[1].pcrs[&0], "ff".repeat(32), "SHA-256 PCR 0 not all FF");
    }

    #[test]
    fn set_startup_locality_noop_for_locality1() {
        // Localities other than 3/4 are no-ops.
        let mut state = PcrState::new(&[(HashAlgorithmId::Sha256, 32)]);
        state.set_startup_locality(1);
        let banks = state.into_banks();
        assert_eq!(banks[0].pcrs[&0], "0".repeat(64));
    }

    #[test]
    fn set_startup_locality_noop_for_locality2() {
        let mut state = PcrState::new(&[(HashAlgorithmId::Sha256, 32)]);
        state.set_startup_locality(2);
        let banks = state.into_banks();
        assert_eq!(banks[0].pcrs[&0], "0".repeat(64));
    }

    // ── PcrState: extend / cap / emulation ────────────────────────────────────

    #[test]
    fn extend_changes_pcr_value() {
        let mut state = PcrState::new(&[(HashAlgorithmId::Sha256, 32)]);
        let init = state.pcrs[0][0].value.clone();
        state.extend(0, HashAlgorithmId::Sha256, &[0xAAu8; 32]);
        assert_ne!(state.pcrs[0][0].value, init);
    }

    #[test]
    fn extend_from_ff_initial_differs_from_zeros_initial() {
        // Emulating a log with locality 3 should produce a different PCR 0
        // value than a log with locality 0, given the same measurement.
        let digest = [0xABu8; 32];

        let mut state0 = PcrState::new(&[(HashAlgorithmId::Sha256, 32)]);
        state0.set_startup_locality(0);
        state0.extend(0, HashAlgorithmId::Sha256, &digest);

        let mut state3 = PcrState::new(&[(HashAlgorithmId::Sha256, 32)]);
        state3.set_startup_locality(3);
        state3.extend(0, HashAlgorithmId::Sha256, &digest);

        assert_ne!(state0.pcrs[0][0].value, state3.pcrs[0][0].value,
            "PCR 0 after extension must differ when initial value differs");
    }

    #[test]
    fn cap_marks_capped() {
        let mut state = PcrState::new(&[(HashAlgorithmId::Sha256, 32)]);
        assert!(!state.is_capped(4));
        state.cap(4);
        assert!(state.is_capped(4));
        assert!(!state.is_capped(5));
    }

    #[test]
    fn extend_out_of_range_is_noop() {
        let mut state = PcrState::new(&[(HashAlgorithmId::Sha256, 32)]);
        // Should not panic.
        state.extend(100, HashAlgorithmId::Sha256, &[0xAAu8; 32]);
    }

    #[test]
    fn cap_out_of_range_is_noop() {
        let mut state = PcrState::new(&[(HashAlgorithmId::Sha256, 32)]);
        state.cap(100);
        // is_capped returns false for out-of-range.
        assert!(!state.is_capped(100));
    }

    #[test]
    fn into_banks_24_entries_per_algorithm() {
        let state = PcrState::new(&[(HashAlgorithmId::Sha1, 20)]);
        let banks = state.into_banks();
        assert_eq!(banks.len(), 1);
        assert_eq!(banks[0].pcrs.len(), 24);
    }

    #[test]
    fn pcr_bank_get_pcr() {
        let state = PcrState::new(&[(HashAlgorithmId::Sha1, 20)]);
        let banks = state.into_banks();
        assert!(banks[0].get_pcr(0).is_some());
        assert!(banks[0].get_pcr(23).is_some());
        assert!(banks[0].get_pcr(24).is_none());
    }
}
