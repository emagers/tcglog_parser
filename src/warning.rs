//! Non-fatal anomalies detected while parsing a TCG event log.
//!
//! A [`ParseWarning`] is attached to the event at which the anomaly was
//! detected via [`TcgPcrEvent2::warnings`](crate::TcgPcrEvent2::warnings).
//! Warnings never prevent parsing from completing; they carry diagnostic
//! information about deviations from the TCG specification.

use crate::types::{EventType, HashAlgorithmId};
use serde::{Deserialize, Serialize};

/// A non-fatal anomaly detected while parsing a TCG event log.
///
/// Each warning represents a condition that is technically recoverable — the
/// parser can still produce a result — but which indicates that the log may
/// not fully conform to the TCG PC Client Platform Firmware Profile
/// Specification.
///
/// Warnings are associated with the event that triggered them via
/// [`TcgPcrEvent2::warnings`](crate::TcgPcrEvent2::warnings).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ParseWarning {
    /// A measurement was extended into a PCR that had already been capped by
    /// an [`EV_SEPARATOR`](crate::EventType::Separator) event.
    ///
    /// Per the TCG spec, no firmware component should extend a PCR after its
    /// `EV_SEPARATOR` has been recorded.  Such events may indicate firmware
    /// misbehaviour or a tampered log.
    PostCapMeasurement {
        /// The zero-based PCR index that was already capped.
        pcr_index: u32,
    },

    /// A second [`EV_SEPARATOR`](crate::EventType::Separator) was observed for
    /// a PCR that was already capped.  Each PCR should receive exactly one
    /// separator during the pre-OS phase.
    DuplicateSeparator {
        /// The zero-based PCR index.
        pcr_index: u32,
    },

    /// An [`EV_SEPARATOR`](crate::EventType::Separator) event contained the
    /// error sentinel value (`0xFFFFFFFF`), indicating that a firmware error
    /// occurred during pre-boot.
    ErrorSeparator {
        /// The zero-based PCR index.
        pcr_index: u32,
    },

    /// An event that is **not** an [`EV_SEPARATOR`](crate::EventType::Separator)
    /// carries a digest that is identical to a known separator digest (i.e.
    /// the hash of the four-byte normal (`0x00000000`) or error (`0xFFFFFFFF`)
    /// separator sentinel).
    ///
    /// This can indicate a log replay attack or firmware that incorrectly
    /// records separator-valued measurements under a different event type.
    SuspiciousSeparatorDigest {
        /// The zero-based PCR index.
        pcr_index: u32,
        /// The algorithm for which the suspicious digest was found.
        algorithm: HashAlgorithmId,
        /// The suspicious digest (hex-encoded).
        digest: String,
        /// The actual event type that carried the suspicious digest.
        event_type: EventType,
    },

    /// An [`EV_NO_ACTION`](crate::EventType::NoAction) event had a non-zero
    /// digest for at least one algorithm.
    ///
    /// Per the TCG spec, `EV_NO_ACTION` events **MUST** have all digest bytes
    /// set to zero because these events are never extended into any PCR.  A
    /// non-zero digest may indicate log corruption.
    NonZeroNoActionDigest {
        /// The algorithm whose digest was non-zero.
        algorithm: HashAlgorithmId,
    },

    /// The PCR index in this event is outside the valid range 0–23 defined by
    /// the TCG PC Client Platform Firmware Profile Specification.
    InvalidPcrIndex {
        /// The out-of-range PCR index.
        pcr_index: u32,
    },

    /// The number of digests in the event does not match the number of
    /// algorithms declared in the SpecID event.
    ///
    /// Per the TCG spec (§10.2), every event in a crypto-agile log must carry
    /// exactly one digest per algorithm listed in the SpecID header.
    DigestCountMismatch {
        /// Number of algorithms declared in the SpecID header.
        expected: usize,
        /// Number of digests actually present in this event.
        actual: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_cap_measurement_serializes() {
        let w = ParseWarning::PostCapMeasurement { pcr_index: 7 };
        let json = serde_json::to_string(&w).unwrap();
        assert!(json.contains("post_cap_measurement"));
        assert!(json.contains("7"));
    }

    #[test]
    fn duplicate_separator_serializes() {
        let w = ParseWarning::DuplicateSeparator { pcr_index: 4 };
        let json = serde_json::to_string(&w).unwrap();
        assert!(json.contains("duplicate_separator"));
    }

    #[test]
    fn error_separator_serializes() {
        let w = ParseWarning::ErrorSeparator { pcr_index: 0 };
        let json = serde_json::to_string(&w).unwrap();
        assert!(json.contains("error_separator"));
    }

    #[test]
    fn suspicious_separator_digest_serializes() {
        let w = ParseWarning::SuspiciousSeparatorDigest {
            pcr_index: 1,
            algorithm: HashAlgorithmId::Sha256,
            digest: "deadbeef".to_string(),
            event_type: EventType::PostCode,
        };
        let json = serde_json::to_string(&w).unwrap();
        assert!(json.contains("suspicious_separator_digest"));
        assert!(json.contains("sha256"));
    }

    #[test]
    fn non_zero_no_action_digest_serializes() {
        let w = ParseWarning::NonZeroNoActionDigest {
            algorithm: HashAlgorithmId::Sha1,
        };
        let json = serde_json::to_string(&w).unwrap();
        assert!(json.contains("non_zero_no_action_digest"));
    }

    #[test]
    fn invalid_pcr_index_serializes() {
        let w = ParseWarning::InvalidPcrIndex { pcr_index: 100 };
        let json = serde_json::to_string(&w).unwrap();
        assert!(json.contains("invalid_pcr_index"));
        assert!(json.contains("100"));
    }

    #[test]
    fn digest_count_mismatch_serializes() {
        let w = ParseWarning::DigestCountMismatch {
            expected: 2,
            actual: 1,
        };
        let json = serde_json::to_string(&w).unwrap();
        assert!(json.contains("digest_count_mismatch"));
    }
}
