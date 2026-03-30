//! Core event structures for TCG 1.2 and TCG 2.0 event logs.

use crate::pcr::PcrBank;
use crate::types::{EventType, HashAlgorithmId, to_hex};
use crate::warning::ParseWarning;
use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────────────────────────────────────
// TCG 1.2 event  (first event in a crypto-agile log, or all events in a 1.2 log)
// ──────────────────────────────────────────────────────────────────────────────

/// A TCG 1.2 format event (`TCG_PCClientPCREvent`).
///
/// This structure appears as the **first** event in a TCG 2.0 (crypto-agile)
/// event log — where its event data contains a [`SpecIdEvent`](crate::event_data::SpecIdEvent) —
/// and is also the only event format used in legacy TCG 1.2-only logs.
///
/// All fields are stored in little-endian byte order on disk.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TcgPcrEvent {
    /// Index of the TPM Platform Configuration Register (PCR) extended.
    pub pcr_index: u32,
    /// Numeric event type value.
    pub event_type: u32,
    /// SHA-1 digest, hex-encoded.
    pub sha1_digest: String,
    /// Raw event data, hex-encoded.
    pub event_data: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Digest value
// ──────────────────────────────────────────────────────────────────────────────

/// A single hash digest with its associated algorithm identifier.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DigestValue {
    /// The hash algorithm used to produce this digest.
    pub hash_alg: HashAlgorithmId,
    /// The digest bytes, hex-encoded.
    pub digest: String,
}

impl DigestValue {
    /// Creates a new [`DigestValue`].
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::{DigestValue, HashAlgorithmId};
    ///
    /// let digest = DigestValue::new(HashAlgorithmId::Sha256, vec![0u8; 32]);
    /// assert_eq!(digest.hash_alg, HashAlgorithmId::Sha256);
    /// assert_eq!(digest.digest.len(), 64); // 32 bytes → 64 hex chars
    /// ```
    pub fn new(hash_alg: HashAlgorithmId, bytes: Vec<u8>) -> Self {
        Self {
            hash_alg,
            digest: to_hex(&bytes),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// TCG 2.0 (crypto-agile) event
// ──────────────────────────────────────────────────────────────────────────────

/// A TCG 2.0 crypto-agile event (`TCG_PCR_EVENT2`).
///
/// These events appear after the first [`TcgPcrEvent`] in a crypto-agile log.
/// Unlike the TCG 1.2 format, a single event can carry digests from multiple
/// hash algorithms simultaneously.
///
/// The `event_data` field contains a [`serde_json::Value`] that holds the
/// parsed event payload.  Built-in parsers handle the most common UEFI event
/// types; custom parsers can be registered via
/// [`TcgLogParser::with_parser`](crate::TcgLogParser::with_parser).
///
/// Any non-fatal spec violations detected while parsing this event are
/// collected in the `warnings` field and do not prevent the event from
/// being included in the parsed log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcgPcrEvent2 {
    /// Index of the TPM Platform Configuration Register (PCR) extended.
    pub pcr_index: u32,
    /// The event type.
    pub event_type: EventType,
    /// All digests associated with this event, one per active hash algorithm.
    pub digests: Vec<DigestValue>,
    /// The parsed event payload.  The structure depends on `event_type`; for
    /// unrecognised event types the value is a JSON object with a single
    /// `"raw"` field containing a hex string.
    pub event_data: serde_json::Value,
    /// Non-fatal spec violations detected for this event.
    ///
    /// An empty list means the event appears fully conformant.  Callers
    /// should treat any non-empty list as a signal that the log may deviate
    /// from the TCG PC Client Platform Firmware Profile Specification.
    pub warnings: Vec<ParseWarning>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Full log
// ──────────────────────────────────────────────────────────────────────────────

/// A fully parsed TCG event log.
///
/// # Structure
///
/// A TCG 2.0 (crypto-agile) log begins with a [`TcgPcrEvent`] in the TCG 1.2
/// format whose event data contains a [`SpecIdEvent`](crate::event_data::SpecIdEvent).
/// The `header` field holds this first event, `spec_id` holds the parsed
/// SpecID event (if the log is in TCG 2.0 format), and `events` holds all
/// subsequent events in the crypto-agile format.
///
/// For legacy TCG 1.2-only logs (no SpecID header), `spec_id` will be `None`,
/// `events` will be empty, and `pcr_tables` will be empty.
///
/// # PCR tables
///
/// The `pcr_tables` field contains one [`PcrBank`] per active hash algorithm.
/// Each bank holds the emulated PCR values computed by replaying all events
/// through the PCR extension formula `PCR_new = H(PCR_old || digest)`.
/// PCRs start at all-zero bytes and are updated for every non-`EV_NO_ACTION`
/// event.
///
/// # JSON output
///
/// Implementing [`serde::Serialize`] on all constituent types means that
/// `serde_json::to_string_pretty(&log)` produces a valid JSON document
/// representing the full log.  Digests are hex-encoded strings; GUIDs are
/// formatted as `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`; custom event-data
/// parsers can return any [`serde_json::Value`] which will be embedded
/// verbatim in the output.
///
/// # Examples
///
/// ```
/// use tcglog_parser::{TcgLog, TcgLogParser};
///
/// // Build a minimal TCG 2.0 log binary.
/// let raw = tcglog_parser::tests::minimal_tcg2_log();
/// let log = TcgLogParser::new().parse(&raw).unwrap();
///
/// assert!(log.spec_id.is_some());
/// // PCR tables are present with one bank (SHA-256).
/// assert_eq!(log.pcr_tables.len(), 1);
/// // JSON output is valid.
/// let json = serde_json::to_string_pretty(&log).unwrap();
/// assert!(json.contains("sha256"));
/// assert!(json.contains("pcr_tables"));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcgLog {
    /// The first event in TCG 1.2 format (always present).
    pub header: TcgPcrEvent,
    /// The parsed SpecID event extracted from `header`, if present.
    ///
    /// `None` for legacy TCG 1.2-only logs.
    pub spec_id: Option<crate::event_data::SpecIdEvent>,
    /// All events following the header, in TCG 2.0 crypto-agile format.
    ///
    /// Empty for legacy TCG 1.2-only logs.
    pub events: Vec<TcgPcrEvent2>,
    /// Emulated PCR tables, one per active hash algorithm.
    ///
    /// Each bank holds the final PCR values after replaying all events.
    /// Empty for legacy TCG 1.2-only logs (no SpecID, no algorithm list).
    pub pcr_tables: Vec<PcrBank>,
}
