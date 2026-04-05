//! Core event structures for TCG 1.2 and TCG 2.0 event logs.

use crate::event_data::{
    EfiGptData, HcrtmComponentEvent, SpecIdEvent, SpecIdEvent00, SpecIdEvent02,
    Sp800155Event, Sp800155Event2, Sp800155Event3, StartupLocality, TaggedEvent,
    UefiFirmwareBlob, UefiFirmwareBlob2, UefiHandoffTables, UefiHandoffTables2,
    UefiImageLoadEvent, UefiVariableData, WbclEventData,
};
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
    /// The raw digest bytes; serializes as a hex string.
    #[serde(serialize_with = "hex_serialize", deserialize_with = "hex_deserialize")]
    pub digest: Vec<u8>,
}

fn hex_serialize<S: serde::Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&to_hex(bytes))
}

fn hex_deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(d)?;
    Ok(crate::parser::hex_decode(&s))
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
    /// assert_eq!(digest.digest.len(), 32); // raw bytes
    /// ```
    pub fn new(hash_alg: HashAlgorithmId, bytes: Vec<u8>) -> Self {
        Self {
            hash_alg,
            digest: bytes,
        }
    }

    /// Returns the digest as a hex-encoded string.
    pub fn digest_hex(&self) -> String {
        to_hex(&self.digest)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// EventData enum  (replaces serde_json::Value for zero-cost serialization)
// ──────────────────────────────────────────────────────────────────────────────

/// Typed event-data payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventData {
    /// Startup locality (`EV_NO_ACTION` sub-type).
    StartupLocality(StartupLocality),
    /// SpecID event (`EV_NO_ACTION` sub-type, TCG 2.0 crypto-agile).
    SpecId(SpecIdEvent),
    /// SpecID event for conventional BIOS (`EV_NO_ACTION` sub-type).
    SpecId00(SpecIdEvent00),
    /// SpecID event for EFI 1.2 (`EV_NO_ACTION` sub-type).
    SpecId02(SpecIdEvent02),
    /// SP 800-155 reference manifest event (`EV_NO_ACTION` sub-type).
    Sp800155(Sp800155Event),
    /// SP 800-155 reference manifest event v2 (`EV_NO_ACTION` sub-type).
    Sp800155v2(Sp800155Event2),
    /// SP 800-155 reference manifest event v3 (`EV_NO_ACTION` sub-type).
    Sp800155v3(Sp800155Event3),
    /// H-CRTM component measurement (`EV_NO_ACTION` sub-type).
    HcrtmComponent(HcrtmComponentEvent),
    /// UEFI variable (`EV_EFI_VARIABLE_*`).
    UefiVariable(UefiVariableData),
    /// UEFI image load (`EV_EFI_BOOT_SERVICES_APPLICATION`, etc.).
    UefiImageLoad(UefiImageLoadEvent),
    /// UEFI firmware blob (`EV_EFI_PLATFORM_FIRMWARE_BLOB`).
    FirmwareBlob(UefiFirmwareBlob),
    /// UEFI firmware blob 2 (`EV_EFI_PLATFORM_FIRMWARE_BLOB2`).
    FirmwareBlob2(UefiFirmwareBlob2),
    /// UEFI handoff tables (`EV_EFI_HANDOFF_TABLES`).
    HandoffTables(UefiHandoffTables),
    /// UEFI handoff tables 2 (`EV_EFI_HANDOFF_TABLES2`).
    HandoffTables2(UefiHandoffTables2),
    /// EFI GPT partition table event (`EV_EFI_GPT_EVENT` / `EV_EFI_GPT_EVENT2`).
    EfiGpt(EfiGptData),
    /// TCG Tagged Event (`EV_EVENT_TAG` — standard `TCG_PCClientTaggedEvent`).
    Tagged(TaggedEvent),
    /// Windows Boot Configuration Log (`EV_EVENT_TAG` — Windows SIPA sub-events).
    Wbcl(WbclEventData),
    /// Any other event, stored as a generic JSON value (custom parsers,
    /// inline JSON for actions/separators, or raw hex fallback).
    Json(serde_json::Value),
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
/// The `event_data` field contains a typed [`EventData`] enum with the
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
    pub event_data: EventData,
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
/// `events` will be empty, and `legacy_events` will contain all events after
/// the header in TCG 1.2 format.
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
    /// All events following the header in TCG 1.2 format.
    ///
    /// Populated only for legacy TCG 1.2-only logs (when `spec_id` is
    /// `None`).  Empty for TCG 2.0 logs.
    pub legacy_events: Vec<TcgPcrEvent>,
    /// Emulated PCR tables, one per active hash algorithm.
    ///
    /// Each bank holds the final PCR values after replaying all events.
    /// Empty for legacy TCG 1.2-only logs (no SpecID, no algorithm list).
    pub pcr_tables: Vec<PcrBank>,
}
