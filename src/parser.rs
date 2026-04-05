//! Binary parsing logic for TCG event logs.
//!
//! The entry point is [`TcgLogParser`], which can be configured with custom
//! [`EventDataParser`] implementations before calling [`TcgLogParser::parse`].

use crate::error::{Cursor, ParseError};
use crate::event::{DigestValue, EventData, TcgLog, TcgPcrEvent, TcgPcrEvent2};
use crate::event_data::{
    SpecIdEvent, StartupLocality, UefiFirmwareBlob, UefiFirmwareBlob2, UefiHandoffTables,
    UefiHandoffTables2, UefiImageLoadEvent, UefiVariableData, WbclEventData,
};
use crate::pcr::{MAX_PCR_INDEX, PcrState, separator_digests};
use crate::types::{EventType, HashAlgorithmId, to_hex};
use crate::warning::ParseWarning;

// ──────────────────────────────────────────────────────────────────────────────
// Extensibility trait
// ──────────────────────────────────────────────────────────────────────────────

/// A trait for parsing custom event-data payloads from raw bytes.
///
/// Implement this trait to teach the library how to decode event types that
/// are not handled by the built-in parsers.  Custom parsers are tried **before**
/// the built-in ones, so they can also override built-in behaviour.
///
/// # Example
///
/// ```rust
/// use tcglog_parser::{EventDataParser, ParseError, TcgLogParser};
///
/// /// A parser that handles a hypothetical vendor event type 0xA0000001.
/// struct VendorParser;
///
/// impl EventDataParser for VendorParser {
///     fn can_parse(&self, event_type: u32) -> bool {
///         event_type == 0xA0000001
///     }
///
///     fn parse(
///         &self,
///         _event_type: u32,
///         data: &[u8],
///     ) -> Result<serde_json::Value, ParseError> {
///         // Interpret the payload as a UTF-8 string.
///         let text = String::from_utf8_lossy(data).into_owned();
///         Ok(serde_json::json!({ "vendor_message": text }))
///     }
/// }
///
/// // Register the custom parser before parsing:
/// let parser = TcgLogParser::new().with_parser(Box::new(VendorParser));
/// // parser.parse(&raw_bytes) would now use VendorParser for 0xA0000001 events.
/// ```
pub trait EventDataParser: Send + Sync {
    /// Returns `true` if this parser can handle events with the given type value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tcglog_parser::EventDataParser;
    ///
    /// struct MyParser;
    /// impl EventDataParser for MyParser {
    ///     fn can_parse(&self, event_type: u32) -> bool { event_type == 42 }
    ///     fn parse(&self, _: u32, _: &[u8]) -> Result<serde_json::Value, tcglog_parser::ParseError> {
    ///         Ok(serde_json::Value::Null)
    ///     }
    /// }
    ///
    /// let p = MyParser;
    /// assert!(p.can_parse(42));
    /// assert!(!p.can_parse(99));
    /// ```
    fn can_parse(&self, event_type: u32) -> bool;

    /// Parse `data` into a [`serde_json::Value`] for events of `event_type`.
    ///
    /// This method is only called when [`can_parse`](Self::can_parse) returns `true`.
    ///
    /// # Errors
    ///
    /// Return [`ParseError::CustomParser`] (or any other [`ParseError`] variant)
    /// if the data cannot be decoded.
    fn parse(&self, event_type: u32, data: &[u8]) -> Result<serde_json::Value, ParseError>;
}

// ──────────────────────────────────────────────────────────────────────────────
// Parser
// ──────────────────────────────────────────────────────────────────────────────

/// Builder and parser for TCG event logs.
///
/// [`TcgLogParser`] supports both TCG 1.2 (SHA-1 only) and TCG 2.0
/// (crypto-agile) binary event log formats as specified in the
/// *TCG PC Client Platform Firmware Profile Specification*.
///
/// # Quick start
///
/// ```rust
/// use tcglog_parser::TcgLogParser;
///
/// let raw = tcglog_parser::tests::minimal_tcg2_log();
/// let log = TcgLogParser::new().parse(&raw).unwrap();
///
/// assert!(log.spec_id.is_some());
/// // Serialize the whole log to JSON.
/// let json = serde_json::to_string_pretty(&log).unwrap();
/// println!("{json}");
/// ```
///
/// # Extensibility
///
/// Register one or more [`EventDataParser`] implementations with
/// [`with_parser`](Self::with_parser) before calling [`parse`](Self::parse).
/// Custom parsers take precedence over the built-in ones.
///
/// ```rust
/// use tcglog_parser::{EventDataParser, ParseError, TcgLogParser};
///
/// struct MyParser;
/// impl EventDataParser for MyParser {
///     fn can_parse(&self, event_type: u32) -> bool { event_type == 0xA0000001 }
///     fn parse(&self, _: u32, data: &[u8]) -> Result<serde_json::Value, ParseError> {
///         Ok(serde_json::json!({ "raw": tcglog_parser::to_hex(data) }))
///     }
/// }
///
/// let raw = tcglog_parser::tests::minimal_tcg2_log();
/// let log = TcgLogParser::new()
///     .with_parser(Box::new(MyParser))
///     .parse(&raw)
///     .unwrap();
/// let _ = serde_json::to_string(&log).unwrap();
/// ```
pub struct TcgLogParser {
    custom_parsers: Vec<Box<dyn EventDataParser>>,
}

impl TcgLogParser {
    /// Creates a new [`TcgLogParser`] with only the built-in event parsers.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::TcgLogParser;
    ///
    /// let parser = TcgLogParser::new();
    /// ```
    pub fn new() -> Self {
        Self {
            custom_parsers: Vec::new(),
        }
    }

    /// Registers a custom [`EventDataParser`] and returns `self` for chaining.
    ///
    /// Custom parsers are tried **before** the built-in ones, in the order they
    /// were added.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::{EventDataParser, ParseError, TcgLogParser};
    ///
    /// struct Noop;
    /// impl EventDataParser for Noop {
    ///     fn can_parse(&self, _: u32) -> bool { false }
    ///     fn parse(&self, _: u32, _: &[u8]) -> Result<serde_json::Value, ParseError> {
    ///         Ok(serde_json::Value::Null)
    ///     }
    /// }
    ///
    /// let parser = TcgLogParser::new().with_parser(Box::new(Noop));
    /// ```
    pub fn with_parser(mut self, parser: Box<dyn EventDataParser>) -> Self {
        self.custom_parsers.push(parser);
        self
    }

    /// Parses a raw TCG event log from a byte slice.
    ///
    /// # Format detection
    ///
    /// The parser automatically detects whether the log uses the TCG 1.2
    /// (SHA-1 only) or the TCG 2.0 (crypto-agile) format by examining the
    /// first event.  If the first event is an `EV_NO_ACTION` event whose data
    /// begins with the `"Spec ID Event03\0"` signature, a TCG 2.0 log is
    /// assumed and subsequent events are parsed in the crypto-agile format.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] if the data is malformed or truncated.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::TcgLogParser;
    ///
    /// let raw = tcglog_parser::tests::minimal_tcg2_log();
    /// let log = TcgLogParser::new().parse(&raw).unwrap();
    /// assert!(log.spec_id.is_some());
    /// assert_eq!(log.events.len(), 1); // one additional event in the fixture
    /// ```
    pub fn parse(&self, data: &[u8]) -> Result<TcgLog, ParseError> {
        let mut cursor = Cursor::new(data);

        // Parse the first event (always TCG 1.2 format).
        let header = parse_tcg1_event(&mut cursor)?;

        // Attempt to parse it as a SpecID event.
        let spec_id = if header.event_type == EventType::NoAction.to_value() {
            // event_data is hex — decode it back to bytes for sub-parsing
            SpecIdEvent::parse(&hex_decode(header.event_data.as_str())).ok()
        } else {
            None
        };

        let mut events = Vec::new();
        let mut legacy_events = Vec::new();
        let mut pcr_tables = Vec::new();

        if let Some(ref spec) = spec_id {
            // Build the algorithm map from the SpecID event.
            let alg_map: Vec<(HashAlgorithmId, usize)> = spec
                .algorithms
                .iter()
                .map(|a| {
                    (
                        HashAlgorithmId::from_id(a.algorithm_id),
                        a.digest_size as usize,
                    )
                })
                .collect();

            let uintn_size = spec.uintn_size;

            // Pre-compute known separator digests for each algorithm.
            let sep_digests: Vec<(HashAlgorithmId, Option<(String, String)>)> = alg_map
                .iter()
                .map(|(alg, _)| (*alg, separator_digests(*alg)))
                .collect();

            // Initialise PCR emulation state.
            let mut pcr_state = PcrState::new(&alg_map);

            // Parse remaining events in TCG 2.0 format.
            while !cursor.is_empty() {
                let ev = self.parse_tcg2_event(
                    &mut cursor,
                    &alg_map,
                    uintn_size,
                    &sep_digests,
                    &mut pcr_state,
                )?;
                events.push(ev);
            }

            // Emit the final PCR tables.
            pcr_tables = pcr_state.into_banks();
        } else {
            // TCG 1.2-only log: parse remaining events in TCG 1.2 format.
            while !cursor.is_empty() {
                legacy_events.push(parse_tcg1_event(&mut cursor)?);
            }
        }

        Ok(TcgLog {
            header,
            spec_id,
            events,
            legacy_events,
            pcr_tables,
        })
    }

    // ── private helpers ──────────────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    fn parse_tcg2_event(
        &self,
        cursor: &mut Cursor<'_>,
        alg_map: &[(HashAlgorithmId, usize)],
        uintn_size: u8,
        sep_digests: &[(HashAlgorithmId, Option<(String, String)>)],
        pcr_state: &mut PcrState,
    ) -> Result<TcgPcrEvent2, ParseError> {
        let pcr_index = cursor.read_u32_le()?;
        let event_type_raw = cursor.read_u32_le()?;
        let event_type = EventType::from_value(event_type_raw);

        let mut warnings: Vec<ParseWarning> = Vec::new();

        // ── PCR index validation ──────────────────────────────────────────
        if pcr_index > MAX_PCR_INDEX {
            warnings.push(ParseWarning::InvalidPcrIndex { pcr_index });
        }

        // ── Digests ───────────────────────────────────────────────────────
        let digest_count = cursor.read_u32_le()? as usize;

        // Warn if count doesn't match the SpecID algorithm list.
        if digest_count != alg_map.len() {
            warnings.push(ParseWarning::DigestCountMismatch {
                expected: alg_map.len(),
                actual: digest_count,
            });
        }

        let mut digests = Vec::with_capacity(digest_count);
        for _ in 0..digest_count {
            let alg_id = cursor.read_u16_le()?;
            let alg = HashAlgorithmId::from_id(alg_id);
            // Determine digest size from the alg_map (from SpecID).
            let digest_size = alg_map
                .iter()
                .find(|(a, _)| *a == alg)
                .map(|(_, s)| *s)
                .or_else(|| alg.digest_size())
                .unwrap_or(0);
            let digest_bytes = cursor.read_bytes(digest_size)?.to_vec();
            digests.push(DigestValue::new(alg, digest_bytes));
        }

        let event_size = cursor.read_u32_le()? as usize;
        let event_bytes = cursor.read_bytes(event_size)?.to_vec();

        // ── EV_NO_ACTION: digests MUST be all zeros ───────────────────────
        if event_type == EventType::NoAction {
            for dv in &digests {
                if dv.digest.chars().any(|c| c != '0') {
                    warnings.push(ParseWarning::NonZeroNoActionDigest {
                        algorithm: dv.hash_alg,
                    });
                }
            }

            // Detect StartupLocality event and apply PCR 0 initialisation.
            // Per TCG PFP §3.3.2, when the TPM is started from locality 3 or 4
            // (H-CRTM), PCR 0 is initialised to all 0xFF instead of all 0x00.
            // EV_NO_ACTION events never extend PCRs, so it is safe to update
            // the initial PCR 0 value here before any measurements arrive.
            if let Ok(Some(loc)) = StartupLocality::try_parse(&event_bytes) {
                pcr_state.set_startup_locality(loc.startup_locality);
            }
        }

        // ── PCR capping / suspicious digest checks ────────────────────────
        if event_type == EventType::Separator {
            self.handle_separator(pcr_index, &event_bytes, pcr_state, &mut warnings);
        } else if event_type != EventType::NoAction {
            // Non-separator, non-no-action: check for post-cap and suspicious digests.
            if pcr_index <= MAX_PCR_INDEX && pcr_state.is_capped(pcr_index) {
                warnings.push(ParseWarning::PostCapMeasurement { pcr_index });
            }

            for dv in &digests {
                if let Some(sep_pair) = sep_digests
                    .iter()
                    .find(|(alg, _)| *alg == dv.hash_alg)
                    .and_then(|(_, pair)| pair.as_ref())
                    && (dv.digest == sep_pair.0 || dv.digest == sep_pair.1)
                {
                    warnings.push(ParseWarning::SuspiciousSeparatorDigest {
                        pcr_index,
                        algorithm: dv.hash_alg,
                        digest: dv.digest.clone(),
                        event_type,
                    });
                }
            }
        }

        // ── PCR extension (skip EV_NO_ACTION) ─────────────────────────────
        if event_type != EventType::NoAction && pcr_index <= MAX_PCR_INDEX {
            for dv in &digests {
                let digest_bytes = hex_decode(&dv.digest);
                pcr_state.extend(pcr_index, dv.hash_alg, &digest_bytes);
            }
        }

        let event_data =
            self.parse_event_data(event_type, event_type_raw, &event_bytes, uintn_size);

        Ok(TcgPcrEvent2 {
            pcr_index,
            event_type,
            digests,
            event_data,
            warnings,
        })
    }

    /// Handle an EV_SEPARATOR event: validate data, update cap state, emit warnings.
    fn handle_separator(
        &self,
        pcr_index: u32,
        event_bytes: &[u8],
        pcr_state: &mut PcrState,
        warnings: &mut Vec<ParseWarning>,
    ) {
        if pcr_index > MAX_PCR_INDEX {
            // InvalidPcrIndex warning already emitted above.
            return;
        }

        if pcr_state.is_capped(pcr_index) {
            warnings.push(ParseWarning::DuplicateSeparator { pcr_index });
        } else {
            pcr_state.cap(pcr_index);
        }

        // Check for error separator: event data != 0x00000000.
        if let Ok(bytes) = <&[u8; 4]>::try_from(&event_bytes[..event_bytes.len().min(4)])
            && u32::from_le_bytes(*bytes) != 0x00000000
        {
            warnings.push(ParseWarning::ErrorSeparator { pcr_index });
        }
    }

    /// Dispatch to custom or built-in event-data parsers.
    fn parse_event_data(
        &self,
        event_type: EventType,
        event_type_raw: u32,
        data: &[u8],
        uintn_size: u8,
    ) -> EventData {
        // Try custom parsers first (in registration order).
        for parser in &self.custom_parsers {
            if parser.can_parse(event_type_raw) {
                match parser.parse(event_type_raw, data) {
                    Ok(v) => return EventData::Json(v),
                    Err(_) => break,
                }
            }
        }

        // Fall back to built-in parsers.
        parse_builtin_event_data(event_type, data, uintn_size)
    }
}

impl Default for TcgLogParser {
    fn default() -> Self {
        Self::new()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Built-in event-data parsers
// ──────────────────────────────────────────────────────────────────────────────

/// Dispatch to the appropriate built-in parser for a known event type.
fn parse_builtin_event_data(
    event_type: EventType,
    data: &[u8],
    uintn_size: u8,
) -> EventData {
    match event_type {
        // The SpecID event shows up as EV_NO_ACTION; also handle StartupLocality.
        EventType::NoAction => {
            if let Ok(Some(loc)) = StartupLocality::try_parse(data) {
                return EventData::StartupLocality(loc);
            }
            if let Ok(spec) = SpecIdEvent::parse(data) {
                return EventData::SpecId(spec);
            }
            EventData::Json(raw_hex(data))
        }

        // EFI variable events share the same payload structure.
        EventType::EfiVariableDriverConfig
        | EventType::EfiVariableBoot
        | EventType::EfiVariableBoot2
        | EventType::EfiVariableAuthority => match UefiVariableData::parse(data) {
            Ok(v) => EventData::UefiVariable(v),
            Err(_) => EventData::Json(raw_hex(data)),
        },

        // EFI image load events.
        EventType::EfiBootServicesApplication
        | EventType::EfiBootServicesDriver
        | EventType::EfiRuntimeServicesDriver => {
            match UefiImageLoadEvent::parse(data, uintn_size) {
                Ok(v) => EventData::UefiImageLoad(v),
                Err(_) => EventData::Json(raw_hex(data)),
            }
        }

        // EFI firmware blob events.
        EventType::EfiFirmwareBlob => match UefiFirmwareBlob::parse(data) {
            Ok(v) => EventData::FirmwareBlob(v),
            Err(_) => EventData::Json(raw_hex(data)),
        },

        EventType::EfiFirmwareBlob2 => match UefiFirmwareBlob2::parse(data) {
            Ok(v) => EventData::FirmwareBlob2(v),
            Err(_) => EventData::Json(raw_hex(data)),
        },

        // EFI handoff tables.
        EventType::EfiHandoffTables => match UefiHandoffTables::parse(data, uintn_size) {
            Ok(v) => EventData::HandoffTables(v),
            Err(_) => EventData::Json(raw_hex(data)),
        },

        EventType::EfiHandoffTables2 => match UefiHandoffTables2::parse(data, uintn_size) {
            Ok(v) => EventData::HandoffTables2(v),
            Err(_) => EventData::Json(raw_hex(data)),
        },

        // EV_EVENT_TAG: Windows Boot Configuration Log (WBCL) / SIPA events.
        EventType::EventTag => match WbclEventData::parse(data) {
            Ok(v) => EventData::Wbcl(v),
            Err(_) => EventData::Json(raw_hex(data)),
        },

        // EV_EFI_ACTION and EV_ACTION: the payload is a UTF-8 / ASCII string.
        EventType::EfiAction | EventType::Action => {
            let text = String::from_utf8_lossy(data).into_owned();
            EventData::Json(serde_json::json!({ "action": text }))
        }

        // EV_S_CRTM_VERSION: UTF-16LE string.
        EventType::SCrtmVersion => {
            let u16s: Vec<u16> = data
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect();
            let text = String::from_utf16_lossy(&u16s)
                .trim_matches('\0')
                .to_string();
            EventData::Json(serde_json::json!({ "version": text }))
        }

        // EV_SEPARATOR: 4-byte value.
        EventType::Separator => {
            if data.len() >= 4 {
                let v = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                EventData::Json(serde_json::json!({ "value": v }))
            } else {
                EventData::Json(raw_hex(data))
            }
        }

        // EV_POST_CODE: UTF-8 string or raw bytes.
        EventType::PostCode => {
            let text = String::from_utf8_lossy(data).into_owned();
            EventData::Json(serde_json::json!({ "post_code": text }))
        }

        // Everything else: hex-encoded raw bytes.
        _ => EventData::Json(raw_hex(data)),
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Helper functions
// ──────────────────────────────────────────────────────────────────────────────

/// Parse the first event in TCG 1.2 format.
fn parse_tcg1_event(cursor: &mut Cursor<'_>) -> Result<TcgPcrEvent, ParseError> {
    let pcr_index = cursor.read_u32_le()?;
    let event_type = cursor.read_u32_le()?;
    let sha1 = cursor.read_bytes(20)?.to_vec();
    let event_size = cursor.read_u32_le()? as usize;
    let event_bytes = cursor.read_bytes(event_size)?.to_vec();

    Ok(TcgPcrEvent {
        pcr_index,
        event_type,
        sha1_digest: to_hex(&sha1),
        event_data: to_hex(&event_bytes),
    })
}

/// Returns a `{"raw": "<hex>"}` JSON value.
fn raw_hex(data: &[u8]) -> serde_json::Value {
    serde_json::json!({ "raw": to_hex(data) })
}



/// Decode a lowercase hex string to bytes (best effort; odd chars → truncated).
pub(crate) fn hex_decode(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks(2)
        .filter_map(|c| {
            if c.len() == 2 {
                let hi = hex_nibble(c[0])?;
                let lo = hex_nibble(c[1])?;
                Some((hi << 4) | lo)
            } else {
                None
            }
        })
        .collect()
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{
        append_tcg2_event, first_event_bytes, minimal_tcg2_log, spec_id_bytes,
        tcg2_log_with_efi_variable, tcg2_log_with_firmware_blob,
    };
    use crate::warning::ParseWarning;

    // ── hex helpers ───────────────────────────────────────────────────────────

    #[test]
    fn hex_decode_round_trip() {
        let bytes = vec![0x00u8, 0xAB, 0xCD, 0xFF];
        let hex = to_hex(&bytes);
        assert_eq!(hex_decode(&hex), bytes);
    }

    #[test]
    fn hex_decode_empty() {
        assert_eq!(hex_decode(""), Vec::<u8>::new());
    }

    // ── TCG 1.2 event parsing ─────────────────────────────────────────────────

    #[test]
    fn parse_tcg1_event_basic() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes()); // pcr_index
        data.extend_from_slice(&3u32.to_le_bytes()); // event_type (EV_NO_ACTION)
        data.extend_from_slice(&[0u8; 20]); // SHA-1 (all zeros)
        data.extend_from_slice(&4u32.to_le_bytes()); // event_size
        data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // event data

        let mut cursor = Cursor::new(&data);
        let ev = parse_tcg1_event(&mut cursor).unwrap();

        assert_eq!(ev.pcr_index, 0);
        assert_eq!(ev.event_type, 3);
        assert_eq!(ev.sha1_digest, "0".repeat(40));
        assert_eq!(ev.event_data, "deadbeef");
    }

    #[test]
    fn parse_tcg1_event_truncated_returns_error() {
        let data = [0x00u8; 5]; // too short for a full TCG 1.2 event
        let mut cursor = Cursor::new(&data);
        assert!(parse_tcg1_event(&mut cursor).is_err());
    }

    // ── full log parsing ──────────────────────────────────────────────────────

    #[test]
    fn parse_minimal_tcg2_log() {
        let raw = minimal_tcg2_log();
        let log = TcgLogParser::new().parse(&raw).unwrap();

        assert!(log.spec_id.is_some());
        let spec = log.spec_id.as_ref().unwrap();
        assert_eq!(spec.spec_version_major, 2);
        assert_eq!(spec.algorithms.len(), 1);
        assert_eq!(spec.algorithms[0].algorithm_id, 0x000B); // SHA-256

        assert_eq!(log.events.len(), 1);
        let ev = &log.events[0];
        assert_eq!(ev.pcr_index, 0);
        assert_eq!(ev.event_type, EventType::NoAction);
        assert_eq!(ev.digests.len(), 1);
        assert_eq!(ev.digests[0].hash_alg, HashAlgorithmId::Sha256);

        // PCR tables emitted.
        assert_eq!(log.pcr_tables.len(), 1);
        assert_eq!(log.pcr_tables[0].algorithm, HashAlgorithmId::Sha256);
        // 24 PCR entries.
        assert_eq!(log.pcr_tables[0].pcrs.len(), 24);
    }

    // ── PCR 0 initialization by startup locality ───────────────────────────────

    #[test]
    fn pcr0_initialized_to_zeros_for_locality0() {
        // Locality 0 (normal firmware): PCR 0 starts at all zeros.
        let raw = crate::tests::tcg2_log_with_locality(0);
        let log = TcgLogParser::new().parse(&raw).unwrap();
        let sha256 = &log.pcr_tables[0];
        assert_eq!(
            sha256.pcrs[&0],
            "0".repeat(64),
            "locality 0: PCR 0 must be all zeros"
        );
        // Other PCRs also zeros.
        for pcr in 1..=23u32 {
            assert_eq!(sha256.pcrs[&pcr], "0".repeat(64));
        }
    }

    #[test]
    fn pcr0_initialized_to_ff_for_locality3() {
        // Locality 3 (H-CRTM): PCR 0 starts at all 0xFF.
        let raw = crate::tests::tcg2_log_with_locality(3);
        let log = TcgLogParser::new().parse(&raw).unwrap();
        let sha256 = &log.pcr_tables[0];
        assert_eq!(
            sha256.pcrs[&0],
            "ff".repeat(32),
            "locality 3: PCR 0 must be all 0xFF"
        );
        // PCRs 1-23 remain zeros.
        for pcr in 1..=23u32 {
            assert_eq!(
                sha256.pcrs[&pcr],
                "0".repeat(64),
                "locality 3: PCR {} must still be zeros",
                pcr
            );
        }
    }

    #[test]
    fn pcr0_initialized_to_ff_for_locality4() {
        // Locality 4 (H-CRTM variant): same rule as locality 3.
        let raw = crate::tests::tcg2_log_with_locality(4);
        let log = TcgLogParser::new().parse(&raw).unwrap();
        let sha256 = &log.pcr_tables[0];
        assert_eq!(
            sha256.pcrs[&0],
            "ff".repeat(32),
            "locality 4: PCR 0 must be all 0xFF"
        );
    }

    #[test]
    fn pcr0_initialized_to_zeros_for_locality1_and_2() {
        // Localities 1 and 2 are not H-CRTM localities; PCR 0 stays zeros.
        for loc in [1u8, 2] {
            let raw = crate::tests::tcg2_log_with_locality(loc);
            let log = TcgLogParser::new().parse(&raw).unwrap();
            assert_eq!(
                log.pcr_tables[0].pcrs[&0],
                "0".repeat(64),
                "locality {}: PCR 0 must be zeros",
                loc
            );
        }
    }

    #[test]
    fn locality3_pcr0_extension_differs_from_locality0() {
        // A measurement to PCR 0 produces a different result depending on the
        // initial PCR 0 value (all-zeros vs all-0xFF).
        let digest_hex = "cd".repeat(32);

        let make_log_with_post_measurement = |locality: u8| -> Vec<u8> {
            let spec = spec_id_bytes(&[(0x000B, 32)]);
            let mut log = first_event_bytes(&spec);

            // StartupLocality event.
            let mut startup = Vec::new();
            startup.extend_from_slice(b"StartupLocality\0");
            startup.push(locality);
            log.extend_from_slice(&0u32.to_le_bytes()); // pcr_index
            log.extend_from_slice(&3u32.to_le_bytes()); // EV_NO_ACTION
            log.extend_from_slice(&1u32.to_le_bytes()); // digest_count
            log.extend_from_slice(&0x000Bu16.to_le_bytes());
            log.extend_from_slice(&[0u8; 32]);
            log.extend_from_slice(&(startup.len() as u32).to_le_bytes());
            log.extend_from_slice(&startup);

            // EV_POST_CODE into PCR 0 with the same digest.
            let mut ev = Vec::new();
            ev.extend_from_slice(&0u32.to_le_bytes()); // pcr_index = 0
            ev.extend_from_slice(&1u32.to_le_bytes()); // EV_POST_CODE
            ev.extend_from_slice(&1u32.to_le_bytes()); // digest_count
            ev.extend_from_slice(&0x000Bu16.to_le_bytes());
            let raw_digest = crate::parser::hex_decode(&digest_hex);
            ev.extend_from_slice(&raw_digest);
            ev.extend_from_slice(&4u32.to_le_bytes());
            ev.extend_from_slice(b"code");
            log.extend_from_slice(&ev);
            log
        };

        let log0 = TcgLogParser::new()
            .parse(&make_log_with_post_measurement(0))
            .unwrap();
        let log3 = TcgLogParser::new()
            .parse(&make_log_with_post_measurement(3))
            .unwrap();

        let pcr0_loc0 = &log0.pcr_tables[0].pcrs[&0];
        let pcr0_loc3 = &log3.pcr_tables[0].pcrs[&0];

        assert_ne!(
            pcr0_loc0, pcr0_loc3,
            "Same measurement into PCR 0 must produce different values \
             when startup locality differs (different initial PCR 0 value)"
        );
    }

    #[test]
    fn no_startup_locality_event_defaults_to_zeros() {
        // A log with no StartupLocality event defaults to all-zero PCR 0.
        let spec = spec_id_bytes(&[(0x000B, 32)]);
        let log_bytes = first_event_bytes(&spec); // only SpecID header, no StartupLocality
        let log = TcgLogParser::new().parse(&log_bytes).unwrap();
        assert_eq!(
            log.pcr_tables[0].pcrs[&0],
            "0".repeat(64),
            "Absent StartupLocality event must default PCR 0 to zeros"
        );
    }

    // ── JSON serialization ────────────────────────────────────────────────────

    #[test]
    fn serialize_to_json() {
        let raw = minimal_tcg2_log();
        let log = TcgLogParser::new().parse(&raw).unwrap();
        let json = serde_json::to_string_pretty(&log).unwrap();

        // Must be valid JSON.
        let _parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(json.contains("sha256"));
        assert!(json.contains("spec_id"));
        assert!(json.contains("pcr_tables"));
    }

    #[test]
    fn serialize_efi_variable_log_to_json() {
        let raw = tcg2_log_with_efi_variable();
        let log = TcgLogParser::new().parse(&raw).unwrap();
        let json = serde_json::to_string_pretty(&log).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["events"][0]["event_data"]["unicode_name"], "SecureBoot");
    }

    #[test]
    fn serialize_firmware_blob_log_to_json() {
        let raw = tcg2_log_with_firmware_blob();
        let log = TcgLogParser::new().parse(&raw).unwrap();
        let json = serde_json::to_string_pretty(&log).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["events"][0]["event_data"]["blob_base"], 0xFF000000u64);
    }

    // ── custom parser ─────────────────────────────────────────────────────────

    #[test]
    fn custom_parser_is_called() {
        struct AlwaysNull;
        impl EventDataParser for AlwaysNull {
            fn can_parse(&self, _: u32) -> bool {
                true
            }
            fn parse(&self, _: u32, _: &[u8]) -> Result<serde_json::Value, ParseError> {
                Ok(serde_json::Value::Null)
            }
        }

        let raw = minimal_tcg2_log();
        let log = TcgLogParser::new()
            .with_parser(Box::new(AlwaysNull))
            .parse(&raw)
            .unwrap();

        // Custom parser overrides built-in; event_data should be Json(Null).
        assert!(matches!(log.events[0].event_data, EventData::Json(serde_json::Value::Null)));
    }

    #[test]
    fn custom_parser_not_called_for_other_types() {
        struct OnlyVendor;
        impl EventDataParser for OnlyVendor {
            fn can_parse(&self, event_type: u32) -> bool {
                event_type == 0xA0000001
            }
            fn parse(&self, _: u32, _: &[u8]) -> Result<serde_json::Value, ParseError> {
                Ok(serde_json::json!({ "vendor": true }))
            }
        }

        let raw = minimal_tcg2_log();
        let log = TcgLogParser::new()
            .with_parser(Box::new(OnlyVendor))
            .parse(&raw)
            .unwrap();

        // The fixture event type is EV_NO_ACTION (3), not 0xA0000001.
        assert!(!matches!(log.events[0].event_data, EventData::Json(serde_json::Value::Null)));
    }

    // ── TCG 1.2-only log (no SpecID) ─────────────────────────────────────────

    #[test]
    fn parse_tcg1_only_log() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes()); // pcr_index
        data.extend_from_slice(&4u32.to_le_bytes()); // EV_SEPARATOR
        data.extend_from_slice(&[0xAA; 20]); // SHA-1
        data.extend_from_slice(&4u32.to_le_bytes()); // event_size
        data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);

        let log = TcgLogParser::new().parse(&data).unwrap();
        assert!(log.spec_id.is_none());
        assert!(log.events.is_empty());
        assert!(log.legacy_events.is_empty());
        assert!(log.pcr_tables.is_empty());
        assert_eq!(log.header.event_type, 4); // EV_SEPARATOR
    }

    #[test]
    fn parse_tcg1_multi_event_log() {
        // Build a TCG 1.2 log with a header and two additional events.
        let mut data = Vec::new();

        // Header event (EV_POST_CODE).
        data.extend_from_slice(&0u32.to_le_bytes()); // pcr_index = 0
        data.extend_from_slice(&1u32.to_le_bytes()); // EV_POST_CODE
        data.extend_from_slice(&[0xBB; 20]); // SHA-1
        data.extend_from_slice(&4u32.to_le_bytes()); // event_size
        data.extend_from_slice(b"POST");

        // Second event (EV_SEPARATOR for PCR 0).
        data.extend_from_slice(&0u32.to_le_bytes()); // pcr_index = 0
        data.extend_from_slice(&4u32.to_le_bytes()); // EV_SEPARATOR
        data.extend_from_slice(&[0xCC; 20]); // SHA-1
        data.extend_from_slice(&4u32.to_le_bytes()); // event_size
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // Third event (EV_ACTION for PCR 1).
        data.extend_from_slice(&1u32.to_le_bytes()); // pcr_index = 1
        data.extend_from_slice(&5u32.to_le_bytes()); // EV_ACTION
        data.extend_from_slice(&[0xDD; 20]); // SHA-1
        data.extend_from_slice(&6u32.to_le_bytes()); // event_size
        data.extend_from_slice(b"action");

        let log = TcgLogParser::new().parse(&data).unwrap();
        assert!(log.spec_id.is_none());
        assert!(log.events.is_empty());
        assert_eq!(log.legacy_events.len(), 2);
        assert_eq!(log.legacy_events[0].event_type, 4); // EV_SEPARATOR
        assert_eq!(log.legacy_events[0].pcr_index, 0);
        assert_eq!(log.legacy_events[1].event_type, 5); // EV_ACTION
        assert_eq!(log.legacy_events[1].pcr_index, 1);
        assert_eq!(log.legacy_events[1].event_data, to_hex(b"action"));
    }

    // ── event data parsing ────────────────────────────────────────────────────

    #[test]
    fn builtin_parser_efi_action() {
        let data = b"Calling EFI Application from Boot Option";
        let v = parse_builtin_event_data(EventType::EfiAction, data, 8);
        match v {
            EventData::Json(ref j) => assert_eq!(j["action"], "Calling EFI Application from Boot Option"),
            _ => panic!("expected EventData::Json"),
        }
    }

    #[test]
    fn builtin_parser_separator() {
        let data = [0x00, 0x00, 0x00, 0x00];
        let v = parse_builtin_event_data(EventType::Separator, &data, 8);
        match v {
            EventData::Json(ref j) => assert_eq!(j["value"], 0),
            _ => panic!("expected EventData::Json"),
        }
    }

    #[test]
    fn builtin_parser_scrtm_version() {
        // "1.0" in UTF-16LE + null terminator
        let data: Vec<u8> = "1.0\0"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let v = parse_builtin_event_data(EventType::SCrtmVersion, &data, 8);
        match v {
            EventData::Json(ref j) => assert_eq!(j["version"], "1.0"),
            _ => panic!("expected EventData::Json"),
        }
    }

    #[test]
    fn builtin_parser_unknown_type_gives_raw() {
        let data = [0xDE, 0xAD];
        let v = parse_builtin_event_data(EventType::Unknown(0xFF), &data, 8);
        match v {
            EventData::Json(ref j) => assert_eq!(j["raw"], "dead"),
            _ => panic!("expected EventData::Json"),
        }
    }

    // ── PCR capping / warnings ────────────────────────────────────────────────

    /// Build a log with an EV_SEPARATOR followed by another measurement to the
    /// same PCR (which should trigger PostCapMeasurement).
    fn log_with_post_cap_measurement() -> Vec<u8> {
        let spec = spec_id_bytes(&[(0x000B, 32)]);
        let mut log = first_event_bytes(&spec);

        // EV_SEPARATOR for PCR 0 (normal: data = 0x00000000).
        let sep_digest = crate::pcr::hash_bytes(HashAlgorithmId::Sha256, &[0u8; 4]).unwrap();
        append_tcg2_event(&mut log, 0, 0x00000004, &[(0x000B, 32)], &[0x00; 4]);
        // Overwrite the digest with the actual separator digest.
        // (append_tcg2_event uses zero digest; that's fine — warning is from the cap, not the digest)
        let _ = sep_digest; // suppress warning

        // Another event targeting PCR 0 after it's been capped.
        append_tcg2_event(&mut log, 0, 0x00000001, &[(0x000B, 32)], b"POST_CODE");

        log
    }

    #[test]
    fn post_cap_measurement_warning() {
        let raw = log_with_post_cap_measurement();
        let log = TcgLogParser::new().parse(&raw).unwrap();

        // First event is the separator (no post-cap warning).
        assert!(
            log.events[0]
                .warnings
                .iter()
                .all(|w| !matches!(w, ParseWarning::PostCapMeasurement { .. }))
        );
        // Second event should have PostCapMeasurement warning.
        assert!(
            log.events[1]
                .warnings
                .iter()
                .any(|w| matches!(w, ParseWarning::PostCapMeasurement { pcr_index: 0 }))
        );
    }

    #[test]
    fn duplicate_separator_warning() {
        let spec = spec_id_bytes(&[(0x000B, 32)]);
        let mut log = first_event_bytes(&spec);
        // Two EV_SEPARATOR events for PCR 0.
        append_tcg2_event(&mut log, 0, 0x00000004, &[(0x000B, 32)], &[0u8; 4]);
        append_tcg2_event(&mut log, 0, 0x00000004, &[(0x000B, 32)], &[0u8; 4]);

        let parsed = TcgLogParser::new().parse(&log).unwrap();
        // Second separator should warn.
        assert!(
            parsed.events[1]
                .warnings
                .iter()
                .any(|w| matches!(w, ParseWarning::DuplicateSeparator { pcr_index: 0 }))
        );
    }

    #[test]
    fn error_separator_warning() {
        let spec = spec_id_bytes(&[(0x000B, 32)]);
        let mut log = first_event_bytes(&spec);
        // EV_SEPARATOR with error value 0xFFFFFFFF.
        append_tcg2_event(&mut log, 0, 0x00000004, &[(0x000B, 32)], &[0xFF; 4]);

        let parsed = TcgLogParser::new().parse(&log).unwrap();
        assert!(
            parsed.events[0]
                .warnings
                .iter()
                .any(|w| matches!(w, ParseWarning::ErrorSeparator { pcr_index: 0 }))
        );
    }

    #[test]
    fn invalid_pcr_index_warning() {
        let spec = spec_id_bytes(&[(0x000B, 32)]);
        let mut log = first_event_bytes(&spec);
        // Event with PCR index 100 (out of range).
        append_tcg2_event(&mut log, 100, 0x00000001, &[(0x000B, 32)], b"data");

        let parsed = TcgLogParser::new().parse(&log).unwrap();
        assert!(
            parsed.events[0]
                .warnings
                .iter()
                .any(|w| matches!(w, ParseWarning::InvalidPcrIndex { pcr_index: 100 }))
        );
    }

    #[test]
    fn digest_count_mismatch_warning() {
        // SpecID says 2 algorithms but event only has 1 digest.
        let spec = spec_id_bytes(&[(0x000B, 32), (0x0004, 20)]);
        let mut log = first_event_bytes(&spec);
        // Event with only 1 digest (SHA-256) instead of 2.
        append_tcg2_event(&mut log, 0, 0x00000001, &[(0x000B, 32)], b"data");

        let parsed = TcgLogParser::new().parse(&log).unwrap();
        assert!(parsed.events[0].warnings.iter().any(|w| matches!(
            w,
            ParseWarning::DigestCountMismatch {
                expected: 2,
                actual: 1
            }
        )));
    }

    #[test]
    fn non_zero_no_action_digest_warning() {
        let spec = spec_id_bytes(&[(0x000B, 32)]);
        let mut log = first_event_bytes(&spec);

        // EV_NO_ACTION event with non-zero SHA-256 digest.
        let mut event_bytes = Vec::new();
        event_bytes.extend_from_slice(&0u32.to_le_bytes()); // pcr_index
        event_bytes.extend_from_slice(&3u32.to_le_bytes()); // EV_NO_ACTION
        event_bytes.extend_from_slice(&1u32.to_le_bytes()); // digest_count
        event_bytes.extend_from_slice(&0x000Bu16.to_le_bytes()); // SHA-256
        event_bytes.extend_from_slice(&[0xAAu8; 32]); // non-zero digest
        event_bytes.extend_from_slice(&4u32.to_le_bytes()); // event_size
        event_bytes.extend_from_slice(&[0u8; 4]); // event data
        log.extend_from_slice(&event_bytes);

        let parsed = TcgLogParser::new().parse(&log).unwrap();
        assert!(parsed.events[0].warnings.iter().any(|w| matches!(
            w,
            ParseWarning::NonZeroNoActionDigest {
                algorithm: HashAlgorithmId::Sha256
            }
        )));
    }

    #[test]
    fn suspicious_separator_digest_warning() {
        // SHA-256 of [0,0,0,0] — this is the known normal separator digest.
        let sep_digest = crate::pcr::hash_bytes(HashAlgorithmId::Sha256, &[0u8; 4]).unwrap();

        let spec = spec_id_bytes(&[(0x000B, 32)]);
        let mut log = first_event_bytes(&spec);

        // A EV_POST_CODE event (not a separator) with the separator digest.
        let mut ev = Vec::new();
        ev.extend_from_slice(&0u32.to_le_bytes()); // pcr_index
        ev.extend_from_slice(&1u32.to_le_bytes()); // EV_POST_CODE
        ev.extend_from_slice(&1u32.to_le_bytes()); // digest_count
        ev.extend_from_slice(&0x000Bu16.to_le_bytes()); // SHA-256 alg
        ev.extend_from_slice(&sep_digest); // the separator digest value
        ev.extend_from_slice(&4u32.to_le_bytes()); // event_size
        ev.extend_from_slice(&[0u8; 4]);
        log.extend_from_slice(&ev);

        let parsed = TcgLogParser::new().parse(&log).unwrap();
        assert!(parsed.events[0].warnings.iter().any(|w| matches!(
            w,
            ParseWarning::SuspiciousSeparatorDigest {
                algorithm: HashAlgorithmId::Sha256,
                ..
            }
        )));
    }

    #[test]
    fn separator_event_does_not_get_suspicious_warning() {
        // An actual EV_SEPARATOR with the normal separator digest should NOT get
        // the SuspiciousSeparatorDigest warning (only non-separator events get it).
        let sep_digest = crate::pcr::hash_bytes(HashAlgorithmId::Sha256, &[0u8; 4]).unwrap();

        let spec = spec_id_bytes(&[(0x000B, 32)]);
        let mut log = first_event_bytes(&spec);

        let mut ev = Vec::new();
        ev.extend_from_slice(&0u32.to_le_bytes()); // pcr_index
        ev.extend_from_slice(&4u32.to_le_bytes()); // EV_SEPARATOR
        ev.extend_from_slice(&1u32.to_le_bytes()); // digest_count
        ev.extend_from_slice(&0x000Bu16.to_le_bytes());
        ev.extend_from_slice(&sep_digest);
        ev.extend_from_slice(&4u32.to_le_bytes()); // event_size = 4
        ev.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // normal separator data
        log.extend_from_slice(&ev);

        let parsed = TcgLogParser::new().parse(&log).unwrap();
        assert!(
            !parsed.events[0]
                .warnings
                .iter()
                .any(|w| matches!(w, ParseWarning::SuspiciousSeparatorDigest { .. }))
        );
    }

    #[test]
    fn no_warnings_on_clean_log() {
        let raw = minimal_tcg2_log();
        let log = TcgLogParser::new().parse(&raw).unwrap();
        for ev in &log.events {
            assert!(
                ev.warnings.is_empty(),
                "unexpected warnings: {:?}",
                ev.warnings
            );
        }
    }

    // ── PCR emulation through real events ─────────────────────────────────────

    #[test]
    fn pcr_emulation_extends_correctly() {
        // Add a real non-EV_NO_ACTION event and verify PCR 0 changed.
        let spec = spec_id_bytes(&[(0x000B, 32)]);
        let mut log = first_event_bytes(&spec);
        // EV_POST_CODE with a known non-zero digest.
        let digest = [0xABu8; 32];
        let mut ev = Vec::new();
        ev.extend_from_slice(&0u32.to_le_bytes()); // pcr_index = 0
        ev.extend_from_slice(&1u32.to_le_bytes()); // EV_POST_CODE
        ev.extend_from_slice(&1u32.to_le_bytes()); // digest_count
        ev.extend_from_slice(&0x000Bu16.to_le_bytes());
        ev.extend_from_slice(&digest);
        ev.extend_from_slice(&4u32.to_le_bytes());
        ev.extend_from_slice(b"code");
        log.extend_from_slice(&ev);

        let parsed = TcgLogParser::new().parse(&log).unwrap();
        let sha256 = &parsed.pcr_tables[0];

        // PCR 0 should no longer be all-zeros.
        assert_ne!(sha256.pcrs[&0], "0".repeat(64));
        // PCR 1 should still be all-zeros (untouched).
        assert_eq!(sha256.pcrs[&1], "0".repeat(64));
    }
}
