//! Binary parsing logic for TCG event logs.
//!
//! The entry point is [`TcgLogParser`], which can be configured with custom
//! [`EventDataParser`] implementations before calling [`TcgLogParser::parse`].

use crate::error::{Cursor, ParseError};
use crate::event::{DigestValue, TcgLog, TcgPcrEvent, TcgPcrEvent2};
use crate::event_data::{
    SpecIdEvent, StartupLocality, UefiFirmwareBlob, UefiFirmwareBlob2, UefiHandoffTables,
    UefiImageLoadEvent, UefiVariableData,
};
use crate::types::{EventType, HashAlgorithmId, to_hex};

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
    fn parse(
        &self,
        event_type: u32,
        data: &[u8],
    ) -> Result<serde_json::Value, ParseError>;
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

            // Parse remaining events in TCG 2.0 format.
            while !cursor.is_empty() {
                let ev =
                    self.parse_tcg2_event(&mut cursor, &alg_map, uintn_size)?;
                events.push(ev);
            }
        }
        // For TCG 1.2-only logs, events is left empty.

        Ok(TcgLog {
            header,
            spec_id,
            events,
        })
    }

    // ── private helpers ──────────────────────────────────────────────────────

    fn parse_tcg2_event(
        &self,
        cursor: &mut Cursor<'_>,
        alg_map: &[(HashAlgorithmId, usize)],
        uintn_size: u8,
    ) -> Result<TcgPcrEvent2, ParseError> {
        let pcr_index = cursor.read_u32_le()?;
        let event_type_raw = cursor.read_u32_le()?;
        let event_type = EventType::from_value(event_type_raw);

        // Digests
        let digest_count = cursor.read_u32_le()? as usize;
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

        let event_data =
            self.parse_event_data(event_type, event_type_raw, &event_bytes, uintn_size);

        Ok(TcgPcrEvent2 {
            pcr_index,
            event_type,
            digests,
            event_data,
        })
    }

    /// Dispatch to custom or built-in event-data parsers.
    fn parse_event_data(
        &self,
        event_type: EventType,
        event_type_raw: u32,
        data: &[u8],
        uintn_size: u8,
    ) -> serde_json::Value {
        // Try custom parsers first (in registration order).
        for parser in &self.custom_parsers {
            if parser.can_parse(event_type_raw) {
                match parser.parse(event_type_raw, data) {
                    Ok(v) => return v,
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
) -> serde_json::Value {
    match event_type {
        // The SpecID event shows up as EV_NO_ACTION; also handle StartupLocality.
        EventType::NoAction => {
            if let Ok(Some(loc)) = StartupLocality::try_parse(data) {
                return serde_json::to_value(loc).unwrap_or_else(raw_value);
            }
            if let Ok(spec) = SpecIdEvent::parse(data) {
                return serde_json::to_value(spec).unwrap_or_else(raw_value);
            }
            raw_hex(data)
        }

        // EFI variable events share the same payload structure.
        EventType::EfiVariableDriverConfig
        | EventType::EfiVariableBoot
        | EventType::EfiVariableAuthority => match UefiVariableData::parse(data) {
            Ok(v) => serde_json::to_value(v).unwrap_or_else(raw_value),
            Err(_) => raw_hex(data),
        },

        // EFI image load events.
        EventType::EfiBootServicesApplication
        | EventType::EfiBootServicesDriver
        | EventType::EfiRuntimeServicesDriver => {
            match UefiImageLoadEvent::parse(data, uintn_size) {
                Ok(v) => serde_json::to_value(v).unwrap_or_else(raw_value),
                Err(_) => raw_hex(data),
            }
        }

        // EFI firmware blob events.
        EventType::EfiFirmwareBlob => match UefiFirmwareBlob::parse(data) {
            Ok(v) => serde_json::to_value(v).unwrap_or_else(raw_value),
            Err(_) => raw_hex(data),
        },

        EventType::EfiFirmwareBlob2 => match UefiFirmwareBlob2::parse(data) {
            Ok(v) => serde_json::to_value(v).unwrap_or_else(raw_value),
            Err(_) => raw_hex(data),
        },

        // EFI handoff tables.
        EventType::EfiHandoffTables => match UefiHandoffTables::parse(data, uintn_size) {
            Ok(v) => serde_json::to_value(v).unwrap_or_else(raw_value),
            Err(_) => raw_hex(data),
        },

        // EV_EFI_ACTION and EV_ACTION: the payload is a UTF-8 / ASCII string.
        EventType::EfiAction | EventType::Action => {
            let text = String::from_utf8_lossy(data).into_owned();
            serde_json::json!({ "action": text })
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
            serde_json::json!({ "version": text })
        }

        // EV_SEPARATOR: 4-byte value.
        EventType::Separator => {
            if data.len() >= 4 {
                let v = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                serde_json::json!({ "value": v })
            } else {
                raw_hex(data)
            }
        }

        // EV_POST_CODE: UTF-8 string or raw bytes.
        EventType::PostCode => {
            let text = String::from_utf8_lossy(data).into_owned();
            serde_json::json!({ "post_code": text })
        }

        // Everything else: hex-encoded raw bytes.
        _ => raw_hex(data),
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

/// Converts a serialisation error into a raw-hex fallback.
fn raw_value(_: impl std::error::Error) -> serde_json::Value {
    serde_json::json!({ "raw": "" })
}

/// Decode a lowercase hex string to bytes (best effort; odd chars → truncated).
fn hex_decode(hex: &str) -> Vec<u8> {
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
    use crate::tests::minimal_tcg2_log;

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
        data.extend_from_slice(&[0u8; 20]);           // SHA-1 (all zeros)
        data.extend_from_slice(&4u32.to_le_bytes()); // event_size
        data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // event data

        let mut cursor = Cursor::new(&data);
        let ev = parse_tcg1_event(&mut cursor).unwrap();

        assert_eq!(ev.pcr_index, 0);
        assert_eq!(ev.event_type, 3);
        assert_eq!(ev.sha1_digest, "0".repeat(40));
        assert_eq!(ev.event_data, "deadbeef");
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
    }

    // ── custom parser ─────────────────────────────────────────────────────────

    #[test]
    fn custom_parser_is_called() {
        struct AlwaysNull;
        impl EventDataParser for AlwaysNull {
            fn can_parse(&self, _: u32) -> bool { true }
            fn parse(&self, _: u32, _: &[u8]) -> Result<serde_json::Value, ParseError> {
                Ok(serde_json::Value::Null)
            }
        }

        let raw = minimal_tcg2_log();
        let log = TcgLogParser::new()
            .with_parser(Box::new(AlwaysNull))
            .parse(&raw)
            .unwrap();

        // Custom parser overrides built-in; event_data should be null.
        assert!(log.events[0].event_data.is_null());
    }

    #[test]
    fn custom_parser_not_called_for_other_types() {
        struct OnlyVendor;
        impl EventDataParser for OnlyVendor {
            fn can_parse(&self, event_type: u32) -> bool { event_type == 0xA0000001 }
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
        // Built-in parser should handle it (StartupLocality).
        assert!(!log.events[0].event_data.is_null());
    }

    // ── TCG 1.2-only log (no SpecID) ─────────────────────────────────────────

    #[test]
    fn parse_tcg1_only_log() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes()); // pcr_index
        data.extend_from_slice(&4u32.to_le_bytes()); // EV_SEPARATOR
        data.extend_from_slice(&[0xAA; 20]);          // SHA-1
        data.extend_from_slice(&4u32.to_le_bytes()); // event_size
        data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);

        let log = TcgLogParser::new().parse(&data).unwrap();
        assert!(log.spec_id.is_none());
        assert!(log.events.is_empty());
        assert_eq!(log.header.event_type, 4); // EV_SEPARATOR
    }

    // ── event data parsing ────────────────────────────────────────────────────

    #[test]
    fn builtin_parser_efi_action() {
        let data = b"Calling EFI Application from Boot Option";
        let v = parse_builtin_event_data(EventType::EfiAction, data, 8);
        assert_eq!(v["action"], "Calling EFI Application from Boot Option");
    }

    #[test]
    fn builtin_parser_separator() {
        let data = [0x00, 0x00, 0x00, 0x00];
        let v = parse_builtin_event_data(EventType::Separator, &data, 8);
        assert_eq!(v["value"], 0);
    }

    #[test]
    fn builtin_parser_scrtm_version() {
        // "1.0" in UTF-16LE + null terminator
        let data: Vec<u8> = "1.0\0"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let v = parse_builtin_event_data(EventType::SCrtmVersion, &data, 8);
        assert_eq!(v["version"], "1.0");
    }

    #[test]
    fn builtin_parser_unknown_type_gives_raw() {
        let data = [0xDE, 0xAD];
        let v = parse_builtin_event_data(EventType::Unknown(0xFF), &data, 8);
        assert_eq!(v["raw"], "dead");
    }
}
