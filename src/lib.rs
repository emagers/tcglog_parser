//! # tcglog_parser
//!
//! A Rust library for parsing **TCG (Trusted Computing Group) TPM event logs**
//! into typed Rust structures, and for serialising those structures to JSON.
//!
//! The library supports both:
//!
//! * **TCG 1.2** (SHA-1 only) event logs — the legacy format used by older
//!   BIOS/firmware.
//! * **TCG 2.0 crypto-agile** event logs — the modern UEFI format that supports
//!   multiple hash algorithms simultaneously (SHA-1, SHA-256, SHA-384, …).
//!
//! The implementation follows the
//! *TCG PC Client Platform Firmware Profile Specification* (TCG PFP).
//!
//! ## Basic usage
//!
//! ```rust
//! use tcglog_parser::TcgLogParser;
//!
//! // Load a raw log from disk (or build one in tests).
//! let raw = tcglog_parser::tests::minimal_tcg2_log();
//!
//! // Parse the log.
//! let log = TcgLogParser::new().parse(&raw).unwrap();
//!
//! // Access structured fields.
//! if let Some(ref spec) = log.spec_id {
//!     println!("TCG spec version {}.{}", spec.spec_version_major, spec.spec_version_minor);
//!     for alg in &spec.algorithms {
//!         println!("  algorithm {:#06x}, digest {} bytes", alg.algorithm_id, alg.digest_size);
//!     }
//! }
//!
//! for ev in &log.events {
//!     println!("PCR[{}] {:?}", ev.pcr_index, ev.event_type);
//! }
//!
//! // Serialise the entire log to a JSON string.
//! let json = serde_json::to_string_pretty(&log).unwrap();
//! println!("{json}");
//! ```
//!
//! ## Extensibility
//!
//! The library ships parsers for the event-data types defined in the TCG and
//! UEFI specifications.  You can plug in **custom parsers** for proprietary or
//! future event types without modifying the library:
//!
//! ```rust
//! use tcglog_parser::{EventDataParser, ParseError, TcgLogParser};
//!
//! /// Parses a hypothetical vendor event type (0xA0000001).
//! struct VendorParser;
//!
//! impl EventDataParser for VendorParser {
//!     fn can_parse(&self, event_type: u32) -> bool {
//!         event_type == 0xA0000001
//!     }
//!
//!     fn parse(
//!         &self,
//!         _event_type: u32,
//!         data: &[u8],
//!     ) -> Result<serde_json::Value, ParseError> {
//!         // Interpret the payload as a UTF-8 string.
//!         let text = String::from_utf8_lossy(data).into_owned();
//!         Ok(serde_json::json!({ "vendor_message": text }))
//!     }
//! }
//!
//! let raw = tcglog_parser::tests::minimal_tcg2_log();
//! let log = TcgLogParser::new()
//!     .with_parser(Box::new(VendorParser))
//!     .parse(&raw)
//!     .unwrap();
//!
//! // The log can still be serialised to JSON; custom event data is included
//! // verbatim in the output.
//! let json = serde_json::to_string_pretty(&log).unwrap();
//! assert!(serde_json::from_str::<serde_json::Value>(&json).is_ok());
//! ```
//!
//! ## JSON output format
//!
//! All types implement [`serde::Serialize`] and [`serde::Deserialize`].
//! Noteworthy encoding choices:
//!
//! | Field type | JSON encoding |
//! |---|---|
//! | Binary digest / raw bytes | Lowercase hexadecimal string |
//! | [`HashAlgorithmId`] | String name (e.g. `"sha256"`) |
//! | [`EventType`] | String name (e.g. `"EV_NO_ACTION"`) |
//! | UEFI [`Guid`] | `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` string |
//! | Custom event data | Embedded as-is (any valid JSON value) |

pub mod error;
pub mod event;
pub mod event_data;
pub mod parser;
pub mod pcr;
pub mod types;
pub mod warning;

// ── Public re-exports ─────────────────────────────────────────────────────────

pub use error::ParseError;
pub use event::{DigestValue, TcgLog, TcgPcrEvent, TcgPcrEvent2};
pub use event_data::{
    AlgorithmSize, CertificateInfo, EfiConfigurationTable, EfiSignatureEntry, EfiSignatureList,
    SpecIdEvent, StartupLocality, UefiFirmwareBlob, UefiFirmwareBlob2,
    UefiHandoffTables, UefiHandoffTables2, UefiImageLoadEvent, UefiVariableData, WbclEventData,
};
pub use event_data::wbcl::{
    BitlockerUnlockData, DriverLoadPolicyData, HashAlgorithmData, KsrSignaturePayload,
    OsDeviceData, RevocationListPayload, SbcpInfoPayload, SiPolicyCertPayload,
    SiPolicyPayload, SiPolicySignerPayload,
    SipaBytes, SipaEvent, SipaEventData, SipaEventType, TransferControlData,
    SIPAEVENT_SI_POLICY_SIGNER, SIPAEVENT_SI_POLICY_UPDATE_SIGNER,
    sipa_event_name,
    SIPAEVENTTYPE_NONMEASURED, SIPAEVENTTYPE_AGGREGATION,
    SIPAEVENT_TRUSTBOUNDARY, SIPAEVENT_ELAM_AGGREGATION, SIPAEVENT_LOADEDMODULE_AGGREGATION,
    SIPAEVENT_TRUSTPOINT_AGGREGATION, SIPAERROR_FIRMWAREFAILURE, SIPAERROR_TPMFAILURE,
    SIPAERROR_INTERNALFAILURE, SIPAEVENT_BOOTCOUNTER, SIPAEVENT_TRANSFER_CONTROL,
    SIPAEVENT_BITLOCKER_UNLOCK, SIPAEVENT_EVENTCOUNTER, SIPAEVENT_COUNTERID,
    SIPAEVENT_BOOTDEBUGGING, SIPAEVENT_OSKERNELDEBUG, SIPAEVENT_CODEINTEGRITY,
    SIPAEVENT_TESTSIGNING, SIPAEVENT_SAFEMODE, SIPAEVENT_WINPE, SIPAEVENT_OSDEVICE,
    SIPAEVENT_SYSTEMROOT, SIPAEVENT_HYPERVISOR_LAUNCH_TYPE, SIPAEVENT_HYPERVISOR_DEBUG,
    SIPAEVENT_DRIVER_LOAD_POLICY, SIPAEVENT_NOAUTHORITY, SIPAEVENT_AUTHORITYPUBKEY,
    SIPAEVENT_FILEPATH, SIPAEVENT_IMAGESIZE, SIPAEVENT_HASHALGORITHMID,
    SIPAEVENT_AUTHENTICODEHASH, SIPAEVENT_AUTHORITYISSUER, SIPAEVENT_AUTHORITYSERIAL,
    SIPAEVENT_IMAGEBASE, SIPAEVENT_AUTHORITYPUBLISHER, SIPAEVENT_AUTHORITYSHA1THUMBPRINT,
    SIPAEVENT_IMAGEVALIDATED, SIPAEVENT_QUOTE, SIPAEVENT_QUOTESIGNATURE,
    SIPAEVENT_AIKID, SIPAEVENT_AIKPUBDIGEST, SIPAEVENT_ELAM_KEYNAME,
    SIPAEVENT_MODULE_PLUTON, SIPAEVENT_MODULE_ORIGINAL_FILENAME, SIPAEVENT_MODULE_TIMESTAMP,
    SIPAEVENT_VBS_VSM_REQUIRED, SIPAEVENT_VBS_SECUREBOOT_REQUIRED,
};
pub use parser::{EventDataParser, TcgLogParser};
pub use pcr::PcrBank;
pub use types::{EventType, Guid, HashAlgorithmId, to_hex};
pub use warning::ParseWarning;

// ── Test helpers (public so doc-tests in other modules can use them) ──────────

/// Utilities for building synthetic TCG log binaries in tests.
///
/// These are exposed publicly so that users of the library can construct
/// minimal test fixtures in their own integration tests without duplicating
/// the binary-building logic.
pub mod tests {
    /// Builds a minimal valid TCG 2.0 (crypto-agile) log binary.
    ///
    /// The log contains:
    /// 1. A TCG 1.2-format header event carrying a `SpecIdEvent` that
    ///    advertises SHA-256 as the only algorithm.
    /// 2. A single `EV_NO_ACTION` `StartupLocality` event (locality = 3,
    ///    H-CRTM).  Per TCG PFP §3.3.2, this causes PCR 0 to be initialised
    ///    to all `0xFF` bytes in the emulated PCR table.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::{TcgLogParser, HashAlgorithmId};
    ///
    /// let raw = tcglog_parser::tests::minimal_tcg2_log();
    /// let log = TcgLogParser::new().parse(&raw).unwrap();
    ///
    /// assert!(log.spec_id.is_some());
    /// assert_eq!(log.events.len(), 1);
    /// assert_eq!(log.events[0].digests[0].hash_alg, HashAlgorithmId::Sha256);
    /// // Locality 3 → PCR 0 starts at all 0xFF.
    /// assert_eq!(log.pcr_tables[0].pcrs[&0], "ff".repeat(32));
    /// ```
    pub fn minimal_tcg2_log() -> Vec<u8> {
        // ── SpecID event data ──────────────────────────────────────────────
        let mut spec_id_data = Vec::new();
        spec_id_data.extend_from_slice(b"Spec ID Event03\0"); // signature
        spec_id_data.extend_from_slice(&0u32.to_le_bytes()); // platform_class
        spec_id_data.push(0); // minor
        spec_id_data.push(2); // major
        spec_id_data.push(0); // errata
        spec_id_data.push(8); // uintn_size (64-bit)
        spec_id_data.extend_from_slice(&1u32.to_le_bytes()); // num_algorithms
        spec_id_data.extend_from_slice(&0x000Bu16.to_le_bytes()); // SHA-256
        spec_id_data.extend_from_slice(&32u16.to_le_bytes()); // digest size
        spec_id_data.push(0); // vendor_info_size

        // ── First event (TCG 1.2 format, carries SpecID) ──────────────────
        let mut log = Vec::new();
        log.extend_from_slice(&0u32.to_le_bytes()); // pcr_index
        log.extend_from_slice(&3u32.to_le_bytes()); // EV_NO_ACTION
        log.extend_from_slice(&[0u8; 20]); // SHA-1 (zeros)
        log.extend_from_slice(&(spec_id_data.len() as u32).to_le_bytes());
        log.extend_from_slice(&spec_id_data);

        // ── Second event (TCG 2.0 format, StartupLocality) ────────────────
        let mut startup_data = Vec::new();
        startup_data.extend_from_slice(b"StartupLocality\0");
        startup_data.push(3); // locality

        log.extend_from_slice(&0u32.to_le_bytes()); // pcr_index
        log.extend_from_slice(&3u32.to_le_bytes()); // EV_NO_ACTION
        log.extend_from_slice(&1u32.to_le_bytes()); // digest_count
        log.extend_from_slice(&0x000Bu16.to_le_bytes()); // SHA-256 alg id
        log.extend_from_slice(&[0u8; 32]); // SHA-256 digest (zeros)
        log.extend_from_slice(&(startup_data.len() as u32).to_le_bytes());
        log.extend_from_slice(&startup_data);

        log
    }

    /// Builds a TCG 2.0 log with a UEFI variable event.
    ///
    /// The log contains:
    /// 1. A SpecID header (SHA-256).
    /// 2. An `EV_EFI_VARIABLE_DRIVER_CONFIG` event for the EFI "SecureBoot"
    ///    variable (GUID all-zeros for simplicity, value `0x01`).
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::{TcgLogParser, EventType};
    ///
    /// let raw = tcglog_parser::tests::tcg2_log_with_efi_variable();
    /// let log = TcgLogParser::new().parse(&raw).unwrap();
    ///
    /// assert_eq!(log.events.len(), 1);
    /// assert_eq!(log.events[0].event_type, EventType::EfiVariableDriverConfig);
    /// let data = &log.events[0].event_data;
    /// assert_eq!(data["unicode_name"], "SecureBoot");
    /// ```
    pub fn tcg2_log_with_efi_variable() -> Vec<u8> {
        let spec_id_data = spec_id_bytes(&[(0x000B, 32)]);

        let mut log = first_event_bytes(&spec_id_data);

        // Build UEFI_VARIABLE_DATA for "SecureBoot" with value 0x01.
        let name_utf16: Vec<u8> = "SecureBoot"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let var_data = vec![0x01u8];

        let mut ev_data = Vec::new();
        ev_data.extend_from_slice(&[0u8; 16]); // GUID (zeros)
        ev_data.extend_from_slice(&(10u64).to_le_bytes()); // name len (10 chars)
        ev_data.extend_from_slice(&(1u64).to_le_bytes()); // data len (1 byte)
        ev_data.extend_from_slice(&name_utf16);
        ev_data.extend_from_slice(&var_data);

        append_tcg2_event(
            &mut log,
            0,          // pcr_index
            0x80000001, // EV_EFI_VARIABLE_DRIVER_CONFIG
            &[(0x000B, 32)],
            &ev_data,
        );

        log
    }

    /// Builds a TCG 2.0 log with a firmware blob event.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::{TcgLogParser, EventType};
    ///
    /// let raw = tcglog_parser::tests::tcg2_log_with_firmware_blob();
    /// let log = TcgLogParser::new().parse(&raw).unwrap();
    ///
    /// assert_eq!(log.events.len(), 1);
    /// assert_eq!(log.events[0].event_type, EventType::EfiFirmwareBlob);
    /// assert_eq!(log.events[0].event_data["blob_base"], 0xFF000000u64);
    /// ```
    pub fn tcg2_log_with_firmware_blob() -> Vec<u8> {
        let spec_id_data = spec_id_bytes(&[(0x000B, 32)]);
        let mut log = first_event_bytes(&spec_id_data);

        let mut ev_data = Vec::new();
        ev_data.extend_from_slice(&0xFF000000u64.to_le_bytes()); // base
        ev_data.extend_from_slice(&0x100000u64.to_le_bytes()); // length

        append_tcg2_event(&mut log, 0, 0x80000008, &[(0x000B, 32)], &ev_data);
        log
    }

    /// Builds a TCG 2.0 log with the `StartupLocality` event set to a
    /// specific locality.
    ///
    /// Use this to test the two PCR 0 initialisation cases defined by
    /// TCG PFP §3.3.2:
    ///
    /// | `locality` | PCR 0 initial value |
    /// |---|---|
    /// | 0 | all `0x00` |
    /// | 3 or 4 (H-CRTM) | all `0xFF` |
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::TcgLogParser;
    ///
    /// // Locality 0: PCR 0 starts at zeros.
    /// let log0 = TcgLogParser::new()
    ///     .parse(&tcglog_parser::tests::tcg2_log_with_locality(0))
    ///     .unwrap();
    /// assert_eq!(log0.pcr_tables[0].pcrs[&0], "0".repeat(64));
    ///
    /// // Locality 3 (H-CRTM): PCR 0 starts at all 0xFF.
    /// let log3 = TcgLogParser::new()
    ///     .parse(&tcglog_parser::tests::tcg2_log_with_locality(3))
    ///     .unwrap();
    /// assert_eq!(log3.pcr_tables[0].pcrs[&0], "ff".repeat(32));
    ///
    /// // Locality 4 (H-CRTM variant): same as locality 3.
    /// let log4 = TcgLogParser::new()
    ///     .parse(&tcglog_parser::tests::tcg2_log_with_locality(4))
    ///     .unwrap();
    /// assert_eq!(log4.pcr_tables[0].pcrs[&0], "ff".repeat(32));
    /// ```
    pub fn tcg2_log_with_locality(locality: u8) -> Vec<u8> {
        let spec_id_data = spec_id_bytes(&[(0x000B, 32)]);
        let mut log = first_event_bytes(&spec_id_data);

        // StartupLocality EV_NO_ACTION event.
        let mut startup_data = Vec::new();
        startup_data.extend_from_slice(b"StartupLocality\0");
        startup_data.push(locality);

        log.extend_from_slice(&0u32.to_le_bytes()); // pcr_index
        log.extend_from_slice(&3u32.to_le_bytes()); // EV_NO_ACTION
        log.extend_from_slice(&1u32.to_le_bytes()); // digest_count
        log.extend_from_slice(&0x000Bu16.to_le_bytes()); // SHA-256 alg id
        log.extend_from_slice(&[0u8; 32]); // digest (zeros — EV_NO_ACTION)
        log.extend_from_slice(&(startup_data.len() as u32).to_le_bytes());
        log.extend_from_slice(&startup_data);

        log
    }

    // ── Internal helpers ───────────────────────────────────────────────────────

    pub(crate) fn spec_id_bytes(algorithms: &[(u16, u16)]) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(b"Spec ID Event03\0");
        d.extend_from_slice(&0u32.to_le_bytes());
        d.push(0);
        d.push(2);
        d.push(0);
        d.push(8);
        d.extend_from_slice(&(algorithms.len() as u32).to_le_bytes());
        for &(id, sz) in algorithms {
            d.extend_from_slice(&id.to_le_bytes());
            d.extend_from_slice(&sz.to_le_bytes());
        }
        d.push(0);
        d
    }

    pub(crate) fn first_event_bytes(spec_id_data: &[u8]) -> Vec<u8> {
        let mut log = Vec::new();
        log.extend_from_slice(&0u32.to_le_bytes());
        log.extend_from_slice(&3u32.to_le_bytes()); // EV_NO_ACTION
        log.extend_from_slice(&[0u8; 20]);
        log.extend_from_slice(&(spec_id_data.len() as u32).to_le_bytes());
        log.extend_from_slice(spec_id_data);
        log
    }

    pub(crate) fn append_tcg2_event(
        log: &mut Vec<u8>,
        pcr_index: u32,
        event_type: u32,
        algorithms: &[(u16, u16)],
        event_data: &[u8],
    ) {
        log.extend_from_slice(&pcr_index.to_le_bytes());
        log.extend_from_slice(&event_type.to_le_bytes());
        log.extend_from_slice(&(algorithms.len() as u32).to_le_bytes());
        for &(alg_id, digest_size) in algorithms {
            log.extend_from_slice(&alg_id.to_le_bytes());
            log.extend_from_slice(&vec![0u8; digest_size as usize]);
        }
        log.extend_from_slice(&(event_data.len() as u32).to_le_bytes());
        log.extend_from_slice(event_data);
    }
}
