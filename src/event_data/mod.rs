//! Parsed event-data structures for known TCG event types.
//!
//! Each structure corresponds to the `Event` field of a [`TcgPcrEvent`](crate::TcgPcrEvent)
//! or [`TcgPcrEvent2`](crate::TcgPcrEvent2) entry.  The library automatically
//! selects the correct parser based on the event type; callers typically do not
//! need to use these types directly.

use crate::error::{Cursor, ParseError};
use crate::types::{Guid, to_hex};
use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────────────────────────────────────
// SpecID event (TCG 2.0 log header)
// ──────────────────────────────────────────────────────────────────────────────

/// Expected signature bytes in the SpecID event data.
const SPEC_ID_SIGNATURE: &[u8; 16] = b"Spec ID Event03\0";

/// A single algorithm–digest-size pair from the [`SpecIdEvent`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlgorithmSize {
    /// The TPM algorithm identifier (e.g. `0x000B` for SHA-256).
    pub algorithm_id: u16,
    /// The digest size in bytes for this algorithm.
    pub digest_size: u16,
}

impl AlgorithmSize {
    /// Parse an `AlgorithmSize` from a cursor.
    pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Self, ParseError> {
        Ok(Self {
            algorithm_id: cursor.read_u16_le()?,
            digest_size: cursor.read_u16_le()?,
        })
    }
}

/// The SpecID event structure, found in the first event of a TCG 2.0 log.
///
/// This is the `TCG_EfiSpecIDEvent` structure defined in the TCG PC Client
/// Platform Firmware Profile Specification §10.2.
///
/// It describes the hash algorithms used by the crypto-agile event log that
/// follows, and provides version information about the log format.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpecIdEvent {
    /// ASCII signature — always `"Spec ID Event03\0"`.
    pub signature: String,
    /// Platform class (desktop = 0, server = 1, …).
    pub platform_class: u32,
    /// Minor version of the TCG specification (e.g. `0` for 1.00).
    pub spec_version_minor: u8,
    /// Major version of the TCG specification (e.g. `2` for 2.00).
    pub spec_version_major: u8,
    /// Errata level of the specification.
    pub spec_errata: u8,
    /// Size of `UINTN` in bytes on the platform (4 or 8).
    pub uintn_size: u8,
    /// Algorithms present in the crypto-agile log.
    pub algorithms: Vec<AlgorithmSize>,
    /// Vendor-defined information bytes (may be empty).
    pub vendor_info: String,
}

impl SpecIdEvent {
    /// Parse a [`SpecIdEvent`] from raw event-data bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidSpecIdSignature`] if the first 16 bytes do
    /// not match `"Spec ID Event03\0"`.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::event_data::SpecIdEvent;
    ///
    /// // Minimal valid SpecID event data (SHA-256 only, no vendor info).
    /// let mut data = Vec::new();
    /// data.extend_from_slice(b"Spec ID Event03\0"); // signature
    /// data.extend_from_slice(&0u32.to_le_bytes());  // platform_class
    /// data.push(0);  // minor
    /// data.push(2);  // major
    /// data.push(0);  // errata
    /// data.push(8);  // uintn_size
    /// data.extend_from_slice(&1u32.to_le_bytes());  // num_algorithms
    /// data.extend_from_slice(&0x000Bu16.to_le_bytes()); // SHA-256 id
    /// data.extend_from_slice(&32u16.to_le_bytes());      // digest size
    /// data.push(0);  // vendor_info_size
    ///
    /// let event = SpecIdEvent::parse(&data).unwrap();
    /// assert_eq!(event.spec_version_major, 2);
    /// assert_eq!(event.algorithms.len(), 1);
    /// assert_eq!(event.algorithms[0].algorithm_id, 0x000B);
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        let mut c = Cursor::new(data);

        let sig_bytes = c.read_bytes(16)?;
        if sig_bytes != SPEC_ID_SIGNATURE {
            return Err(ParseError::InvalidSpecIdSignature {
                found: sig_bytes.to_vec(),
            });
        }
        let signature = "Spec ID Event03".to_string();

        let platform_class = c.read_u32_le()?;
        let spec_version_minor = c.read_u8()?;
        let spec_version_major = c.read_u8()?;
        let spec_errata = c.read_u8()?;
        let uintn_size = c.read_u8()?;
        let num_algorithms = c.read_u32_le()?;

        let mut algorithms = Vec::with_capacity(num_algorithms as usize);
        for _ in 0..num_algorithms {
            algorithms.push(AlgorithmSize::parse(&mut c)?);
        }

        let vendor_info_size = c.read_u8()? as usize;
        let vendor_info_bytes = c.read_bytes(vendor_info_size)?;
        let vendor_info = to_hex(vendor_info_bytes);

        Ok(Self {
            signature,
            platform_class,
            spec_version_minor,
            spec_version_major,
            spec_errata,
            uintn_size,
            algorithms,
            vendor_info,
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// UEFI variable data  (EV_EFI_VARIABLE_*)
// ──────────────────────────────────────────────────────────────────────────────

/// Event data for EFI variable events
/// (`EV_EFI_VARIABLE_DRIVER_CONFIG`, `EV_EFI_VARIABLE_BOOT`,
/// `EV_EFI_VARIABLE_AUTHORITY`).
///
/// Corresponds to the `UEFI_VARIABLE_DATA` structure in the TCG spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UefiVariableData {
    /// GUID of the UEFI variable namespace.
    pub variable_name: Guid,
    /// Name of the variable (UTF-16LE decoded to a Rust `String`).
    pub unicode_name: String,
    /// Raw variable data, hex-encoded.
    pub variable_data: String,
}

impl UefiVariableData {
    /// Parse a [`UefiVariableData`] from raw event-data bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::event_data::UefiVariableData;
    ///
    /// // Build a minimal UEFI_VARIABLE_DATA for variable "SB" with no data.
    /// let mut data = Vec::new();
    /// data.extend_from_slice(&[0u8; 16]); // GUID (all zeros)
    /// data.extend_from_slice(&2u64.to_le_bytes()); // unicode_name_length = 2 chars
    /// data.extend_from_slice(&0u64.to_le_bytes()); // variable_data_length = 0
    /// // "SB" in UTF-16LE
    /// data.extend_from_slice(&[b'S', 0, b'B', 0]);
    /// // no variable data
    ///
    /// let ev = UefiVariableData::parse(&data).unwrap();
    /// assert_eq!(ev.unicode_name, "SB");
    /// assert_eq!(ev.variable_data, "");
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        let mut c = Cursor::new(data);

        let guid_bytes: [u8; 16] = c.read_bytes(16)?.try_into().unwrap();
        let variable_name = Guid::from_bytes(guid_bytes);

        let unicode_name_length = c.read_u64_le()? as usize;
        let variable_data_length = c.read_u64_le()? as usize;

        // Read UTF-16LE encoded variable name
        let name_byte_count = unicode_name_length * 2;
        let name_bytes = c.read_bytes(name_byte_count)?;
        let name_u16: Vec<u16> = name_bytes
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        let unicode_name = String::from_utf16(&name_u16).map_err(|_| {
            ParseError::invalid_string(c.position(), "invalid UTF-16 variable name")
        })?;

        let var_data = c.read_bytes(variable_data_length)?;
        let variable_data = to_hex(var_data);

        Ok(Self {
            variable_name,
            unicode_name,
            variable_data,
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// UEFI image load event  (EV_EFI_BOOT_SERVICES_APPLICATION etc.)
// ──────────────────────────────────────────────────────────────────────────────

/// Event data for EFI image load events
/// (`EV_EFI_BOOT_SERVICES_APPLICATION`, `EV_EFI_BOOT_SERVICES_DRIVER`,
/// `EV_EFI_RUNTIME_SERVICES_DRIVER`).
///
/// Corresponds to the `UEFI_IMAGE_LOAD_EVENT` structure in the TCG spec.
/// Note that `LengthOfImage`, `LinkTimeAddress`, and `LengthOfDevicePath`
/// are `UINTN`-sized fields whose width (4 or 8 bytes) is determined by
/// the [`SpecIdEvent::uintn_size`](SpecIdEvent::uintn_size) field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UefiImageLoadEvent {
    /// Physical address of the image in memory.
    pub image_location_in_memory: u64,
    /// Length of the image in bytes.
    pub length_of_image: u64,
    /// Link-time base address of the image.
    pub link_time_address: u64,
    /// Device path bytes, hex-encoded.
    pub device_path: String,
}

impl UefiImageLoadEvent {
    /// Parse a [`UefiImageLoadEvent`] from raw event-data bytes.
    ///
    /// `uintn_size` must be either `4` or `8`, sourced from the log's
    /// [`SpecIdEvent`].
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::event_data::UefiImageLoadEvent;
    ///
    /// let mut data = Vec::new();
    /// data.extend_from_slice(&0x1000u64.to_le_bytes()); // image_location
    /// data.extend_from_slice(&0x2000u64.to_le_bytes()); // length_of_image (uintn=8)
    /// data.extend_from_slice(&0u64.to_le_bytes());      // link_time_address
    /// data.extend_from_slice(&4u64.to_le_bytes());      // length_of_device_path
    /// data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // device path
    ///
    /// let ev = UefiImageLoadEvent::parse(&data, 8).unwrap();
    /// assert_eq!(ev.image_location_in_memory, 0x1000);
    /// assert_eq!(ev.length_of_image, 0x2000);
    /// assert_eq!(ev.device_path, "aabbccdd");
    /// ```
    pub fn parse(data: &[u8], uintn_size: u8) -> Result<Self, ParseError> {
        let mut c = Cursor::new(data);

        let image_location_in_memory = c.read_u64_le()?;

        let length_of_image = read_uintn(&mut c, uintn_size)?;
        let link_time_address = read_uintn(&mut c, uintn_size)?;
        let length_of_device_path = read_uintn(&mut c, uintn_size)? as usize;

        let dp_bytes = c.read_bytes(length_of_device_path)?;
        let device_path = to_hex(dp_bytes);

        Ok(Self {
            image_location_in_memory,
            length_of_image,
            link_time_address,
            device_path,
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// UEFI platform firmware blob  (EV_EFI_PLATFORM_FIRMWARE_BLOB)
// ──────────────────────────────────────────────────────────────────────────────

/// Event data for `EV_EFI_PLATFORM_FIRMWARE_BLOB`.
///
/// Corresponds to `UEFI_PLATFORM_FIRMWARE_BLOB` in the TCG spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UefiFirmwareBlob {
    /// Physical address of the firmware blob.
    pub blob_base: u64,
    /// Length of the firmware blob in bytes.
    pub blob_length: u64,
}

impl UefiFirmwareBlob {
    /// Parse a [`UefiFirmwareBlob`] from raw event-data bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::event_data::UefiFirmwareBlob;
    ///
    /// let mut data = Vec::new();
    /// data.extend_from_slice(&0xFF000000u64.to_le_bytes()); // base
    /// data.extend_from_slice(&0x100000u64.to_le_bytes());   // length
    ///
    /// let blob = UefiFirmwareBlob::parse(&data).unwrap();
    /// assert_eq!(blob.blob_base, 0xFF000000);
    /// assert_eq!(blob.blob_length, 0x100000);
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        let mut c = Cursor::new(data);
        Ok(Self {
            blob_base: c.read_u64_le()?,
            blob_length: c.read_u64_le()?,
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// UEFI platform firmware blob v2  (EV_EFI_PLATFORM_FIRMWARE_BLOB2)
// ──────────────────────────────────────────────────────────────────────────────

/// Event data for `EV_EFI_PLATFORM_FIRMWARE_BLOB2`.
///
/// Extends [`UefiFirmwareBlob`] with a human-readable description string.
/// Corresponds to `UEFI_PLATFORM_FIRMWARE_BLOB2` in the TCG spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UefiFirmwareBlob2 {
    /// Human-readable ASCII description of the firmware blob.
    pub blob_description: String,
    /// Physical address of the firmware blob.
    pub blob_base: u64,
    /// Length of the firmware blob in bytes.
    pub blob_length: u64,
}

impl UefiFirmwareBlob2 {
    /// Parse a [`UefiFirmwareBlob2`] from raw event-data bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::event_data::UefiFirmwareBlob2;
    ///
    /// let mut data = Vec::new();
    /// let desc = b"Firmware Volume";
    /// data.push(desc.len() as u8);         // description size
    /// data.extend_from_slice(desc);         // description
    /// data.extend_from_slice(&0xFF000000u64.to_le_bytes()); // base
    /// data.extend_from_slice(&0x80000u64.to_le_bytes());    // length
    ///
    /// let blob = UefiFirmwareBlob2::parse(&data).unwrap();
    /// assert_eq!(blob.blob_description, "Firmware Volume");
    /// assert_eq!(blob.blob_base, 0xFF000000);
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        let mut c = Cursor::new(data);
        let desc_size = c.read_u8()? as usize;
        let desc_bytes = c.read_bytes(desc_size)?;
        let blob_description = String::from_utf8_lossy(desc_bytes).into_owned();
        Ok(Self {
            blob_description,
            blob_base: c.read_u64_le()?,
            blob_length: c.read_u64_le()?,
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// UEFI handoff tables  (EV_EFI_HANDOFF_TABLES)
// ──────────────────────────────────────────────────────────────────────────────

/// A single `EFI_CONFIGURATION_TABLE` entry with its vendor GUID and
/// table pointer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EfiConfigurationTable {
    /// GUID identifying the configuration table type.
    pub vendor_guid: Guid,
    /// Vendor table pointer (physical address).
    pub vendor_table: u64,
}

/// Event data for `EV_EFI_HANDOFF_TABLES`.
///
/// Corresponds to `UEFI_HANDOFF_TABLE_POINTERS` in the TCG spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UefiHandoffTables {
    /// The list of EFI configuration tables handed off.
    pub tables: Vec<EfiConfigurationTable>,
}

impl UefiHandoffTables {
    /// Parse a [`UefiHandoffTables`] from raw event-data bytes.
    ///
    /// `uintn_size` must be either `4` or `8`, sourced from the log's
    /// [`SpecIdEvent`].
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::event_data::UefiHandoffTables;
    ///
    /// let mut data = Vec::new();
    /// data.extend_from_slice(&1u64.to_le_bytes()); // NumberOfTables (uintn=8)
    /// data.extend_from_slice(&[1u8; 16]);           // vendor GUID
    /// data.extend_from_slice(&0xABCDu64.to_le_bytes()); // vendor table ptr
    ///
    /// let tables = UefiHandoffTables::parse(&data, 8).unwrap();
    /// assert_eq!(tables.tables.len(), 1);
    /// ```
    pub fn parse(data: &[u8], uintn_size: u8) -> Result<Self, ParseError> {
        let mut c = Cursor::new(data);
        let num_tables = read_uintn(&mut c, uintn_size)? as usize;
        let mut tables = Vec::with_capacity(num_tables);
        for _ in 0..num_tables {
            let guid_bytes: [u8; 16] = c.read_bytes(16)?.try_into().unwrap();
            let vendor_guid = Guid::from_bytes(guid_bytes);
            let vendor_table = read_uintn(&mut c, uintn_size)?;
            tables.push(EfiConfigurationTable {
                vendor_guid,
                vendor_table,
            });
        }
        Ok(Self { tables })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// UEFI handoff tables v2  (EV_EFI_HANDOFF_TABLES2)
// ──────────────────────────────────────────────────────────────────────────────

/// Event data for `EV_EFI_HANDOFF_TABLES2`.
///
/// Extends [`UefiHandoffTables`] with a human-readable description string.
/// Corresponds to `UEFI_HANDOFF_TABLE_POINTERS2` in the TCG spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UefiHandoffTables2 {
    /// Human-readable ASCII description of the handoff tables.
    pub table_description: String,
    /// The list of EFI configuration tables handed off.
    pub tables: Vec<EfiConfigurationTable>,
}

impl UefiHandoffTables2 {
    /// Parse a [`UefiHandoffTables2`] from raw event-data bytes.
    ///
    /// `uintn_size` must be either `4` or `8`, sourced from the log's
    /// [`SpecIdEvent`].
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::event_data::UefiHandoffTables2;
    ///
    /// let mut data = Vec::new();
    /// let desc = b"ACPI Tables";
    /// data.push(desc.len() as u8);                       // description size
    /// data.extend_from_slice(desc);                       // description
    /// data.extend_from_slice(&1u64.to_le_bytes());        // NumberOfTables (uintn=8)
    /// data.extend_from_slice(&[1u8; 16]);                 // vendor GUID
    /// data.extend_from_slice(&0xABCDu64.to_le_bytes());   // vendor table ptr
    ///
    /// let tables = UefiHandoffTables2::parse(&data, 8).unwrap();
    /// assert_eq!(tables.table_description, "ACPI Tables");
    /// assert_eq!(tables.tables.len(), 1);
    /// ```
    pub fn parse(data: &[u8], uintn_size: u8) -> Result<Self, ParseError> {
        let mut c = Cursor::new(data);
        let desc_size = c.read_u8()? as usize;
        let desc_bytes = c.read_bytes(desc_size)?;
        let table_description = String::from_utf8_lossy(desc_bytes).into_owned();
        let num_tables = read_uintn(&mut c, uintn_size)? as usize;
        let mut tables = Vec::with_capacity(num_tables);
        for _ in 0..num_tables {
            let guid_bytes: [u8; 16] = c.read_bytes(16)?.try_into().unwrap();
            let vendor_guid = Guid::from_bytes(guid_bytes);
            let vendor_table = read_uintn(&mut c, uintn_size)?;
            tables.push(EfiConfigurationTable {
                vendor_guid,
                vendor_table,
            });
        }
        Ok(Self {
            table_description,
            tables,
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Startup locality event  (EV_NO_ACTION with "StartupLocality\0" signature)
// ──────────────────────────────────────────────────────────────────────────────

/// Expected signature for the StartupLocality `EV_NO_ACTION` sub-type.
const STARTUP_LOCALITY_SIGNATURE: &[u8; 16] = b"StartupLocality\0";

/// Event data for the `StartupLocality` sub-type of `EV_NO_ACTION`.
///
/// This optional event records the TPM's startup locality.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StartupLocality {
    /// The startup locality (typically 0 or 3).
    pub startup_locality: u8,
}

impl StartupLocality {
    /// Parse a [`StartupLocality`] event from raw event-data bytes.
    ///
    /// Returns `None` if the signature does not match (i.e. this is a
    /// different kind of `EV_NO_ACTION` event).
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::event_data::StartupLocality;
    ///
    /// let mut data = Vec::new();
    /// data.extend_from_slice(b"StartupLocality\0");
    /// data.push(3); // locality
    ///
    /// let ev = StartupLocality::try_parse(&data).unwrap().unwrap();
    /// assert_eq!(ev.startup_locality, 3);
    /// ```
    pub fn try_parse(data: &[u8]) -> Result<Option<Self>, ParseError> {
        if data.len() < 17 {
            return Ok(None);
        }
        if &data[..16] != STARTUP_LOCALITY_SIGNATURE {
            return Ok(None);
        }
        let mut c = Cursor::new(&data[16..]);
        Ok(Some(Self {
            startup_locality: c.read_u8()?,
        }))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Read a `UINTN` value (4 or 8 bytes, little-endian) from a cursor.
pub(crate) fn read_uintn(c: &mut Cursor<'_>, uintn_size: u8) -> Result<u64, ParseError> {
    match uintn_size {
        4 => Ok(c.read_u32_le()? as u64),
        8 => c.read_u64_le(),
        _ => Err(ParseError::UnsupportedValue {
            field: "uintn_size",
            value: uintn_size as u64,
            offset: c.position(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_spec_id_event(algorithms: &[(u16, u16)], vendor_info: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"Spec ID Event03\0");
        data.extend_from_slice(&0u32.to_le_bytes()); // platform_class
        data.push(0); // minor
        data.push(2); // major
        data.push(0); // errata
        data.push(8); // uintn_size
        data.extend_from_slice(&(algorithms.len() as u32).to_le_bytes());
        for &(alg_id, digest_size) in algorithms {
            data.extend_from_slice(&alg_id.to_le_bytes());
            data.extend_from_slice(&digest_size.to_le_bytes());
        }
        data.push(vendor_info.len() as u8);
        data.extend_from_slice(vendor_info);
        data
    }

    #[test]
    fn spec_id_event_parse_sha256() {
        let data = build_spec_id_event(&[(0x000B, 32)], &[]);
        let ev = SpecIdEvent::parse(&data).unwrap();
        assert_eq!(ev.spec_version_major, 2);
        assert_eq!(ev.spec_version_minor, 0);
        assert_eq!(ev.algorithms.len(), 1);
        assert_eq!(ev.algorithms[0].algorithm_id, 0x000B);
        assert_eq!(ev.algorithms[0].digest_size, 32);
        assert_eq!(ev.vendor_info, "");
    }

    #[test]
    fn spec_id_event_parse_multiple_algorithms() {
        let data = build_spec_id_event(&[(0x0004, 20), (0x000B, 32)], &[0xAB]);
        let ev = SpecIdEvent::parse(&data).unwrap();
        assert_eq!(ev.algorithms.len(), 2);
        assert_eq!(ev.vendor_info, "ab");
    }

    #[test]
    fn spec_id_event_bad_signature() {
        let mut data = build_spec_id_event(&[(0x000B, 32)], &[]);
        data[0] = 0xFF; // corrupt the signature
        assert!(matches!(
            SpecIdEvent::parse(&data),
            Err(ParseError::InvalidSpecIdSignature { .. })
        ));
    }

    #[test]
    fn uefi_variable_data_parse() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0u8; 16]); // GUID
        data.extend_from_slice(&2u64.to_le_bytes()); // name length (2 chars)
        data.extend_from_slice(&3u64.to_le_bytes()); // data length (3 bytes)
        data.extend_from_slice(&[b'O', 0, b'K', 0]); // "OK" in UTF-16LE
        data.extend_from_slice(&[0xDE, 0xAD, 0xBE]); // variable data

        let ev = UefiVariableData::parse(&data).unwrap();
        assert_eq!(ev.unicode_name, "OK");
        assert_eq!(ev.variable_data, "deadbe");
    }

    #[test]
    fn uefi_image_load_event_parse_uintn8() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000u64.to_le_bytes());
        data.extend_from_slice(&0x2000u64.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&2u64.to_le_bytes()); // dp length
        data.extend_from_slice(&[0xAB, 0xCD]);

        let ev = UefiImageLoadEvent::parse(&data, 8).unwrap();
        assert_eq!(ev.image_location_in_memory, 0x1000);
        assert_eq!(ev.length_of_image, 0x2000);
        assert_eq!(ev.device_path, "abcd");
    }

    #[test]
    fn uefi_image_load_event_parse_uintn4() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000u64.to_le_bytes()); // always u64
        data.extend_from_slice(&0x2000u32.to_le_bytes()); // uintn=4
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes()); // dp length = 0

        let ev = UefiImageLoadEvent::parse(&data, 4).unwrap();
        assert_eq!(ev.length_of_image, 0x2000);
        assert_eq!(ev.device_path, "");
    }

    #[test]
    fn uefi_firmware_blob_parse() {
        let mut data = Vec::new();
        data.extend_from_slice(&0xFF000000u64.to_le_bytes());
        data.extend_from_slice(&0x100000u64.to_le_bytes());

        let blob = UefiFirmwareBlob::parse(&data).unwrap();
        assert_eq!(blob.blob_base, 0xFF000000);
        assert_eq!(blob.blob_length, 0x100000);
    }

    #[test]
    fn uefi_firmware_blob2_parse() {
        let mut data = Vec::new();
        let desc = b"FvMain";
        data.push(desc.len() as u8);
        data.extend_from_slice(desc);
        data.extend_from_slice(&0xFE000000u64.to_le_bytes());
        data.extend_from_slice(&0x200000u64.to_le_bytes());

        let blob = UefiFirmwareBlob2::parse(&data).unwrap();
        assert_eq!(blob.blob_description, "FvMain");
        assert_eq!(blob.blob_base, 0xFE000000);
    }

    #[test]
    fn startup_locality_match() {
        let mut data = Vec::new();
        data.extend_from_slice(b"StartupLocality\0");
        data.push(3);

        let ev = StartupLocality::try_parse(&data).unwrap().unwrap();
        assert_eq!(ev.startup_locality, 3);
    }

    #[test]
    fn startup_locality_no_match() {
        let data = b"Spec ID Event03\0\x01";
        let result = StartupLocality::try_parse(data).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn uefi_handoff_tables_parse() {
        let mut data = Vec::new();
        data.extend_from_slice(&1u64.to_le_bytes()); // 1 table, uintn=8
        data.extend_from_slice(&[2u8; 16]); // GUID
        data.extend_from_slice(&0xBEEFu64.to_le_bytes()); // pointer

        let tables = UefiHandoffTables::parse(&data, 8).unwrap();
        assert_eq!(tables.tables.len(), 1);
        assert_eq!(tables.tables[0].vendor_table, 0xBEEF);
    }

    #[test]
    fn uefi_handoff_tables2_parse() {
        let mut data = Vec::new();
        let desc = b"ACPI Tables";
        data.push(desc.len() as u8);
        data.extend_from_slice(desc);
        data.extend_from_slice(&1u64.to_le_bytes()); // 1 table, uintn=8
        data.extend_from_slice(&[3u8; 16]); // GUID
        data.extend_from_slice(&0xCAFEu64.to_le_bytes()); // pointer

        let tables = UefiHandoffTables2::parse(&data, 8).unwrap();
        assert_eq!(tables.table_description, "ACPI Tables");
        assert_eq!(tables.tables.len(), 1);
        assert_eq!(tables.tables[0].vendor_table, 0xCAFE);
    }
}
