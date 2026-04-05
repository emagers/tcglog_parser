/// Identifies a TPM hash algorithm, as defined in the TCG Algorithm Registry.
///
/// The numeric values correspond to `TPM_ALG_ID` constants in the TCG spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(into = "String", from = "String")]
pub enum HashAlgorithmId {
    /// SHA-1 (20-byte digest). Algorithm ID `0x0004`.
    Sha1,
    /// SHA-256 (32-byte digest). Algorithm ID `0x000B`.
    Sha256,
    /// SHA-384 (48-byte digest). Algorithm ID `0x000C`.
    Sha384,
    /// SHA-512 (64-byte digest). Algorithm ID `0x000D`.
    Sha512,
    /// SM3-256 (32-byte digest). Algorithm ID `0x0012`.
    Sm3_256,
    /// SHA3-256 (32-byte digest). Algorithm ID `0x0027`.
    Sha3_256,
    /// SHA3-384 (48-byte digest). Algorithm ID `0x0028`.
    Sha3_384,
    /// SHA3-512 (64-byte digest). Algorithm ID `0x0029`.
    Sha3_512,
    /// An algorithm ID not recognised by this library.
    Unknown(u16),
}

impl HashAlgorithmId {
    /// Creates a [`HashAlgorithmId`] from its numeric `TPM_ALG_ID` value.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::HashAlgorithmId;
    ///
    /// assert_eq!(HashAlgorithmId::from_id(0x0004), HashAlgorithmId::Sha1);
    /// assert_eq!(HashAlgorithmId::from_id(0x000B), HashAlgorithmId::Sha256);
    /// assert_eq!(HashAlgorithmId::from_id(0x9999), HashAlgorithmId::Unknown(0x9999));
    /// ```
    pub fn from_id(id: u16) -> Self {
        match id {
            0x0004 => Self::Sha1,
            0x000B => Self::Sha256,
            0x000C => Self::Sha384,
            0x000D => Self::Sha512,
            0x0012 => Self::Sm3_256,
            0x0027 => Self::Sha3_256,
            0x0028 => Self::Sha3_384,
            0x0029 => Self::Sha3_512,
            other => Self::Unknown(other),
        }
    }

    /// Returns the numeric `TPM_ALG_ID` value for this algorithm.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::HashAlgorithmId;
    ///
    /// assert_eq!(HashAlgorithmId::Sha256.to_id(), 0x000B);
    /// assert_eq!(HashAlgorithmId::Unknown(0xABCD).to_id(), 0xABCD);
    /// ```
    pub fn to_id(self) -> u16 {
        match self {
            Self::Sha1 => 0x0004,
            Self::Sha256 => 0x000B,
            Self::Sha384 => 0x000C,
            Self::Sha512 => 0x000D,
            Self::Sm3_256 => 0x0012,
            Self::Sha3_256 => 0x0027,
            Self::Sha3_384 => 0x0028,
            Self::Sha3_512 => 0x0029,
            Self::Unknown(id) => id,
        }
    }

    /// Returns the expected digest size in bytes for this algorithm, if known.
    ///
    /// Returns `None` for [`HashAlgorithmId::Unknown`] variants.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::HashAlgorithmId;
    ///
    /// assert_eq!(HashAlgorithmId::Sha1.digest_size(), Some(20));
    /// assert_eq!(HashAlgorithmId::Sha256.digest_size(), Some(32));
    /// assert_eq!(HashAlgorithmId::Unknown(0x9999).digest_size(), None);
    /// ```
    pub fn digest_size(self) -> Option<usize> {
        match self {
            Self::Sha1 => Some(20),
            Self::Sha256 => Some(32),
            Self::Sha384 => Some(48),
            Self::Sha512 => Some(64),
            Self::Sm3_256 => Some(32),
            Self::Sha3_256 => Some(32),
            Self::Sha3_384 => Some(48),
            Self::Sha3_512 => Some(64),
            Self::Unknown(_) => None,
        }
    }

    /// Returns a human-readable name for this algorithm.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::HashAlgorithmId;
    ///
    /// assert_eq!(HashAlgorithmId::Sha256.name(), "sha256");
    /// assert_eq!(HashAlgorithmId::Unknown(0x1234).name(), "unknown(0x1234)");
    /// ```
    pub fn name(self) -> String {
        match self {
            Self::Sha1 => "sha1".to_string(),
            Self::Sha256 => "sha256".to_string(),
            Self::Sha384 => "sha384".to_string(),
            Self::Sha512 => "sha512".to_string(),
            Self::Sm3_256 => "sm3_256".to_string(),
            Self::Sha3_256 => "sha3_256".to_string(),
            Self::Sha3_384 => "sha3_384".to_string(),
            Self::Sha3_512 => "sha3_512".to_string(),
            Self::Unknown(id) => format!("unknown({:#06x})", id),
        }
    }
}

impl From<HashAlgorithmId> for String {
    fn from(id: HashAlgorithmId) -> String {
        id.name()
    }
}

impl From<String> for HashAlgorithmId {
    /// Parses a [`HashAlgorithmId`] from its string name (as produced by
    /// [`HashAlgorithmId::name`]).  Unknown algorithm names in the format
    /// `"unknown(0xXXXX)"` are parsed back into `Unknown(id)`, preserving the
    /// original numeric value.
    fn from(s: String) -> Self {
        match s.as_str() {
            "sha1" => Self::Sha1,
            "sha256" => Self::Sha256,
            "sha384" => Self::Sha384,
            "sha512" => Self::Sha512,
            "sm3_256" => Self::Sm3_256,
            "sha3_256" => Self::Sha3_256,
            "sha3_384" => Self::Sha3_384,
            "sha3_512" => Self::Sha3_512,
            other => {
                // Try to recover the numeric value from "unknown(0xXXXX)".
                parse_unknown_u16(other).map_or(Self::Unknown(0), Self::Unknown)
            }
        }
    }
}

/// TCG event type constants, as defined in the TCG PC Client Platform
/// Firmware Profile Specification.
///
/// Event types `0x00`–`0x12` are from the TCG 1.2 specification.
/// Event types starting with `0x80000000` are UEFI/EFI-specific.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(into = "String", from = "String")]
pub enum EventType {
    /// `EV_PREBOOT_CERT` (0x00000000) – Pre-boot certificate.
    PrebootCert,
    /// `EV_POST_CODE` (0x00000001) – POST code measurement.
    PostCode,
    /// `EV_UNUSED` (0x00000002) – Unused/reserved.
    Unused,
    /// `EV_NO_ACTION` (0x00000003) – Informational; digest must not be extended into PCR.
    NoAction,
    /// `EV_SEPARATOR` (0x00000004) – Marks the end of pre-OS measurements.
    Separator,
    /// `EV_ACTION` (0x00000005) – A specific action was taken.
    Action,
    /// `EV_EVENT_TAG` (0x00000006) – Tagged event.
    EventTag,
    /// `EV_S_CRTM_CONTENTS` (0x00000007) – S-CRTM contents measurement.
    SCrtmContents,
    /// `EV_S_CRTM_VERSION` (0x00000008) – S-CRTM version string.
    SCrtmVersion,
    /// `EV_CPU_MICROCODE` (0x00000009) – CPU microcode measurement.
    CpuMicrocode,
    /// `EV_PLATFORM_CONFIG_FLAGS` (0x0000000A) – Platform configuration flags.
    PlatformConfigFlags,
    /// `EV_TABLE_OF_DEVICES` (0x0000000B) – Table of devices.
    TableOfDevices,
    /// `EV_COMPACT_HASH` (0x0000000C) – Compact hash.
    CompactHash,
    /// `EV_IPL` (0x0000000D) – Initial Program Load measurement.
    Ipl,
    /// `EV_IPL_PARTITION_DATA` (0x0000000E) – IPL partition data.
    IplPartitionData,
    /// `EV_NONHOST_CODE` (0x0000000F) – Non-host code.
    NonhostCode,
    /// `EV_NONHOST_CONFIG` (0x00000010) – Non-host configuration.
    NonhostConfig,
    /// `EV_NONHOST_INFO` (0x00000011) – Non-host info.
    NonhostInfo,
    /// `EV_OMIT_BOOT_DEVICE_EVENTS` (0x00000012) – Omit boot device events.
    OmitBootDeviceEvents,
    /// `EV_POST_CODE2` (0x00000013) – POST code measurement v2.
    PostCode2,
    /// `EV_EFI_EVENT_BASE` (0x80000000) – Base for EFI event types.
    EfiEventBase,
    /// `EV_EFI_VARIABLE_DRIVER_CONFIG` (0x80000001) – EFI variable (driver config).
    EfiVariableDriverConfig,
    /// `EV_EFI_VARIABLE_BOOT` (0x80000002) – EFI boot variable.
    EfiVariableBoot,
    /// `EV_EFI_BOOT_SERVICES_APPLICATION` (0x80000003) – EFI boot services application.
    EfiBootServicesApplication,
    /// `EV_EFI_BOOT_SERVICES_DRIVER` (0x80000004) – EFI boot services driver.
    EfiBootServicesDriver,
    /// `EV_EFI_RUNTIME_SERVICES_DRIVER` (0x80000005) – EFI runtime services driver.
    EfiRuntimeServicesDriver,
    /// `EV_EFI_GPT_EVENT` (0x80000006) – EFI GPT partition table event.
    EfiGptEvent,
    /// `EV_EFI_ACTION` (0x80000007) – EFI action string.
    EfiAction,
    /// `EV_EFI_PLATFORM_FIRMWARE_BLOB` (0x80000008) – EFI platform firmware blob.
    EfiFirmwareBlob,
    /// `EV_EFI_HANDOFF_TABLES` (0x80000009) – EFI handoff tables.
    EfiHandoffTables,
    /// `EV_EFI_PLATFORM_FIRMWARE_BLOB2` (0x8000000A) – EFI platform firmware blob v2.
    EfiFirmwareBlob2,
    /// `EV_EFI_HANDOFF_TABLES2` (0x8000000B) – EFI handoff tables v2.
    EfiHandoffTables2,
    /// `EV_EFI_VARIABLE_BOOT2` (0x8000000C) – EFI boot variable v2.
    EfiVariableBoot2,
    /// `EV_EFI_GPT_EVENT2` (0x8000000D) – EFI GPT partition table event v2.
    EfiGptEvent2,
    /// `EV_EFI_HCRTM_EVENT` (0x80000010) – EFI H-CRTM event.
    EfiHcrtmEvent,
    /// `EV_EFI_VARIABLE_AUTHORITY` (0x800000E0) – EFI variable authority.
    EfiVariableAuthority,
    /// `EV_EFI_SPDM_FIRMWARE_BLOB` (0x800000E1) – EFI SPDM firmware blob.
    EfiSpdmFirmwareBlob,
    /// `EV_EFI_SPDM_FIRMWARE_CONFIG` (0x800000E2) – EFI SPDM firmware config.
    EfiSpdmFirmwareConfig,
    /// `EV_EFI_SPDM_DEVICE_POLICY` (0x800000E3) – EFI SPDM device policy.
    EfiSpdmDevicePolicy,
    /// `EV_EFI_SPDM_DEVICE_AUTHORITY` (0x800000E4) – EFI SPDM device authority.
    EfiSpdmDeviceAuthority,
    /// An event type not recognised by this library.
    Unknown(u32),
}

impl EventType {
    /// Creates an [`EventType`] from its raw `u32` value.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::EventType;
    ///
    /// assert_eq!(EventType::from_value(3), EventType::NoAction);
    /// assert_eq!(EventType::from_value(0x80000001), EventType::EfiVariableDriverConfig);
    /// assert_eq!(EventType::from_value(0xDEAD), EventType::Unknown(0xDEAD));
    /// ```
    pub fn from_value(v: u32) -> Self {
        match v {
            0x00000000 => Self::PrebootCert,
            0x00000001 => Self::PostCode,
            0x00000002 => Self::Unused,
            0x00000003 => Self::NoAction,
            0x00000004 => Self::Separator,
            0x00000005 => Self::Action,
            0x00000006 => Self::EventTag,
            0x00000007 => Self::SCrtmContents,
            0x00000008 => Self::SCrtmVersion,
            0x00000009 => Self::CpuMicrocode,
            0x0000000A => Self::PlatformConfigFlags,
            0x0000000B => Self::TableOfDevices,
            0x0000000C => Self::CompactHash,
            0x0000000D => Self::Ipl,
            0x0000000E => Self::IplPartitionData,
            0x0000000F => Self::NonhostCode,
            0x00000010 => Self::NonhostConfig,
            0x00000011 => Self::NonhostInfo,
            0x00000012 => Self::OmitBootDeviceEvents,
            0x00000013 => Self::PostCode2,
            0x80000000 => Self::EfiEventBase,
            0x80000001 => Self::EfiVariableDriverConfig,
            0x80000002 => Self::EfiVariableBoot,
            0x80000003 => Self::EfiBootServicesApplication,
            0x80000004 => Self::EfiBootServicesDriver,
            0x80000005 => Self::EfiRuntimeServicesDriver,
            0x80000006 => Self::EfiGptEvent,
            0x80000007 => Self::EfiAction,
            0x80000008 => Self::EfiFirmwareBlob,
            0x80000009 => Self::EfiHandoffTables,
            0x8000000A => Self::EfiFirmwareBlob2,
            0x8000000B => Self::EfiHandoffTables2,
            0x8000000C => Self::EfiVariableBoot2,
            0x8000000D => Self::EfiGptEvent2,
            0x80000010 => Self::EfiHcrtmEvent,
            0x800000E0 => Self::EfiVariableAuthority,
            0x800000E1 => Self::EfiSpdmFirmwareBlob,
            0x800000E2 => Self::EfiSpdmFirmwareConfig,
            0x800000E3 => Self::EfiSpdmDevicePolicy,
            0x800000E4 => Self::EfiSpdmDeviceAuthority,
            other => Self::Unknown(other),
        }
    }

    /// Returns the raw `u32` value for this event type.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::EventType;
    ///
    /// assert_eq!(EventType::Separator.to_value(), 4);
    /// assert_eq!(EventType::Unknown(0xFF).to_value(), 0xFF);
    /// ```
    pub fn to_value(self) -> u32 {
        match self {
            Self::PrebootCert => 0x00000000,
            Self::PostCode => 0x00000001,
            Self::Unused => 0x00000002,
            Self::NoAction => 0x00000003,
            Self::Separator => 0x00000004,
            Self::Action => 0x00000005,
            Self::EventTag => 0x00000006,
            Self::SCrtmContents => 0x00000007,
            Self::SCrtmVersion => 0x00000008,
            Self::CpuMicrocode => 0x00000009,
            Self::PlatformConfigFlags => 0x0000000A,
            Self::TableOfDevices => 0x0000000B,
            Self::CompactHash => 0x0000000C,
            Self::Ipl => 0x0000000D,
            Self::IplPartitionData => 0x0000000E,
            Self::NonhostCode => 0x0000000F,
            Self::NonhostConfig => 0x00000010,
            Self::NonhostInfo => 0x00000011,
            Self::OmitBootDeviceEvents => 0x00000012,
            Self::PostCode2 => 0x00000013,
            Self::EfiEventBase => 0x80000000,
            Self::EfiVariableDriverConfig => 0x80000001,
            Self::EfiVariableBoot => 0x80000002,
            Self::EfiBootServicesApplication => 0x80000003,
            Self::EfiBootServicesDriver => 0x80000004,
            Self::EfiRuntimeServicesDriver => 0x80000005,
            Self::EfiGptEvent => 0x80000006,
            Self::EfiAction => 0x80000007,
            Self::EfiFirmwareBlob => 0x80000008,
            Self::EfiHandoffTables => 0x80000009,
            Self::EfiFirmwareBlob2 => 0x8000000A,
            Self::EfiHandoffTables2 => 0x8000000B,
            Self::EfiVariableBoot2 => 0x8000000C,
            Self::EfiGptEvent2 => 0x8000000D,
            Self::EfiHcrtmEvent => 0x80000010,
            Self::EfiVariableAuthority => 0x800000E0,
            Self::EfiSpdmFirmwareBlob => 0x800000E1,
            Self::EfiSpdmFirmwareConfig => 0x800000E2,
            Self::EfiSpdmDevicePolicy => 0x800000E3,
            Self::EfiSpdmDeviceAuthority => 0x800000E4,
            Self::Unknown(v) => v,
        }
    }

    /// Returns a human-readable name for this event type.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::EventType;
    ///
    /// assert_eq!(EventType::NoAction.name(), "EV_NO_ACTION");
    /// assert_eq!(EventType::EfiVariableDriverConfig.name(), "EV_EFI_VARIABLE_DRIVER_CONFIG");
    /// assert_eq!(EventType::Unknown(0xAB).name(), "Unknown(0x000000ab)");
    /// ```
    pub fn name(self) -> String {
        match self {
            Self::PrebootCert => "EV_PREBOOT_CERT".to_string(),
            Self::PostCode => "EV_POST_CODE".to_string(),
            Self::Unused => "EV_UNUSED".to_string(),
            Self::NoAction => "EV_NO_ACTION".to_string(),
            Self::Separator => "EV_SEPARATOR".to_string(),
            Self::Action => "EV_ACTION".to_string(),
            Self::EventTag => "EV_EVENT_TAG".to_string(),
            Self::SCrtmContents => "EV_S_CRTM_CONTENTS".to_string(),
            Self::SCrtmVersion => "EV_S_CRTM_VERSION".to_string(),
            Self::CpuMicrocode => "EV_CPU_MICROCODE".to_string(),
            Self::PlatformConfigFlags => "EV_PLATFORM_CONFIG_FLAGS".to_string(),
            Self::TableOfDevices => "EV_TABLE_OF_DEVICES".to_string(),
            Self::CompactHash => "EV_COMPACT_HASH".to_string(),
            Self::Ipl => "EV_IPL".to_string(),
            Self::IplPartitionData => "EV_IPL_PARTITION_DATA".to_string(),
            Self::NonhostCode => "EV_NONHOST_CODE".to_string(),
            Self::NonhostConfig => "EV_NONHOST_CONFIG".to_string(),
            Self::NonhostInfo => "EV_NONHOST_INFO".to_string(),
            Self::OmitBootDeviceEvents => "EV_OMIT_BOOT_DEVICE_EVENTS".to_string(),
            Self::PostCode2 => "EV_POST_CODE2".to_string(),
            Self::EfiEventBase => "EV_EFI_EVENT_BASE".to_string(),
            Self::EfiVariableDriverConfig => "EV_EFI_VARIABLE_DRIVER_CONFIG".to_string(),
            Self::EfiVariableBoot => "EV_EFI_VARIABLE_BOOT".to_string(),
            Self::EfiBootServicesApplication => "EV_EFI_BOOT_SERVICES_APPLICATION".to_string(),
            Self::EfiBootServicesDriver => "EV_EFI_BOOT_SERVICES_DRIVER".to_string(),
            Self::EfiRuntimeServicesDriver => "EV_EFI_RUNTIME_SERVICES_DRIVER".to_string(),
            Self::EfiGptEvent => "EV_EFI_GPT_EVENT".to_string(),
            Self::EfiAction => "EV_EFI_ACTION".to_string(),
            Self::EfiFirmwareBlob => "EV_EFI_PLATFORM_FIRMWARE_BLOB".to_string(),
            Self::EfiHandoffTables => "EV_EFI_HANDOFF_TABLES".to_string(),
            Self::EfiFirmwareBlob2 => "EV_EFI_PLATFORM_FIRMWARE_BLOB2".to_string(),
            Self::EfiHandoffTables2 => "EV_EFI_HANDOFF_TABLES2".to_string(),
            Self::EfiVariableBoot2 => "EV_EFI_VARIABLE_BOOT2".to_string(),
            Self::EfiGptEvent2 => "EV_EFI_GPT_EVENT2".to_string(),
            Self::EfiHcrtmEvent => "EV_EFI_HCRTM_EVENT".to_string(),
            Self::EfiVariableAuthority => "EV_EFI_VARIABLE_AUTHORITY".to_string(),
            Self::EfiSpdmFirmwareBlob => "EV_EFI_SPDM_FIRMWARE_BLOB".to_string(),
            Self::EfiSpdmFirmwareConfig => "EV_EFI_SPDM_FIRMWARE_CONFIG".to_string(),
            Self::EfiSpdmDevicePolicy => "EV_EFI_SPDM_DEVICE_POLICY".to_string(),
            Self::EfiSpdmDeviceAuthority => "EV_EFI_SPDM_DEVICE_AUTHORITY".to_string(),
            Self::Unknown(v) => format!("Unknown({:#010x})", v),
        }
    }
}

impl From<EventType> for String {
    fn from(et: EventType) -> String {
        et.name()
    }
}

impl From<String> for EventType {
    fn from(s: String) -> Self {
        match s.as_str() {
            "EV_PREBOOT_CERT" => Self::PrebootCert,
            "EV_POST_CODE" => Self::PostCode,
            "EV_UNUSED" => Self::Unused,
            "EV_NO_ACTION" => Self::NoAction,
            "EV_SEPARATOR" => Self::Separator,
            "EV_ACTION" => Self::Action,
            "EV_EVENT_TAG" => Self::EventTag,
            "EV_S_CRTM_CONTENTS" => Self::SCrtmContents,
            "EV_S_CRTM_VERSION" => Self::SCrtmVersion,
            "EV_CPU_MICROCODE" => Self::CpuMicrocode,
            "EV_PLATFORM_CONFIG_FLAGS" => Self::PlatformConfigFlags,
            "EV_TABLE_OF_DEVICES" => Self::TableOfDevices,
            "EV_COMPACT_HASH" => Self::CompactHash,
            "EV_IPL" => Self::Ipl,
            "EV_IPL_PARTITION_DATA" => Self::IplPartitionData,
            "EV_NONHOST_CODE" => Self::NonhostCode,
            "EV_NONHOST_CONFIG" => Self::NonhostConfig,
            "EV_NONHOST_INFO" => Self::NonhostInfo,
            "EV_OMIT_BOOT_DEVICE_EVENTS" => Self::OmitBootDeviceEvents,
            "EV_POST_CODE2" => Self::PostCode2,
            "EV_EFI_EVENT_BASE" => Self::EfiEventBase,
            "EV_EFI_VARIABLE_DRIVER_CONFIG" => Self::EfiVariableDriverConfig,
            "EV_EFI_VARIABLE_BOOT" => Self::EfiVariableBoot,
            "EV_EFI_BOOT_SERVICES_APPLICATION" => Self::EfiBootServicesApplication,
            "EV_EFI_BOOT_SERVICES_DRIVER" => Self::EfiBootServicesDriver,
            "EV_EFI_RUNTIME_SERVICES_DRIVER" => Self::EfiRuntimeServicesDriver,
            "EV_EFI_GPT_EVENT" => Self::EfiGptEvent,
            "EV_EFI_ACTION" => Self::EfiAction,
            "EV_EFI_PLATFORM_FIRMWARE_BLOB" => Self::EfiFirmwareBlob,
            "EV_EFI_HANDOFF_TABLES" => Self::EfiHandoffTables,
            "EV_EFI_PLATFORM_FIRMWARE_BLOB2" => Self::EfiFirmwareBlob2,
            "EV_EFI_HANDOFF_TABLES2" => Self::EfiHandoffTables2,
            "EV_EFI_VARIABLE_BOOT2" => Self::EfiVariableBoot2,
            "EV_EFI_GPT_EVENT2" => Self::EfiGptEvent2,
            "EV_EFI_HCRTM_EVENT" => Self::EfiHcrtmEvent,
            "EV_EFI_VARIABLE_AUTHORITY" => Self::EfiVariableAuthority,
            "EV_EFI_SPDM_FIRMWARE_BLOB" => Self::EfiSpdmFirmwareBlob,
            "EV_EFI_SPDM_FIRMWARE_CONFIG" => Self::EfiSpdmFirmwareConfig,
            "EV_EFI_SPDM_DEVICE_POLICY" => Self::EfiSpdmDevicePolicy,
            "EV_EFI_SPDM_DEVICE_AUTHORITY" => Self::EfiSpdmDeviceAuthority,
            other => {
                // Try to recover the numeric value from "Unknown(0xXXXXXXXX)".
                parse_unknown_u32(other).map_or(Self::Unknown(0), Self::Unknown)
            }
        }
    }
}

/// A UEFI GUID (128-bit globally unique identifier).
///
/// The on-disk layout uses mixed endianness as defined by the UEFI specification:
/// `Data1` is a little-endian `u32`, `Data2` and `Data3` are little-endian `u16`s,
/// and `Data4` is an 8-byte big-endian byte array.
///
/// The string representation follows the standard
/// `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` format.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(into = "String", from = "String")]
pub struct Guid {
    /// The raw 16-byte GUID in the UEFI mixed-endian on-disk layout.
    pub bytes: [u8; 16],
}

impl Guid {
    /// Creates a [`Guid`] from 16 raw bytes in UEFI mixed-endian order.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::Guid;
    ///
    /// let bytes = [
    ///     0x61, 0xDF, 0xe4, 0x8B, // Data1 (LE) => 0x8BE4DF61
    ///     0x03, 0x17,              // Data2 (LE) => 0x1703
    ///     0x91, 0x4E,              // Data3 (LE) => 0x4E91
    ///     0x96, 0xE8, 0x44, 0xB5, 0x0C, 0xD2, 0x16, 0xE2,
    /// ];
    /// let guid = Guid::from_bytes(bytes);
    /// assert_eq!(guid.to_string(), "{8be4df61-1703-4e91-96e8-44b50cd216e2}");
    /// ```
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }

    /// Returns the GUID formatted as `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::Guid;
    ///
    /// let zero = Guid::from_bytes([0u8; 16]);
    /// assert_eq!(format!("{zero}"), "{00000000-0000-0000-0000-000000000000}");
    /// ```
    fn fmt_guid(&self) -> String {
        // Pre-sized stack buffer: {8-4-4-4-12} = 38 ASCII bytes.
        static HEX: &[u8; 16] = b"0123456789abcdef";
        let mut buf = [0u8; 38];
        buf[0] = b'{';

        // Helper: write a byte as two hex nibbles at `pos`.
        #[inline(always)]
        fn put(buf: &mut [u8; 38], pos: usize, b: u8) {
            buf[pos] = HEX[(b >> 4) as usize];
            buf[pos + 1] = HEX[(b & 0xf) as usize];
        }

        let d1 = u32::from_le_bytes([self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3]]);
        let d1b = d1.to_be_bytes();
        put(&mut buf, 1, d1b[0]);
        put(&mut buf, 3, d1b[1]);
        put(&mut buf, 5, d1b[2]);
        put(&mut buf, 7, d1b[3]);
        buf[9] = b'-';

        let d2 = u16::from_le_bytes([self.bytes[4], self.bytes[5]]);
        let d2b = d2.to_be_bytes();
        put(&mut buf, 10, d2b[0]);
        put(&mut buf, 12, d2b[1]);
        buf[14] = b'-';

        let d3 = u16::from_le_bytes([self.bytes[6], self.bytes[7]]);
        let d3b = d3.to_be_bytes();
        put(&mut buf, 15, d3b[0]);
        put(&mut buf, 17, d3b[1]);
        buf[19] = b'-';

        put(&mut buf, 20, self.bytes[8]);
        put(&mut buf, 22, self.bytes[9]);
        buf[24] = b'-';

        for i in 0..6 {
            put(&mut buf, 25 + i * 2, self.bytes[10 + i]);
        }
        buf[37] = b'}';

        // SAFETY: `buf` contains only ASCII bytes from HEX + literal ASCII.
        unsafe { String::from_utf8_unchecked(buf.to_vec()) }
    }
}

impl std::fmt::Display for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.fmt_guid())
    }
}

impl From<Guid> for String {
    fn from(g: Guid) -> String {
        g.fmt_guid()
    }
}

impl From<String> for Guid {
    /// Attempts to parse a GUID string in `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` format.
    /// Returns a zeroed GUID on parse failure.
    fn from(s: String) -> Self {
        // Strip optional braces
        let s = s.trim_matches(|c| c == '{' || c == '}');
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 5 {
            return Self { bytes: [0u8; 16] };
        }
        let d1 = u32::from_str_radix(parts[0], 16).unwrap_or(0).to_le_bytes();
        let d2 = u16::from_str_radix(parts[1], 16).unwrap_or(0).to_le_bytes();
        let d3 = u16::from_str_radix(parts[2], 16).unwrap_or(0).to_le_bytes();
        let d4_str = format!("{}{}", parts[3], parts[4]);
        let mut d4 = [0u8; 8];
        for i in 0..8 {
            d4[i] = u8::from_str_radix(&d4_str[i * 2..i * 2 + 2], 16).unwrap_or(0);
        }
        Self {
            bytes: [
                d1[0], d1[1], d1[2], d1[3], d2[0], d2[1], d3[0], d3[1], d4[0], d4[1], d4[2], d4[3],
                d4[4], d4[5], d4[6], d4[7],
            ],
        }
    }
}

/// Encodes a byte slice as a lowercase hexadecimal string.
///
/// # Examples
///
/// ```
/// use tcglog_parser::to_hex;
///
/// assert_eq!(to_hex(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
/// assert_eq!(to_hex(&[]), "");
/// ```
pub fn to_hex(bytes: &[u8]) -> String {
    // One allocation sized upfront; nibble lookup avoids any format! overhead.
    static NIBBLES: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(NIBBLES[(b >> 4) as usize]);
        out.push(NIBBLES[(b & 0xf) as usize]);
    }
    // SAFETY: `out` contains only ASCII bytes from `NIBBLES`.
    unsafe { String::from_utf8_unchecked(out) }
}

/// Parses the numeric value out of an `"unknown(0xXXXX)"` string produced
/// by [`HashAlgorithmId::name`].  Returns `None` if the string does not
/// match that pattern.
fn parse_unknown_u16(s: &str) -> Option<u16> {
    let inner = s.strip_prefix("unknown(")?.strip_suffix(')')?;
    let hex = inner.strip_prefix("0x")?;
    u16::from_str_radix(hex, 16).ok()
}

/// Parses the numeric value out of an `"Unknown(0xXXXXXXXX)"` string
/// produced by [`EventType::name`].  Returns `None` if the string does not
/// match that pattern.
fn parse_unknown_u32(s: &str) -> Option<u32> {
    let inner = s.strip_prefix("Unknown(")?.strip_suffix(')')?;
    let hex = inner.strip_prefix("0x")?;
    u32::from_str_radix(hex, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_algorithm_id_round_trip() {
        for &id in &[
            0x0004u16, 0x000B, 0x000C, 0x000D, 0x0012, 0x0027, 0x0028, 0x0029,
        ] {
            let alg = HashAlgorithmId::from_id(id);
            assert_eq!(alg.to_id(), id);
        }
    }

    #[test]
    fn hash_algorithm_id_unknown() {
        let alg = HashAlgorithmId::from_id(0xFFFF);
        assert_eq!(alg, HashAlgorithmId::Unknown(0xFFFF));
        assert_eq!(alg.digest_size(), None);
        assert_eq!(alg.name(), "unknown(0xffff)");
    }

    #[test]
    fn hash_algorithm_id_digest_sizes() {
        assert_eq!(HashAlgorithmId::Sha1.digest_size(), Some(20));
        assert_eq!(HashAlgorithmId::Sha256.digest_size(), Some(32));
        assert_eq!(HashAlgorithmId::Sha384.digest_size(), Some(48));
        assert_eq!(HashAlgorithmId::Sha512.digest_size(), Some(64));
        assert_eq!(HashAlgorithmId::Sm3_256.digest_size(), Some(32));
        assert_eq!(HashAlgorithmId::Sha3_256.digest_size(), Some(32));
        assert_eq!(HashAlgorithmId::Sha3_384.digest_size(), Some(48));
        assert_eq!(HashAlgorithmId::Sha3_512.digest_size(), Some(64));
    }

    #[test]
    fn event_type_round_trip() {
        let types = [
            (0x00000000u32, EventType::PrebootCert),
            (0x00000003, EventType::NoAction),
            (0x00000004, EventType::Separator),
            (0x80000001, EventType::EfiVariableDriverConfig),
            (0x80000003, EventType::EfiBootServicesApplication),
            (0x8000000C, EventType::EfiVariableBoot2),
            (0x80000010, EventType::EfiHcrtmEvent),
            (0x800000E0, EventType::EfiVariableAuthority),
        ];
        for (val, ty) in types {
            assert_eq!(EventType::from_value(val), ty);
            assert_eq!(ty.to_value(), val);
        }
    }

    #[test]
    fn event_type_unknown() {
        let et = EventType::from_value(0xDEAD);
        assert_eq!(et, EventType::Unknown(0xDEAD));
        assert_eq!(et.name(), "Unknown(0x0000dead)");
    }

    #[test]
    fn hash_algorithm_id_unknown_string_round_trip() {
        // Serialise Unknown(0x1234) to its name, then deserialise back.
        let alg = HashAlgorithmId::Unknown(0x1234);
        let name = alg.name();
        assert_eq!(name, "unknown(0x1234)");
        let recovered = HashAlgorithmId::from(name);
        assert_eq!(recovered, HashAlgorithmId::Unknown(0x1234));
    }

    #[test]
    fn event_type_unknown_string_round_trip() {
        // Serialise Unknown(0xDEAD) to its name, then deserialise back.
        let et = EventType::Unknown(0xDEAD);
        let name = et.name();
        assert_eq!(name, "Unknown(0x0000dead)");
        let recovered = EventType::from(name);
        assert_eq!(recovered, EventType::Unknown(0xDEAD));
    }

    #[test]
    fn guid_formatting() {
        // EFI_GLOBAL_VARIABLE GUID: 8be4df61-1703-4e91-96e8-44b50cd216e2
        let bytes: [u8; 16] = [
            0x61, 0xDF, 0xe4, 0x8B, // Data1 LE
            0x03, 0x17, // Data2 LE
            0x91, 0x4E, // Data3 LE
            0x96, 0xE8, 0x44, 0xB5, 0x0C, 0xD2, 0x16, 0xE2,
        ];
        let guid = Guid::from_bytes(bytes);
        assert_eq!(guid.to_string(), "{8be4df61-1703-4e91-96e8-44b50cd216e2}");
    }

    #[test]
    fn guid_zero() {
        let guid = Guid::from_bytes([0u8; 16]);
        assert_eq!(guid.to_string(), "{00000000-0000-0000-0000-000000000000}");
    }

    #[test]
    fn to_hex_empty() {
        assert_eq!(to_hex(&[]), "");
    }

    #[test]
    fn to_hex_values() {
        assert_eq!(to_hex(&[0x00, 0xFF, 0xAB]), "00ffab");
    }

    #[test]
    fn guid_serde_round_trip() {
        let bytes: [u8; 16] = [
            0x61, 0xDF, 0xe4, 0x8B, 0x03, 0x17, 0x91, 0x4E, 0x96, 0xE8, 0x44, 0xB5, 0x0C, 0xD2,
            0x16, 0xE2,
        ];
        let guid = Guid::from_bytes(bytes);
        let json = serde_json::to_string(&guid).unwrap();
        let recovered: Guid = serde_json::from_str(&json).unwrap();
        assert_eq!(guid, recovered);
    }

    #[test]
    fn sha3_algorithm_id_round_trip() {
        let pairs = [
            (0x0027u16, HashAlgorithmId::Sha3_256),
            (0x0028, HashAlgorithmId::Sha3_384),
            (0x0029, HashAlgorithmId::Sha3_512),
        ];
        for (id, expected) in pairs {
            let alg = HashAlgorithmId::from_id(id);
            assert_eq!(alg, expected);
            assert_eq!(alg.to_id(), id);
        }
    }

    #[test]
    fn sha3_algorithm_id_serde_round_trip() {
        for alg in [
            HashAlgorithmId::Sha3_256,
            HashAlgorithmId::Sha3_384,
            HashAlgorithmId::Sha3_512,
        ] {
            let json = serde_json::to_string(&alg).unwrap();
            let recovered: HashAlgorithmId = serde_json::from_str(&json).unwrap();
            assert_eq!(alg, recovered);
        }
    }

    #[test]
    fn new_event_types_serde_round_trip() {
        for et in [EventType::EfiVariableBoot2, EventType::EfiHcrtmEvent] {
            let json = serde_json::to_string(&et).unwrap();
            let recovered: EventType = serde_json::from_str(&json).unwrap();
            assert_eq!(et, recovered);
        }
    }
}
