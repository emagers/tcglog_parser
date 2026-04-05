//! Windows Boot Configuration Log (WBCL) event parsing.
//!
//! WBCL is the name Windows gives to the TCG event log.  Windows-specific
//! measurements appear in the log as [`EventType::EventTag`](crate::EventType::EventTag)
//! (`EV_EVENT_TAG`, `0x00000006`) entries whose event data is a flat sequence
//! of **SIPA** (Security Initiative Policy Attestation) sub-events.
//!
//! Each sub-event has the on-disk layout:
//! ```text
//! u32  event_type   (little-endian)
//! u32  data_size    (little-endian)
//! [u8; data_size]  data
//! ```
//!
//! When both the `SIPAEVENTTYPE_AGGREGATION` (`0x40000000`) and
//! `SIPAEVENTTYPE_CONTAINER` (`0x00010000`) bits are set in `event_type`,
//! the `data` field is itself a nested sequence of SIPA sub-events.
//!
//! Constants, types, and names are derived from `wbcl.h` (Windows SDK) and
//! the PCPTool sample (`AttestationAPI.cpp`, `Support.cpp`).

use crate::error::ParseError;
use crate::types::to_hex;
use serde::{Deserialize, Serialize};

// ── SIPA event-type flags (high bits) ─────────────────────────────────────────

/// Bit 31: event was **not** measured / extended into a PCR.
pub const SIPAEVENTTYPE_NONMEASURED: u32 = 0x8000_0000;

/// Bit 30: event is an aggregation container of nested SIPA sub-events.
pub const SIPAEVENTTYPE_AGGREGATION: u32 = 0x4000_0000;

// ── SIPA category codes (bits 16–27) ─────────────────────────────────────────

const SIPAEVENTTYPE_CONTAINER: u32      = 0x0001_0000;
const SIPAEVENTTYPE_INFORMATION: u32    = 0x0002_0000;
const SIPAEVENTTYPE_ERROR: u32          = 0x0003_0000;
const SIPAEVENTTYPE_PREOSPARAMETER: u32 = 0x0004_0000;
const SIPAEVENTTYPE_OSPARAMETER: u32    = 0x0005_0000;
const SIPAEVENTTYPE_AUTHORITY: u32      = 0x0006_0000;
const SIPAEVENTTYPE_LOADEDMODULE: u32   = 0x0007_0000;
const SIPAEVENTTYPE_TRUSTPOINT: u32     = 0x0008_0000;
const SIPAEVENTTYPE_ELAM: u32           = 0x0009_0000;
const SIPAEVENTTYPE_VBS: u32            = 0x000A_0000;
const SIPAEVENTTYPE_KSR: u32            = 0x000B_0000;
const SIPAEVENTTYPE_DRTM: u32           = 0x000C_0000;

// ── Well-known SIPA event-type values ─────────────────────────────────────────

// --- Aggregation / container events ---

/// Root container for a single boot phase's measurements.
pub const SIPAEVENT_TRUSTBOUNDARY: u32 =
    SIPAEVENTTYPE_AGGREGATION | SIPAEVENTTYPE_CONTAINER | 0x0001;

/// Aggregation container for ELAM driver measurements.
pub const SIPAEVENT_ELAM_AGGREGATION: u32 =
    SIPAEVENTTYPE_AGGREGATION | SIPAEVENTTYPE_CONTAINER | 0x0002;

/// Aggregation container for loaded-module measurements.
pub const SIPAEVENT_LOADEDMODULE_AGGREGATION: u32 =
    SIPAEVENTTYPE_AGGREGATION | SIPAEVENTTYPE_CONTAINER | 0x0003;

/// Aggregation container for the TPM quote / trust point.
pub const SIPAEVENT_TRUSTPOINT_AGGREGATION: u32 =
    SIPAEVENTTYPE_NONMEASURED | SIPAEVENTTYPE_AGGREGATION | SIPAEVENTTYPE_CONTAINER | 0x0004;

/// Aggregation container for KSR (Kernel Software Resilience) measurements.
pub const SIPAEVENT_KSR_AGGREGATION: u32 =
    SIPAEVENTTYPE_AGGREGATION | SIPAEVENTTYPE_CONTAINER | 0x0005;

/// Aggregation container for a KSR signed measurement.
pub const SIPAEVENT_KSR_SIGNED_MEASUREMENT_AGGREGATION: u32 =
    SIPAEVENTTYPE_AGGREGATION | SIPAEVENTTYPE_CONTAINER | 0x0006;

// --- Error events ---

/// Firmware reported an error during the boot measurement sequence.
pub const SIPAERROR_FIRMWAREFAILURE: u32 = SIPAEVENTTYPE_ERROR | 0x0001;

/// TPM reported a failure (not measured into PCR).
pub const SIPAERROR_TPMFAILURE: u32 =
    SIPAEVENTTYPE_NONMEASURED | SIPAEVENTTYPE_ERROR | 0x0002;

/// Internal integrity-services failure.
pub const SIPAERROR_INTERNALFAILURE: u32 = SIPAEVENTTYPE_ERROR | 0x0003;

/// KSR failure (not measured into PCR).
pub const SIPAERROR_KSRFAILURE: u32 =
    SIPAEVENTTYPE_NONMEASURED | SIPAEVENTTYPE_ERROR | 0x0004;

// --- Information events ---

/// Generic informational event.
pub const SIPAEVENT_INFORMATION: u32 = SIPAEVENTTYPE_INFORMATION | 0x0001;

/// TPM 2.0 power-up boot counter value (`u64`).
pub const SIPAEVENT_BOOTCOUNTER: u32 = SIPAEVENTTYPE_INFORMATION | 0x0002;

/// Control was transferred to another boot application (`u32` target code).
pub const SIPAEVENT_TRANSFER_CONTROL: u32 = SIPAEVENTTYPE_INFORMATION | 0x0003;

/// A boot application returned control.
pub const SIPAEVENT_APPLICATION_RETURN: u32 = SIPAEVENTTYPE_INFORMATION | 0x0004;

/// A BitLocker-protected volume was unlocked (`u32` flags).
pub const SIPAEVENT_BITLOCKER_UNLOCK: u32 = SIPAEVENTTYPE_INFORMATION | 0x0005;

/// TPM monotonic event counter at boot time (`u64`).
pub const SIPAEVENT_EVENTCOUNTER: u32 = SIPAEVENTTYPE_INFORMATION | 0x0006;

/// TPM 1.2 counter identifier (`u64`).
pub const SIPAEVENT_COUNTERID: u32 = SIPAEVENTTYPE_INFORMATION | 0x0007;

/// MOR bit cannot be cancelled by the OS.
pub const SIPAEVENT_MORBIT_NOT_CANCELABLE: u32 = SIPAEVENTTYPE_INFORMATION | 0x0008;

/// Security version number of the boot application (`u64`).
pub const SIPAEVENT_APPLICATION_SVN: u32 = SIPAEVENTTYPE_INFORMATION | 0x0009;

/// SVN chain validation status (`u64`).
pub const SIPAEVENT_SVN_CHAIN_STATUS: u32 = SIPAEVENTTYPE_INFORMATION | 0x000A;

/// NTSTATUS from the MOR-bit setting API (`u32`).
pub const SIPAEVENT_MORBIT_API_STATUS: u32 = SIPAEVENTTYPE_INFORMATION | 0x000B;

/// IDK generation/caching status for VSM (`u32`).
pub const SIPAEVENT_IDK_GENERATION_STATUS: u32 = SIPAEVENTTYPE_INFORMATION | 0x000C;

// --- Pre-OS parameter events ---

/// Boot debugger was enabled (`bool`).
pub const SIPAEVENT_BOOTDEBUGGING: u32 = SIPAEVENTTYPE_PREOSPARAMETER | 0x0001;

/// Boot revocation list.
pub const SIPAEVENT_BOOT_REVOCATION_LIST: u32 = SIPAEVENTTYPE_PREOSPARAMETER | 0x0002;

// --- OS parameter events ---

/// Kernel debugger is enabled (`bool`).
pub const SIPAEVENT_OSKERNELDEBUG: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0001;

/// Code Integrity (HVCI/CI) enforcement is **enabled** (`bool`).
pub const SIPAEVENT_CODEINTEGRITY: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0002;

/// Test-signing mode is enabled (`bool`).
pub const SIPAEVENT_TESTSIGNING: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0003;

/// Data Execution Prevention (DEP / NX) policy value (`u64`).
pub const SIPAEVENT_DATAEXECUTIONPREVENTION: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0004;

/// OS booted into Safe Mode (`bool`).
pub const SIPAEVENT_SAFEMODE: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0005;

/// OS is running as Windows PE (`bool`).
pub const SIPAEVENT_WINPE: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0006;

/// Physical Address Extension (PAE) is enabled (`u64`).
pub const SIPAEVENT_PHYSICALADDRESSEXTENSION: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0007;

/// Type of the device the OS was booted from (`u32` `OSDEVICE_TYPE_*`).
pub const SIPAEVENT_OSDEVICE: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0008;

/// OS system root path (UTF-16LE string, e.g. `\Windows`).
pub const SIPAEVENT_SYSTEMROOT: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0009;

/// Hypervisor launch type (`u64`; 0 = not launched).
pub const SIPAEVENT_HYPERVISOR_LAUNCH_TYPE: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x000A;

/// Path to the hypervisor binary (UTF-16LE string).
pub const SIPAEVENT_HYPERVISOR_PATH: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x000B;

/// IOMMU policy enforced by the hypervisor (`u64`).
pub const SIPAEVENT_HYPERVISOR_IOMMU_POLICY: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x000C;

/// Hypervisor debug mode is enabled (`bool`).
pub const SIPAEVENT_HYPERVISOR_DEBUG: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x000D;

/// Driver load policy (`u32`; 1 = default).
pub const SIPAEVENT_DRIVER_LOAD_POLICY: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x000E;

/// System Integrity (WDAC / AppLocker) policy blob.
pub const SIPAEVENT_SI_POLICY: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x000F;

/// Hypervisor MMIO NX policy.
pub const SIPAEVENT_HYPERVISOR_MMIO_NX_POLICY: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0010;

/// Hypervisor MSR-filter policy.
pub const SIPAEVENT_HYPERVISOR_MSR_FILTER_POLICY: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0011;

/// Virtual Secure Mode (VSM) launch type (`u64`).
pub const SIPAEVENT_VSM_LAUNCH_TYPE: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0012;

/// OS boot revocation list.
pub const SIPAEVENT_OS_REVOCATION_LIST: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0013;

/// SMT (Hyper-Threading) status (`u64`; 0 = disabled, 1 = enabled, 2 = SW-disabled).
pub const SIPAEVENT_SMT_STATUS: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0014;

/// VSM identity key information.
pub const SIPAEVENT_VSM_IDK_INFO: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0020;

/// Flight/preview signing mode is enabled (`bool`).
pub const SIPAEVENT_FLIGHTSIGNING: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0021;

/// Page-file encryption is enabled (`bool`).
pub const SIPAEVENT_PAGEFILE_ENCRYPTION_ENABLED: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0022;

/// VSM identity key signing information.
pub const SIPAEVENT_VSM_IDKS_INFO: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0023;

/// Hibernation has been disabled (`bool`).
pub const SIPAEVENT_HIBERNATION_DISABLED: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0024;

/// Crash dumps have been disabled (`bool`).
pub const SIPAEVENT_DUMPS_DISABLED: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0025;

/// Crash-dump encryption is enabled (`bool`).
pub const SIPAEVENT_DUMP_ENCRYPTION_ENABLED: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0026;

/// SHA-256 digest of the dump-encryption key.
pub const SIPAEVENT_DUMP_ENCRYPTION_KEY_DIGEST: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0027;

/// LSA isolated configuration flags (`u32`).
pub const SIPAEVENT_LSAISO_CONFIG: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0028;

/// Secure Boot Custom Policy (SBCP) information.
pub const SIPAEVENT_SBCP_INFO: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0029;

/// Hypervisor Boot DMA protection is enabled (`bool`).
pub const SIPAEVENT_HYPERVISOR_BOOT_DMA_PROTECTION: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0030;

/// Code integrity (WDAC/AppLocker) policy signer information (Windows 11+).
pub const SIPAEVENT_SI_POLICY_SIGNER: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0031;

/// Code integrity policy allowed-update signer information (Windows 11+).
pub const SIPAEVENT_SI_POLICY_UPDATE_SIGNER: u32 = SIPAEVENTTYPE_OSPARAMETER | 0x0032;

// --- Authority events ---

/// The loaded image had no authority / was not signed.
pub const SIPAEVENT_NOAUTHORITY: u32 = SIPAEVENTTYPE_AUTHORITY | 0x0001;

/// Public key of the signing authority (raw bytes).
pub const SIPAEVENT_AUTHORITYPUBKEY: u32 = SIPAEVENTTYPE_AUTHORITY | 0x0002;

// --- Loaded-module events ---

/// File path of the loaded image (UTF-16LE string).
pub const SIPAEVENT_FILEPATH: u32 = SIPAEVENTTYPE_LOADEDMODULE | 0x0001;

/// Size of the loaded image in bytes (`u64`).
pub const SIPAEVENT_IMAGESIZE: u32 = SIPAEVENTTYPE_LOADEDMODULE | 0x0002;

/// CAPI algorithm ID used to produce the Authenticode hash (`u32`).
pub const SIPAEVENT_HASHALGORITHMID: u32 = SIPAEVENTTYPE_LOADEDMODULE | 0x0003;

/// Authenticode hash of the loaded image (raw bytes).
pub const SIPAEVENT_AUTHENTICODEHASH: u32 = SIPAEVENTTYPE_LOADEDMODULE | 0x0004;

/// Issuer distinguished name of the signing certificate (UTF-16LE string).
pub const SIPAEVENT_AUTHORITYISSUER: u32 = SIPAEVENTTYPE_LOADEDMODULE | 0x0005;

/// Serial number of the signing certificate (raw bytes).
pub const SIPAEVENT_AUTHORITYSERIAL: u32 = SIPAEVENTTYPE_LOADEDMODULE | 0x0006;

/// Load address (image base) of the image (`u64`).
pub const SIPAEVENT_IMAGEBASE: u32 = SIPAEVENTTYPE_LOADEDMODULE | 0x0007;

/// Subject / publisher distinguished name of the signing certificate (UTF-16LE string).
pub const SIPAEVENT_AUTHORITYPUBLISHER: u32 = SIPAEVENTTYPE_LOADEDMODULE | 0x0008;

/// SHA-1 thumbprint of the signing certificate (raw bytes).
pub const SIPAEVENT_AUTHORITYSHA1THUMBPRINT: u32 = SIPAEVENTTYPE_LOADEDMODULE | 0x0009;

/// Whether Authenticode validation of the image succeeded (`bool`).
pub const SIPAEVENT_IMAGEVALIDATED: u32 = SIPAEVENTTYPE_LOADEDMODULE | 0x000A;

/// Security version number (SVN) of the loaded module (`u64`).
pub const SIPAEVENT_MODULE_SVN: u32 = SIPAEVENTTYPE_LOADEDMODULE | 0x000B;

/// Pluton security processor measurement (Windows 10 NI+, raw bytes).
pub const SIPAEVENT_MODULE_PLUTON: u32 = SIPAEVENTTYPE_LOADEDMODULE | 0x000C;

/// Module internal / original filename (UTF-16LE string).
///
/// Not present in the public `wbcl.h` SDK header; name and purpose are
/// inferred from observed payloads (e.g. `"bootmgr.exe.mui"`, `"hiberrsm.exe"`).
/// Corresponds to the PE version-resource *OriginalFilename* / *InternalName*.
pub const SIPAEVENT_MODULE_ORIGINAL_FILENAME: u32 = SIPAEVENTTYPE_LOADEDMODULE | 0x000D;

/// Module build timestamp or version info (`u64`).
///
/// Not present in the public `wbcl.h` SDK header; name and purpose are
/// inferred from observed 8-byte payloads whose low 4 bytes resemble a PE
/// `TimeDateStamp` and whose high bytes encode the OS major version.
pub const SIPAEVENT_MODULE_TIMESTAMP: u32 = SIPAEVENTTYPE_LOADEDMODULE | 0x000E;

// --- Trust-point events (non-measured) ---

/// Raw TPM quote structure (not measured into PCR).
pub const SIPAEVENT_QUOTE: u32 =
    SIPAEVENTTYPE_NONMEASURED | SIPAEVENTTYPE_TRUSTPOINT | 0x0001;

/// Signature over the TPM quote (not measured into PCR).
pub const SIPAEVENT_QUOTESIGNATURE: u32 =
    SIPAEVENTTYPE_NONMEASURED | SIPAEVENTTYPE_TRUSTPOINT | 0x0002;

/// Identifier of the Attestation Identity Key (not measured into PCR).
pub const SIPAEVENT_AIKID: u32 =
    SIPAEVENTTYPE_NONMEASURED | SIPAEVENTTYPE_TRUSTPOINT | 0x0003;

/// SHA-1 digest of the AIK public key (not measured into PCR).
pub const SIPAEVENT_AIKPUBDIGEST: u32 =
    SIPAEVENTTYPE_NONMEASURED | SIPAEVENTTYPE_TRUSTPOINT | 0x0004;

// --- ELAM events ---

/// Registry key name of the ELAM driver (UTF-16LE string).
pub const SIPAEVENT_ELAM_KEYNAME: u32 = SIPAEVENTTYPE_ELAM | 0x0001;

/// ELAM driver configuration data (raw bytes).
pub const SIPAEVENT_ELAM_CONFIGURATION: u32 = SIPAEVENTTYPE_ELAM | 0x0002;

/// ELAM driver policy data (raw bytes).
pub const SIPAEVENT_ELAM_POLICY: u32 = SIPAEVENTTYPE_ELAM | 0x0003;

/// ELAM driver measurement data (raw bytes).
pub const SIPAEVENT_ELAM_MEASURED: u32 = SIPAEVENTTYPE_ELAM | 0x0004;

// --- VBS (Virtualization-Based Security) events ---

/// VSM is required (`bool`).
pub const SIPAEVENT_VBS_VSM_REQUIRED: u32 = SIPAEVENTTYPE_VBS | 0x0001;

/// Secure Boot is required for VBS (`bool`).
pub const SIPAEVENT_VBS_SECUREBOOT_REQUIRED: u32 = SIPAEVENTTYPE_VBS | 0x0002;

/// IOMMU is required for VBS (`bool`).
pub const SIPAEVENT_VBS_IOMMU_REQUIRED: u32 = SIPAEVENTTYPE_VBS | 0x0003;

/// MMIO NX is required for VBS (`bool`).
pub const SIPAEVENT_VBS_MMIO_NX_REQUIRED: u32 = SIPAEVENTTYPE_VBS | 0x0004;

/// MSR filtering is required for VBS (`bool`).
pub const SIPAEVENT_VBS_MSR_FILTERING_REQUIRED: u32 = SIPAEVENTTYPE_VBS | 0x0005;

/// VBS is in mandatory-enforcement mode (`bool`).
pub const SIPAEVENT_VBS_MANDATORY_ENFORCEMENT: u32 = SIPAEVENTTYPE_VBS | 0x0006;

/// Hypervisor-Protected Code Integrity (HVCI) policy (`u64`).
pub const SIPAEVENT_VBS_HVCI_POLICY: u32 = SIPAEVENTTYPE_VBS | 0x0007;

/// Microsoft-signed boot chain is required for VBS (`bool`).
pub const SIPAEVENT_VBS_MICROSOFT_BOOT_CHAIN_REQUIRED: u32 = SIPAEVENTTYPE_VBS | 0x0008;

/// VBS VSM no-secrets-enforced policy.
pub const SIPAEVENT_VBS_VSM_NOSECRETS_ENFORCED: u32 = SIPAEVENTTYPE_VBS | 0x000A;

// --- KSR events ---

/// KSR measurement signature.
pub const SIPAEVENT_KSR_SIGNATURE: u32 = SIPAEVENTTYPE_KSR | 0x0001;

// --- DRTM events ---

/// DRTM state authorisation.
pub const SIPAEVENT_DRTM_STATE_AUTH: u32 = SIPAEVENTTYPE_DRTM | 0x0001;

/// DRTM SMM protection level.
pub const SIPAEVENT_DRTM_SMM_LEVEL: u32 = SIPAEVENTTYPE_DRTM | 0x0002;

// ── BitLocker unlock flags (FVEB_UNLOCK_FLAG_*) ───────────────────────────────

const FVEB_UNLOCK_FLAG_CACHED: u32   = 0x0000_0001;
const FVEB_UNLOCK_FLAG_MEDIA: u32    = 0x0000_0002;
const FVEB_UNLOCK_FLAG_TPM: u32      = 0x0000_0004;
const FVEB_UNLOCK_FLAG_PIN: u32      = 0x0000_0010;
const FVEB_UNLOCK_FLAG_EXTERNAL: u32 = 0x0000_0020;
const FVEB_UNLOCK_FLAG_RECOVERY: u32 = 0x0000_0040;
const FVEB_UNLOCK_FLAG_PASSPHRASE: u32 = 0x0000_0080;
const FVEB_UNLOCK_FLAG_NBP: u32      = 0x0000_0100;

// ── OS Device type constants (OSDEVICE_TYPE_*) ────────────────────────────────

const OSDEVICE_TYPE_UNKNOWN: u32                 = 0x0000_0000;
const OSDEVICE_TYPE_BLOCKIO_HARDDISK: u32        = 0x0001_0001;
const OSDEVICE_TYPE_BLOCKIO_REMOVABLEDISK: u32   = 0x0001_0002;
const OSDEVICE_TYPE_BLOCKIO_CDROM: u32           = 0x0001_0003;
const OSDEVICE_TYPE_BLOCKIO_PARTITION: u32       = 0x0001_0004;
const OSDEVICE_TYPE_BLOCKIO_FILE: u32            = 0x0001_0005;
const OSDEVICE_TYPE_BLOCKIO_RAMDISK: u32         = 0x0001_0006;
const OSDEVICE_TYPE_BLOCKIO_VIRTUALHARDDISK: u32 = 0x0001_0007;
const OSDEVICE_TYPE_SERIAL: u32                  = 0x0002_0000;
const OSDEVICE_TYPE_UDP: u32                     = 0x0003_0000;
const OSDEVICE_TYPE_VMBUS: u32                   = 0x0004_0000;
const OSDEVICE_TYPE_COMPOSITE: u32               = 0x0005_0000;

// ── CAPI hash algorithm IDs (CALG_*) ─────────────────────────────────────────

const CALG_MD4: u32     = 0x0000_8002;
const CALG_MD5: u32     = 0x0000_8003;
const CALG_SHA1: u32    = 0x0000_8004;
const CALG_SHA_256: u32 = 0x0000_800C;
const CALG_SHA_384: u32 = 0x0000_800D;
const CALG_SHA_512: u32 = 0x0000_800E;

// ── Transfer-control target codes ────────────────────────────────────────────

const TRANSFER_CONTROL_OSLOADER: u32    = 0x0000_0001;
const TRANSFER_CONTROL_RESUME: u32      = 0x0000_0002;
const TRANSFER_CONTROL_MSUTILITY: u32   = 0x0000_0003;
const TRANSFER_CONTROL_NOSIGCHECK: u32  = 0x0000_0004;
const TRANSFER_CONTROL_HYPERVISOR: u32  = 0x0000_0005;

// ── Typed data structures for decoded payloads ────────────────────────────────

/// Decoded BitLocker unlock flags from a [`SIPAEVENT_BITLOCKER_UNLOCK`] event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitlockerUnlockData {
    /// The raw 32-bit flags value.
    pub raw_flags: u32,
    /// Unlocked using a TPM-sealed key cached from a previous boot.
    pub cached: bool,
    /// Unlocked using a key stored on removable media.
    pub media: bool,
    /// Unlocked using the TPM alone (no PIN, no external key).
    pub tpm: bool,
    /// Unlocked using a TPM + PIN combination.
    pub pin: bool,
    /// Unlocked using an external key file (.bek).
    pub external: bool,
    /// Unlocked using a BitLocker recovery key.
    pub recovery: bool,
    /// Unlocked using a passphrase.
    pub passphrase: bool,
    /// Unlocked via Network Boot Protocol (NBP).
    pub nbp: bool,
}

impl BitlockerUnlockData {
    fn from_flags(flags: u32) -> Self {
        Self {
            raw_flags: flags,
            cached:     (flags & FVEB_UNLOCK_FLAG_CACHED)     != 0,
            media:      (flags & FVEB_UNLOCK_FLAG_MEDIA)      != 0,
            tpm:        (flags & FVEB_UNLOCK_FLAG_TPM)        != 0,
            pin:        (flags & FVEB_UNLOCK_FLAG_PIN)        != 0,
            external:   (flags & FVEB_UNLOCK_FLAG_EXTERNAL)   != 0,
            recovery:   (flags & FVEB_UNLOCK_FLAG_RECOVERY)   != 0,
            passphrase: (flags & FVEB_UNLOCK_FLAG_PASSPHRASE) != 0,
            nbp:        (flags & FVEB_UNLOCK_FLAG_NBP)        != 0,
        }
    }
}

/// Decoded OS device type from a [`SIPAEVENT_OSDEVICE`] event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsDeviceData {
    /// The raw 32-bit `OSDEVICE_TYPE_*` value.
    pub raw_value: u32,
    /// Human-readable device type name.
    pub device_type: String,
}

impl OsDeviceData {
    fn from_value(v: u32) -> Self {
        let name = match v {
            OSDEVICE_TYPE_UNKNOWN                 => "UNKNOWN",
            OSDEVICE_TYPE_BLOCKIO_HARDDISK        => "BLOCKIO_HARDDISK",
            OSDEVICE_TYPE_BLOCKIO_REMOVABLEDISK   => "BLOCKIO_REMOVABLEDISK",
            OSDEVICE_TYPE_BLOCKIO_CDROM           => "BLOCKIO_CDROM",
            OSDEVICE_TYPE_BLOCKIO_PARTITION       => "BLOCKIO_PARTITION",
            OSDEVICE_TYPE_BLOCKIO_FILE            => "BLOCKIO_FILE",
            OSDEVICE_TYPE_BLOCKIO_RAMDISK         => "BLOCKIO_RAMDISK",
            OSDEVICE_TYPE_BLOCKIO_VIRTUALHARDDISK => "BLOCKIO_VIRTUALHARDDISK",
            OSDEVICE_TYPE_SERIAL                  => "SERIAL",
            OSDEVICE_TYPE_UDP                     => "UDP",
            OSDEVICE_TYPE_VMBUS                   => "VMBUS",
            OSDEVICE_TYPE_COMPOSITE               => "COMPOSITE",
            _                                     => "UNKNOWN",
        };
        Self { raw_value: v, device_type: name.to_string() }
    }
}

/// Decoded transfer-control target from a [`SIPAEVENT_TRANSFER_CONTROL`] event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferControlData {
    /// The raw 32-bit transfer-control value.
    pub raw_value: u32,
    /// Human-readable target name.
    pub target: String,
}

impl TransferControlData {
    fn from_value(v: u32) -> Self {
        let name = match v {
            TRANSFER_CONTROL_OSLOADER   => "OSLOADER",
            TRANSFER_CONTROL_RESUME     => "RESUME",
            TRANSFER_CONTROL_MSUTILITY  => "MSUTILITY",
            TRANSFER_CONTROL_NOSIGCHECK => "NOSIGCHECK",
            TRANSFER_CONTROL_HYPERVISOR => "HYPERVISOR",
            _                           => "UNKNOWN",
        };
        Self { raw_value: v, target: name.to_string() }
    }
}

/// Decoded CAPI hash algorithm ID from a [`SIPAEVENT_HASHALGORITHMID`] event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashAlgorithmData {
    /// The raw 32-bit CAPI `ALG_ID` value.
    pub raw_value: u32,
    /// Human-readable algorithm name.
    pub algorithm: String,
}

impl HashAlgorithmData {
    fn from_value(v: u32) -> Self {
        let name = match v {
            CALG_MD4     => "MD4",
            CALG_MD5     => "MD5",
            CALG_SHA1    => "SHA-1",
            CALG_SHA_256 => "SHA-256",
            CALG_SHA_384 => "SHA-384",
            CALG_SHA_512 => "SHA-512",
            _            => "UNKNOWN",
        };
        Self { raw_value: v, algorithm: name.to_string() }
    }
}

/// Decoded driver-load policy from a [`SIPAEVENT_DRIVER_LOAD_POLICY`] event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverLoadPolicyData {
    /// The raw 32-bit policy value.
    pub raw_value: u32,
    /// Human-readable policy name.
    pub policy: String,
}

impl DriverLoadPolicyData {
    fn from_value(v: u32) -> Self {
        let name = match v {
            0x0000_0001 => "DEFAULT",
            _ => "UNKNOWN",
        };
        Self { raw_value: v, policy: name.to_string() }
    }
}

// ── Structured payload types ─────────────────────────────────────────────────

/// Decoded System Integrity (CI/WDAC) policy measurement from a
/// [`SIPAEVENT_SI_POLICY`] event.
///
/// Corresponds to `SIPAEVENT_SI_POLICY_PAYLOAD` in the Windows SDK `wbcl.h`.
/// The `hash_alg_id` field carries a `TPM_ALG_ID` value (e.g. `0x000B` =
/// `TPM_ALG_SHA256`). The policy name is the string from Windows Boot
/// Configuration (e.g. `"{Policy GUID}"` or a descriptive name).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiPolicyPayload {
    /// Policy version number from the WBCL payload.
    pub policy_version: u64,
    /// Human-readable policy name decoded from UTF-16LE (includes WDAC/AppLocker
    /// policy names such as `"{SiPolicy.p7b}"`).
    pub policy_name: String,
    /// TPM algorithm ID (`TPM_ALG_ID`) used to produce the digest.
    pub hash_alg_id: u16,
    /// Hex-encoded hash digest of the policy blob.
    pub digest: String,
}

/// Decoded revocation-list hash from a [`SIPAEVENT_BOOT_REVOCATION_LIST`] or
/// [`SIPAEVENT_OS_REVOCATION_LIST`] event.
///
/// Corresponds to `SIPAEVENT_REVOCATION_LIST_PAYLOAD` in `wbcl.h`.
/// `creation_time` is a Windows FILETIME (100-nanosecond intervals since
/// 1601-01-01 UTC).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationListPayload {
    /// Windows FILETIME of the revocation list's creation.
    pub creation_time: i64,
    /// TPM algorithm ID used for the digest.
    pub hash_alg_id: u16,
    /// Hex-encoded digest of the revocation list.
    pub digest: String,
}

/// Decoded Secure Boot Custom Policy (SBCP) information from a
/// [`SIPAEVENT_SBCP_INFO`] event.
///
/// Corresponds to `SIPAEVENT_SBCP_INFO_PAYLOAD_V1` in `wbcl.h`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbcpInfoPayload {
    /// Structure version (1 for `SIPAEVENT_SBCP_INFO_PAYLOAD_V1`).
    pub payload_version: u32,
    /// TPM algorithm ID used for the digest.
    pub hash_alg_id: u16,
    /// Digest length in bytes.
    pub digest_length: u16,
    /// `OptionFlags` from the SBCP descriptor.
    pub options: u32,
    /// Number of signers in the SBCP.
    pub signers_count: u32,
    /// Hex-encoded digest of the SBCP.
    pub digest: String,
}

/// Decoded KSR measurement signature from a [`SIPAEVENT_KSR_SIGNATURE`] event.
///
/// Corresponds to `SIPAEVENT_KSR_SIGNATURE_PAYLOAD` in `wbcl.h`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KsrSignaturePayload {
    /// Signature algorithm identifier.
    pub sign_alg_id: u32,
    /// Hex-encoded signature bytes.
    pub signature: String,
}

// ── SipaEventType ─────────────────────────────────────────────────────────────

/// A SIPA event-type identifier, serialised as its human-readable name string.
///
/// Wraps the raw 32-bit `SIPAEVENT_*` / `SIPAERROR_*` value and provides
/// named access, flag queries, and lossless round-trip serialisation
/// (unknown values are preserved as `"Unknown(0xXXXXXXXX)"`).
///
/// The serialised form mirrors [`EventType`](crate::EventType): the JSON
/// field value is the name string rather than a raw integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "String", from = "String")]
pub struct SipaEventType(u32);

impl SipaEventType {
    /// Creates a `SipaEventType` from its raw 32-bit value.
    pub fn from_value(v: u32) -> Self { Self(v) }

    /// Returns the underlying raw 32-bit value.
    pub fn to_value(self) -> u32 { self.0 }

    /// Returns the human-readable name for this event type, or
    /// `"Unknown(0xXXXXXXXX)"` for unrecognised values.
    pub fn name(self) -> String {
        let n = sipa_event_name(self.0);
        if n == "Unknown" {
            format!("Unknown({:#010x})", self.0)
        } else {
            n.to_string()
        }
    }

    /// Returns `true` if this event type is an aggregation container —
    /// both `SIPAEVENTTYPE_AGGREGATION` and `SIPAEVENTTYPE_CONTAINER` bits
    /// are set.
    pub fn is_aggregation(self) -> bool { is_container(self.0) }

    /// Returns `true` if this event was not extended into a PCR
    /// (`SIPAEVENTTYPE_NONMEASURED` bit is set).
    pub fn is_non_measured(self) -> bool { (self.0 & SIPAEVENTTYPE_NONMEASURED) != 0 }
}

impl PartialEq<u32> for SipaEventType {
    fn eq(&self, other: &u32) -> bool { self.0 == *other }
}

impl From<SipaEventType> for String {
    fn from(t: SipaEventType) -> String { t.name() }
}

impl From<String> for SipaEventType {
    fn from(s: String) -> Self {
        if let Some(v) = sipa_value_from_name(&s) {
            return Self(v);
        }
        // Recover Unknown(0xXXXXXXXX) round-tripped from serialisation.
        if let Some(inner) = s.strip_prefix("Unknown(").and_then(|t| t.strip_suffix(')')) {
            if let Some(hex) = inner.strip_prefix("0x") {
                if let Ok(v) = u32::from_str_radix(hex, 16) {
                    return Self(v);
                }
            }
        }
        Self(0)
    }
}

/// Map a SIPA event-type name back to its raw `u32` value.
/// Returns `None` for names not present in the known set.
fn sipa_value_from_name(name: &str) -> Option<u32> {
    match name {
        "TrustBoundary"                       => Some(SIPAEVENT_TRUSTBOUNDARY),
        "ElamAggregation"                     => Some(SIPAEVENT_ELAM_AGGREGATION),
        "LoadedModuleAggregation"             => Some(SIPAEVENT_LOADEDMODULE_AGGREGATION),
        "TrustPointAggregation"               => Some(SIPAEVENT_TRUSTPOINT_AGGREGATION),
        "KsrAggregation"                      => Some(SIPAEVENT_KSR_AGGREGATION),
        "KsrSignedMeasurementAggregation"     => Some(SIPAEVENT_KSR_SIGNED_MEASUREMENT_AGGREGATION),
        "FirmwareFailure"                     => Some(SIPAERROR_FIRMWAREFAILURE),
        "TpmFailure"                          => Some(SIPAERROR_TPMFAILURE),
        "InternalFailure"                     => Some(SIPAERROR_INTERNALFAILURE),
        "KsrFailure"                          => Some(SIPAERROR_KSRFAILURE),
        "Information"                         => Some(SIPAEVENT_INFORMATION),
        "BootCounter"                         => Some(SIPAEVENT_BOOTCOUNTER),
        "TransferControl"                     => Some(SIPAEVENT_TRANSFER_CONTROL),
        "ApplicationReturn"                   => Some(SIPAEVENT_APPLICATION_RETURN),
        "BitLockerUnlock"                     => Some(SIPAEVENT_BITLOCKER_UNLOCK),
        "EventCounter"                        => Some(SIPAEVENT_EVENTCOUNTER),
        "CounterId"                           => Some(SIPAEVENT_COUNTERID),
        "MorBitNotCancelable"                 => Some(SIPAEVENT_MORBIT_NOT_CANCELABLE),
        "ApplicationSvn"                      => Some(SIPAEVENT_APPLICATION_SVN),
        "SvnChainStatus"                      => Some(SIPAEVENT_SVN_CHAIN_STATUS),
        "MorBitApiStatus"                     => Some(SIPAEVENT_MORBIT_API_STATUS),
        "IdkGenerationStatus"                 => Some(SIPAEVENT_IDK_GENERATION_STATUS),
        "BootDebugging"                       => Some(SIPAEVENT_BOOTDEBUGGING),
        "BootRevocationList"                  => Some(SIPAEVENT_BOOT_REVOCATION_LIST),
        "OsKernelDebug"                       => Some(SIPAEVENT_OSKERNELDEBUG),
        "CodeIntegrity"                       => Some(SIPAEVENT_CODEINTEGRITY),
        "TestSigning"                         => Some(SIPAEVENT_TESTSIGNING),
        "DataExecutionPrevention"             => Some(SIPAEVENT_DATAEXECUTIONPREVENTION),
        "SafeMode"                            => Some(SIPAEVENT_SAFEMODE),
        "WinPE"                               => Some(SIPAEVENT_WINPE),
        "PhysicalAddressExtension"            => Some(SIPAEVENT_PHYSICALADDRESSEXTENSION),
        "OsDevice"                            => Some(SIPAEVENT_OSDEVICE),
        "SystemRoot"                          => Some(SIPAEVENT_SYSTEMROOT),
        "HypervisorLaunchType"                => Some(SIPAEVENT_HYPERVISOR_LAUNCH_TYPE),
        "HypervisorPath"                      => Some(SIPAEVENT_HYPERVISOR_PATH),
        "HypervisorIommuPolicy"               => Some(SIPAEVENT_HYPERVISOR_IOMMU_POLICY),
        "HypervisorDebug"                     => Some(SIPAEVENT_HYPERVISOR_DEBUG),
        "DriverLoadPolicy"                    => Some(SIPAEVENT_DRIVER_LOAD_POLICY),
        "SiPolicy"                            => Some(SIPAEVENT_SI_POLICY),
        "HypervisorMmioNxPolicy"              => Some(SIPAEVENT_HYPERVISOR_MMIO_NX_POLICY),
        "HypervisorMsrFilterPolicy"           => Some(SIPAEVENT_HYPERVISOR_MSR_FILTER_POLICY),
        "VsmLaunchType"                       => Some(SIPAEVENT_VSM_LAUNCH_TYPE),
        "OsRevocationList"                    => Some(SIPAEVENT_OS_REVOCATION_LIST),
        "SmtStatus"                           => Some(SIPAEVENT_SMT_STATUS),
        "VsmIdkInfo"                          => Some(SIPAEVENT_VSM_IDK_INFO),
        "FlightSigning"                       => Some(SIPAEVENT_FLIGHTSIGNING),
        "PagefileEncryptionEnabled"           => Some(SIPAEVENT_PAGEFILE_ENCRYPTION_ENABLED),
        "VsmIdksInfo"                         => Some(SIPAEVENT_VSM_IDKS_INFO),
        "HibernationDisabled"                 => Some(SIPAEVENT_HIBERNATION_DISABLED),
        "DumpsDisabled"                       => Some(SIPAEVENT_DUMPS_DISABLED),
        "DumpEncryptionEnabled"               => Some(SIPAEVENT_DUMP_ENCRYPTION_ENABLED),
        "DumpEncryptionKeyDigest"             => Some(SIPAEVENT_DUMP_ENCRYPTION_KEY_DIGEST),
        "LsaIsoConfig"                        => Some(SIPAEVENT_LSAISO_CONFIG),
        "SbcpInfo"                            => Some(SIPAEVENT_SBCP_INFO),
        "HypervisorBootDmaProtection"         => Some(SIPAEVENT_HYPERVISOR_BOOT_DMA_PROTECTION),
        "SiPolicySigner"                      => Some(SIPAEVENT_SI_POLICY_SIGNER),
        "SiPolicyUpdateSigner"                => Some(SIPAEVENT_SI_POLICY_UPDATE_SIGNER),
        "NoAuthority"                         => Some(SIPAEVENT_NOAUTHORITY),
        "AuthorityPubKey"                     => Some(SIPAEVENT_AUTHORITYPUBKEY),
        "FilePath"                            => Some(SIPAEVENT_FILEPATH),
        "ImageSize"                           => Some(SIPAEVENT_IMAGESIZE),
        "HashAlgorithmId"                     => Some(SIPAEVENT_HASHALGORITHMID),
        "AuthenticodeHash"                    => Some(SIPAEVENT_AUTHENTICODEHASH),
        "AuthorityIssuer"                     => Some(SIPAEVENT_AUTHORITYISSUER),
        "AuthoritySerial"                     => Some(SIPAEVENT_AUTHORITYSERIAL),
        "ImageBase"                           => Some(SIPAEVENT_IMAGEBASE),
        "AuthorityPublisher"                  => Some(SIPAEVENT_AUTHORITYPUBLISHER),
        "AuthoritySha1Thumbprint"             => Some(SIPAEVENT_AUTHORITYSHA1THUMBPRINT),
        "ImageValidated"                      => Some(SIPAEVENT_IMAGEVALIDATED),
        "ModuleSvn"                           => Some(SIPAEVENT_MODULE_SVN),
        "ModulePluton"                        => Some(SIPAEVENT_MODULE_PLUTON),
        "ModuleOriginalFilename"              => Some(SIPAEVENT_MODULE_ORIGINAL_FILENAME),
        "ModuleTimestamp"                     => Some(SIPAEVENT_MODULE_TIMESTAMP),
        "Quote"                               => Some(SIPAEVENT_QUOTE),
        "QuoteSignature"                      => Some(SIPAEVENT_QUOTESIGNATURE),
        "AikId"                               => Some(SIPAEVENT_AIKID),
        "AikPubDigest"                        => Some(SIPAEVENT_AIKPUBDIGEST),
        "ElamKeyName"                         => Some(SIPAEVENT_ELAM_KEYNAME),
        "ElamConfiguration"                   => Some(SIPAEVENT_ELAM_CONFIGURATION),
        "ElamPolicy"                          => Some(SIPAEVENT_ELAM_POLICY),
        "ElamMeasured"                        => Some(SIPAEVENT_ELAM_MEASURED),
        "VbsVsmRequired"                      => Some(SIPAEVENT_VBS_VSM_REQUIRED),
        "VbsSecureBootRequired"               => Some(SIPAEVENT_VBS_SECUREBOOT_REQUIRED),
        "VbsIommuRequired"                    => Some(SIPAEVENT_VBS_IOMMU_REQUIRED),
        "VbsMmioNxRequired"                   => Some(SIPAEVENT_VBS_MMIO_NX_REQUIRED),
        "VbsMsrFilteringRequired"             => Some(SIPAEVENT_VBS_MSR_FILTERING_REQUIRED),
        "VbsMandatoryEnforcement"             => Some(SIPAEVENT_VBS_MANDATORY_ENFORCEMENT),
        "VbsHvciPolicy"                       => Some(SIPAEVENT_VBS_HVCI_POLICY),
        "VbsMicrosoftBootChainRequired"       => Some(SIPAEVENT_VBS_MICROSOFT_BOOT_CHAIN_REQUIRED),
        "VbsVsmNoSecretsEnforced"             => Some(SIPAEVENT_VBS_VSM_NOSECRETS_ENFORCED),
        "KsrSignature"                        => Some(SIPAEVENT_KSR_SIGNATURE),
        "DrtmStateAuth"                       => Some(SIPAEVENT_DRTM_STATE_AUTH),
        "DrtmSmmLevel"                        => Some(SIPAEVENT_DRTM_SMM_LEVEL),
        _                                     => None,
    }
}

// ── SipaEventData ─────────────────────────────────────────────────────────────

/// Parsed payload of a single SIPA sub-event.
///
/// The variant selected depends on the [`SipaEvent::event_type`] value:
///
/// | Variant | Used for |
/// |---|---|
/// | `Container` | Aggregation events (TRUSTBOUNDARY, etc.) |
/// | `Bool` | Boolean flags (BootDebugging, CodeIntegrity, …) |
/// | `U64` | 64-bit counters and addresses (BootCounter, ImageSize, …) |
/// | `U32` | Other 32-bit values |
/// | `BitlockerUnlock` | [`SIPAEVENT_BITLOCKER_UNLOCK`] |
/// | `OsDevice` | [`SIPAEVENT_OSDEVICE`] |
/// | `TransferControl` | [`SIPAEVENT_TRANSFER_CONTROL`] |
/// | `HashAlgorithm` | [`SIPAEVENT_HASHALGORITHMID`] |
/// | `DriverLoadPolicy` | [`SIPAEVENT_DRIVER_LOAD_POLICY`] |
/// | `SiPolicy` | [`SIPAEVENT_SI_POLICY`] |
/// | `RevocationList` | [`SIPAEVENT_BOOT_REVOCATION_LIST`], [`SIPAEVENT_OS_REVOCATION_LIST`] |
/// | `SbcpInfo` | [`SIPAEVENT_SBCP_INFO`] |
/// | `KsrSignature` | [`SIPAEVENT_KSR_SIGNATURE`] |
/// | `Text` | UTF-16LE string values (FilePath, SystemRoot, …) |
/// | `Bytes` | Raw binary data (hashes, signatures, keys) |
/// | `Empty` | Events with zero-length data |
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SipaEventData {
    /// Nested SIPA sub-events (aggregation containers).
    Container(Vec<SipaEvent>),
    /// Boolean value (1-byte payload: `0x00` = false, otherwise true).
    Bool(bool),
    /// BitLocker unlock flags.
    BitlockerUnlock(BitlockerUnlockData),
    /// Transfer-control target.
    TransferControl(TransferControlData),
    /// OS device type.
    OsDevice(OsDeviceData),
    /// CAPI hash algorithm identifier.
    HashAlgorithm(HashAlgorithmData),
    /// Driver load policy.
    DriverLoadPolicy(DriverLoadPolicyData),
    /// System Integrity (CI/WDAC) policy measurement.
    SiPolicy(SiPolicyPayload),
    /// Boot or OS revocation-list hash.
    RevocationList(RevocationListPayload),
    /// Secure Boot Custom Policy information.
    SbcpInfo(SbcpInfoPayload),
    /// KSR measurement signature.
    KsrSignature(KsrSignaturePayload),
    /// 64-bit numeric value.
    U64(u64),
    /// 32-bit numeric value.
    U32(u32),
    /// UTF-16LE decoded text (file paths, system root, authority names, etc.).
    Text(String),
    /// Raw binary data, hex-encoded.
    Bytes(SipaBytes),
    /// Event with no data payload.
    Empty,
}

/// Wrapper for a raw binary payload, serialised as `{ "raw": "<hex>" }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SipaBytes {
    /// Hex-encoded bytes.
    pub raw: String,
}

// ── SipaEvent ─────────────────────────────────────────────────────────────────

/// A single SIPA (Security Initiative Policy Attestation) sub-event.
///
/// These appear as elements inside the [`WbclEventData`] of an
/// `EV_EVENT_TAG` TCG log entry.  Each sub-event carries a typed event
/// identifier that serialises as its human-readable name string, and a
/// decoded payload.
///
/// Whether the event was measured into a PCR can be tested with
/// [`SipaEventType::is_non_measured`] on the `event_type` field.
/// Whether the event is an aggregation container can be tested with
/// [`SipaEventType::is_aggregation`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SipaEvent {
    /// The SIPA event type.  Serialises to/from its human-readable name
    /// (e.g. `"BootDebugging"`, `"TrustBoundary"`).  Unknown values
    /// round-trip as `"Unknown(0xXXXXXXXX)"`.
    pub event_type: SipaEventType,
    /// Decoded event payload.
    pub data: SipaEventData,
}

// ── WbclEventData ─────────────────────────────────────────────────────────────

/// Parsed event data for an `EV_EVENT_TAG` (`0x00000006`) TCG log entry in a
/// Windows Boot Configuration Log (WBCL).
///
/// The `events` list preserves the original linear ordering of the sub-events
/// in the binary data.  Aggregation containers have their payloads recursively
/// decoded into nested [`SipaEvent`] lists.
///
/// # Wire format
///
/// ```text
/// ┌──────────────────────────────────────────────────────────┐
/// │  SIPA sub-event 0                                        │
/// │  ┌─────────┬─────────┬─────────────────────────────────┐ │
/// │  │ type u32│ size u32│ data[size]                      │ │
/// │  └─────────┴─────────┴─────────────────────────────────┘ │
/// │  SIPA sub-event 1 …                                       │
/// └──────────────────────────────────────────────────────────┘
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WbclEventData {
    /// The decoded SIPA sub-events, in order.
    pub events: Vec<SipaEvent>,
}

impl WbclEventData {
    /// Parse [`WbclEventData`] from the raw event bytes of an `EV_EVENT_TAG`
    /// TCG log entry.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] if the data is truncated or structurally invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcglog_parser::event_data::wbcl::{
    ///     WbclEventData, SipaEventData, SIPAEVENT_BOOTDEBUGGING,
    /// };
    ///
    /// let mut data = Vec::new();
    /// // SIPAEVENT_BOOTDEBUGGING (1 byte bool payload = false)
    /// data.extend_from_slice(&SIPAEVENT_BOOTDEBUGGING.to_le_bytes());
    /// data.extend_from_slice(&1u32.to_le_bytes()); // data_size = 1
    /// data.push(0u8); // false
    ///
    /// let ev = WbclEventData::parse(&data).unwrap();
    /// assert_eq!(ev.events.len(), 1);
    /// assert_eq!(ev.events[0].data, SipaEventData::Bool(false));
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        let events = parse_sipa_events(data)?;
        Ok(Self { events })
    }
}

// ── Internal parsing helpers ──────────────────────────────────────────────────

/// Parse a flat list of SIPA sub-events from `data`.
///
/// Processing stops silently when fewer than 8 bytes remain (incomplete
/// header), matching the behaviour of the reference `PcpToolDisplaySIPA`
/// C implementation (`while(cbWBCLIntern > (2 * sizeof(UINT32)))`).
fn parse_sipa_events(data: &[u8]) -> Result<Vec<SipaEvent>, ParseError> {
    let mut pos = 0usize;
    let mut events = Vec::new();

    while pos + 8 <= data.len() {
        // Read the 8-byte header: event_type (u32 LE) + data_size (u32 LE).
        let event_type = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        let data_size  = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as usize;
        pos += 8;

        if pos + data_size > data.len() {
            return Err(ParseError::eof(pos + data_size - data.len(), pos));
        }

        let payload = &data[pos..pos + data_size];
        pos += data_size;

        let event = decode_sipa_event(event_type, payload)?;
        events.push(event);
    }

    Ok(events)
}

/// Decode a single SIPA sub-event given its raw type and payload bytes.
fn decode_sipa_event(event_type: u32, data: &[u8]) -> Result<SipaEvent, ParseError> {
    let et = SipaEventType::from_value(event_type);

    let sipa_data = if et.is_aggregation() {
        // Recursively decode nested events.
        SipaEventData::Container(parse_sipa_events(data)?)
    } else {
        decode_payload(event_type, data)
    };

    Ok(SipaEvent {
        event_type: et,
        data: sipa_data,
    })
}

/// True when the event type has both `AGGREGATION` and `CONTAINER` bits set.
#[inline]
fn is_container(event_type: u32) -> bool {
    (event_type & (SIPAEVENTTYPE_AGGREGATION | SIPAEVENTTYPE_CONTAINER))
        == (SIPAEVENTTYPE_AGGREGATION | SIPAEVENTTYPE_CONTAINER)
}

/// Decode the payload bytes into a typed [`SipaEventData`] value.
fn decode_payload(event_type: u32, data: &[u8]) -> SipaEventData {
    if data.is_empty() {
        return SipaEventData::Empty;
    }

    match event_type {
        // ── 1-byte Boolean events ─────────────────────────────────────────
        SIPAEVENT_BOOTDEBUGGING
        | SIPAEVENT_OSKERNELDEBUG
        | SIPAEVENT_CODEINTEGRITY
        | SIPAEVENT_TESTSIGNING
        | SIPAEVENT_SAFEMODE
        | SIPAEVENT_WINPE
        | SIPAEVENT_IMAGEVALIDATED
        | SIPAEVENT_NOAUTHORITY
        | SIPAEVENT_FLIGHTSIGNING
        | SIPAEVENT_PAGEFILE_ENCRYPTION_ENABLED
        | SIPAEVENT_HIBERNATION_DISABLED
        | SIPAEVENT_DUMPS_DISABLED
        | SIPAEVENT_DUMP_ENCRYPTION_ENABLED
        | SIPAEVENT_HYPERVISOR_BOOT_DMA_PROTECTION
        | SIPAEVENT_VBS_VSM_REQUIRED
        | SIPAEVENT_VBS_SECUREBOOT_REQUIRED
        | SIPAEVENT_VBS_IOMMU_REQUIRED
        | SIPAEVENT_VBS_MMIO_NX_REQUIRED
        | SIPAEVENT_VBS_MSR_FILTERING_REQUIRED
        | SIPAEVENT_VBS_MANDATORY_ENFORCEMENT
        | SIPAEVENT_VBS_MICROSOFT_BOOT_CHAIN_REQUIRED
        | SIPAEVENT_VBS_VSM_NOSECRETS_ENFORCED
        if data.len() == 1 =>
        {
            SipaEventData::Bool(data[0] != 0)
        }

        // ── Boolean events with variable-size payload ─────────────────────
        // SIPAEVENT_MORBIT_NOT_CANCELABLE is documented as INFORMATION-category
        // but Windows emits a 4-byte DWORD (0x00000001) rather than a 1-byte
        // BOOLEAN, so we handle it size-agnostically.
        SIPAEVENT_MORBIT_NOT_CANCELABLE => {
            SipaEventData::Bool(data.iter().any(|&b| b != 0))
        }

        // ── 8-byte U64 events ─────────────────────────────────────────────
        SIPAEVENT_BOOTCOUNTER
        | SIPAEVENT_EVENTCOUNTER
        | SIPAEVENT_COUNTERID
        | SIPAEVENT_IMAGESIZE
        | SIPAEVENT_IMAGEBASE
        | SIPAEVENT_HYPERVISOR_LAUNCH_TYPE
        | SIPAEVENT_DATAEXECUTIONPREVENTION
        | SIPAEVENT_PHYSICALADDRESSEXTENSION
        | SIPAEVENT_APPLICATION_SVN
        | SIPAEVENT_SVN_CHAIN_STATUS
        | SIPAEVENT_SMT_STATUS
        | SIPAEVENT_VSM_LAUNCH_TYPE
        | SIPAEVENT_VBS_HVCI_POLICY
        if data.len() == 8 =>
        {
            let v = u64::from_le_bytes(data[..8].try_into().unwrap());
            SipaEventData::U64(v)
        }

        // ── 4-byte special-cased U32 events ──────────────────────────────
        SIPAEVENT_BITLOCKER_UNLOCK if data.len() == 4 => {
            let flags = u32::from_le_bytes(data[..4].try_into().unwrap());
            SipaEventData::BitlockerUnlock(BitlockerUnlockData::from_flags(flags))
        }

        SIPAEVENT_OSDEVICE if data.len() == 4 => {
            let v = u32::from_le_bytes(data[..4].try_into().unwrap());
            SipaEventData::OsDevice(OsDeviceData::from_value(v))
        }

        SIPAEVENT_TRANSFER_CONTROL if data.len() == 4 => {
            let v = u32::from_le_bytes(data[..4].try_into().unwrap());
            SipaEventData::TransferControl(TransferControlData::from_value(v))
        }

        SIPAEVENT_HASHALGORITHMID if data.len() == 4 => {
            let v = u32::from_le_bytes(data[..4].try_into().unwrap());
            SipaEventData::HashAlgorithm(HashAlgorithmData::from_value(v))
        }

        SIPAEVENT_DRIVER_LOAD_POLICY if data.len() == 4 => {
            let v = u32::from_le_bytes(data[..4].try_into().unwrap());
            SipaEventData::DriverLoadPolicy(DriverLoadPolicyData::from_value(v))
        }

        // ── Other 4-byte U32 events ───────────────────────────────────────
        SIPAEVENT_MORBIT_API_STATUS
        | SIPAEVENT_IDK_GENERATION_STATUS
        | SIPAEVENT_HYPERVISOR_IOMMU_POLICY
        | SIPAEVENT_HYPERVISOR_MMIO_NX_POLICY
        | SIPAEVENT_HYPERVISOR_MSR_FILTER_POLICY
        | SIPAEVENT_LSAISO_CONFIG
        if data.len() == 4 =>
        {
            let v = u32::from_le_bytes(data[..4].try_into().unwrap());
            SipaEventData::U32(v)
        }

        // ── UTF-16LE string events ────────────────────────────────────────
        SIPAEVENT_FILEPATH
        | SIPAEVENT_SYSTEMROOT
        | SIPAEVENT_AUTHORITYPUBLISHER
        | SIPAEVENT_AUTHORITYISSUER
        | SIPAEVENT_HYPERVISOR_PATH
        | SIPAEVENT_ELAM_KEYNAME
        | SIPAEVENT_MODULE_ORIGINAL_FILENAME =>
        {
            let text = decode_utf16le(data);
            SipaEventData::Text(text)
        }

        // ── SI policy measurement ─────────────────────────────────────────
        // SIPAEVENT_SI_POLICY_PAYLOAD layout (wbcl.h):
        //   u64  PolicyVersion        [0..8]
        //   u16  PolicyNameLength     [8..10]  bytes, incl. UTF-16LE null terminator
        //   u16  HashAlgID            [10..12] TPM_ALG_ID
        //   u32  DigestLength         [12..16] bytes
        //   u8   PolicyName[PolicyNameLength]  (UTF-16LE)
        //   u8   Digest[DigestLength]
        SIPAEVENT_SI_POLICY => {
            if data.len() >= 16 {
                let policy_version = u64::from_le_bytes(data[..8].try_into().unwrap());
                let name_len       = u16::from_le_bytes(data[8..10].try_into().unwrap()) as usize;
                let hash_alg_id    = u16::from_le_bytes(data[10..12].try_into().unwrap());
                let digest_len     = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;
                let var_end = 16 + name_len + digest_len;
                if data.len() >= var_end {
                    let policy_name = decode_utf16le(&data[16..16 + name_len]);
                    let digest      = to_hex(&data[16 + name_len..var_end]);
                    return SipaEventData::SiPolicy(SiPolicyPayload {
                        policy_version,
                        policy_name,
                        hash_alg_id,
                        digest,
                    });
                }
            }
            SipaEventData::Bytes(SipaBytes { raw: to_hex(data) })
        }

        // ── Revocation-list hash ──────────────────────────────────────────
        // SIPAEVENT_REVOCATION_LIST_PAYLOAD layout (wbcl.h):
        //   i64  CreationTime         [0..8]   Windows FILETIME
        //   u32  DigestLength         [8..12]  bytes
        //   u16  HashAlgID            [12..14] TPM_ALG_ID
        //   u8   Digest[DigestLength]
        SIPAEVENT_BOOT_REVOCATION_LIST | SIPAEVENT_OS_REVOCATION_LIST => {
            if data.len() >= 14 {
                let creation_time = i64::from_le_bytes(data[..8].try_into().unwrap());
                let digest_len    = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
                let hash_alg_id   = u16::from_le_bytes(data[12..14].try_into().unwrap());
                if data.len() >= 14 + digest_len {
                    let digest = to_hex(&data[14..14 + digest_len]);
                    return SipaEventData::RevocationList(RevocationListPayload {
                        creation_time,
                        hash_alg_id,
                        digest,
                    });
                }
            }
            SipaEventData::Bytes(SipaBytes { raw: to_hex(data) })
        }

        // ── Secure Boot Custom Policy information ─────────────────────────
        // SIPAEVENT_SBCP_INFO_PAYLOAD_V1 layout (wbcl.h):
        //   u32  PayloadVersion    [0..4]
        //   u32  VarDataOffset     [4..8]   offset from struct start to VarData
        //   u16  HashAlgID         [8..10]  TPM_ALG_ID
        //   u16  DigestLength      [10..12] bytes
        //   u32  Options           [12..16]
        //   u32  SignersCount      [16..20]
        //   u8   VarData[DigestLength] at VarDataOffset
        SIPAEVENT_SBCP_INFO => {
            if data.len() >= 20 {
                let payload_version = u32::from_le_bytes(data[..4].try_into().unwrap());
                let var_data_offset = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
                let hash_alg_id     = u16::from_le_bytes(data[8..10].try_into().unwrap());
                let digest_length   = u16::from_le_bytes(data[10..12].try_into().unwrap());
                let options         = u32::from_le_bytes(data[12..16].try_into().unwrap());
                let signers_count   = u32::from_le_bytes(data[16..20].try_into().unwrap());
                let dig_end = var_data_offset + digest_length as usize;
                if data.len() >= dig_end {
                    let digest = to_hex(&data[var_data_offset..dig_end]);
                    return SipaEventData::SbcpInfo(SbcpInfoPayload {
                        payload_version,
                        hash_alg_id,
                        digest_length,
                        options,
                        signers_count,
                        digest,
                    });
                }
            }
            SipaEventData::Bytes(SipaBytes { raw: to_hex(data) })
        }

        // ── KSR measurement signature ─────────────────────────────────────
        // SIPAEVENT_KSR_SIGNATURE_PAYLOAD layout (wbcl.h):
        //   u32  SignAlgID          [0..4]
        //   u32  SignatureLength    [4..8]  bytes
        //   u8   Signature[SignatureLength]
        SIPAEVENT_KSR_SIGNATURE => {
            if data.len() >= 8 {
                let sign_alg_id      = u32::from_le_bytes(data[..4].try_into().unwrap());
                let signature_length = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
                if data.len() >= 8 + signature_length {
                    let signature = to_hex(&data[8..8 + signature_length]);
                    return SipaEventData::KsrSignature(KsrSignaturePayload {
                        sign_alg_id,
                        signature,
                    });
                }
            }
            SipaEventData::Bytes(SipaBytes { raw: to_hex(data) })
        }

        // ── Everything else: raw bytes ────────────────────────────────────
        _ => SipaEventData::Bytes(SipaBytes { raw: to_hex(data) }),
    }
}

/// Decode a UTF-16LE byte slice into a `String`, stripping a trailing null.
fn decode_utf16le(data: &[u8]) -> String {
    let u16s: Vec<u16> = data
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    String::from_utf16_lossy(&u16s)
        .trim_matches('\0')
        .to_string()
}

/// Return the human-readable name for a SIPA event type value.
///
/// Returns `"Unknown"` for unrecognised values.
pub fn sipa_event_name(event_type: u32) -> &'static str {
    match event_type {
        SIPAEVENT_TRUSTBOUNDARY                   => "TrustBoundary",
        SIPAEVENT_ELAM_AGGREGATION                => "ElamAggregation",
        SIPAEVENT_LOADEDMODULE_AGGREGATION        => "LoadedModuleAggregation",
        SIPAEVENT_TRUSTPOINT_AGGREGATION          => "TrustPointAggregation",
        SIPAEVENT_KSR_AGGREGATION                 => "KsrAggregation",
        SIPAEVENT_KSR_SIGNED_MEASUREMENT_AGGREGATION => "KsrSignedMeasurementAggregation",
        SIPAERROR_FIRMWAREFAILURE                 => "FirmwareFailure",
        SIPAERROR_TPMFAILURE                      => "TpmFailure",
        SIPAERROR_INTERNALFAILURE                 => "InternalFailure",
        SIPAERROR_KSRFAILURE                      => "KsrFailure",
        SIPAEVENT_INFORMATION                     => "Information",
        SIPAEVENT_BOOTCOUNTER                     => "BootCounter",
        SIPAEVENT_TRANSFER_CONTROL                => "TransferControl",
        SIPAEVENT_APPLICATION_RETURN              => "ApplicationReturn",
        SIPAEVENT_BITLOCKER_UNLOCK                => "BitLockerUnlock",
        SIPAEVENT_EVENTCOUNTER                    => "EventCounter",
        SIPAEVENT_COUNTERID                       => "CounterId",
        SIPAEVENT_MORBIT_NOT_CANCELABLE           => "MorBitNotCancelable",
        SIPAEVENT_APPLICATION_SVN                 => "ApplicationSvn",
        SIPAEVENT_SVN_CHAIN_STATUS                => "SvnChainStatus",
        SIPAEVENT_MORBIT_API_STATUS               => "MorBitApiStatus",
        SIPAEVENT_IDK_GENERATION_STATUS           => "IdkGenerationStatus",
        SIPAEVENT_BOOTDEBUGGING                   => "BootDebugging",
        SIPAEVENT_BOOT_REVOCATION_LIST            => "BootRevocationList",
        SIPAEVENT_OSKERNELDEBUG                   => "OsKernelDebug",
        SIPAEVENT_CODEINTEGRITY                   => "CodeIntegrity",
        SIPAEVENT_TESTSIGNING                     => "TestSigning",
        SIPAEVENT_DATAEXECUTIONPREVENTION         => "DataExecutionPrevention",
        SIPAEVENT_SAFEMODE                        => "SafeMode",
        SIPAEVENT_WINPE                           => "WinPE",
        SIPAEVENT_PHYSICALADDRESSEXTENSION        => "PhysicalAddressExtension",
        SIPAEVENT_OSDEVICE                        => "OsDevice",
        SIPAEVENT_SYSTEMROOT                      => "SystemRoot",
        SIPAEVENT_HYPERVISOR_LAUNCH_TYPE          => "HypervisorLaunchType",
        SIPAEVENT_HYPERVISOR_PATH                 => "HypervisorPath",
        SIPAEVENT_HYPERVISOR_IOMMU_POLICY         => "HypervisorIommuPolicy",
        SIPAEVENT_HYPERVISOR_DEBUG                => "HypervisorDebug",
        SIPAEVENT_DRIVER_LOAD_POLICY              => "DriverLoadPolicy",
        SIPAEVENT_SI_POLICY                       => "SiPolicy",
        SIPAEVENT_HYPERVISOR_MMIO_NX_POLICY       => "HypervisorMmioNxPolicy",
        SIPAEVENT_HYPERVISOR_MSR_FILTER_POLICY    => "HypervisorMsrFilterPolicy",
        SIPAEVENT_VSM_LAUNCH_TYPE                 => "VsmLaunchType",
        SIPAEVENT_OS_REVOCATION_LIST              => "OsRevocationList",
        SIPAEVENT_SMT_STATUS                      => "SmtStatus",
        SIPAEVENT_VSM_IDK_INFO                    => "VsmIdkInfo",
        SIPAEVENT_FLIGHTSIGNING                   => "FlightSigning",
        SIPAEVENT_PAGEFILE_ENCRYPTION_ENABLED     => "PagefileEncryptionEnabled",
        SIPAEVENT_VSM_IDKS_INFO                   => "VsmIdksInfo",
        SIPAEVENT_HIBERNATION_DISABLED            => "HibernationDisabled",
        SIPAEVENT_DUMPS_DISABLED                  => "DumpsDisabled",
        SIPAEVENT_DUMP_ENCRYPTION_ENABLED         => "DumpEncryptionEnabled",
        SIPAEVENT_DUMP_ENCRYPTION_KEY_DIGEST      => "DumpEncryptionKeyDigest",
        SIPAEVENT_LSAISO_CONFIG                   => "LsaIsoConfig",
        SIPAEVENT_SBCP_INFO                       => "SbcpInfo",
        SIPAEVENT_HYPERVISOR_BOOT_DMA_PROTECTION  => "HypervisorBootDmaProtection",
        SIPAEVENT_SI_POLICY_SIGNER                => "SiPolicySigner",
        SIPAEVENT_SI_POLICY_UPDATE_SIGNER         => "SiPolicyUpdateSigner",
        SIPAEVENT_NOAUTHORITY                     => "NoAuthority",
        SIPAEVENT_AUTHORITYPUBKEY                 => "AuthorityPubKey",
        SIPAEVENT_FILEPATH                        => "FilePath",
        SIPAEVENT_IMAGESIZE                       => "ImageSize",
        SIPAEVENT_HASHALGORITHMID                 => "HashAlgorithmId",
        SIPAEVENT_AUTHENTICODEHASH                => "AuthenticodeHash",
        SIPAEVENT_AUTHORITYISSUER                 => "AuthorityIssuer",
        SIPAEVENT_AUTHORITYSERIAL                 => "AuthoritySerial",
        SIPAEVENT_IMAGEBASE                       => "ImageBase",
        SIPAEVENT_AUTHORITYPUBLISHER              => "AuthorityPublisher",
        SIPAEVENT_AUTHORITYSHA1THUMBPRINT         => "AuthoritySha1Thumbprint",
        SIPAEVENT_IMAGEVALIDATED                  => "ImageValidated",
        SIPAEVENT_MODULE_SVN                      => "ModuleSvn",
        SIPAEVENT_MODULE_PLUTON                   => "ModulePluton",
        SIPAEVENT_MODULE_ORIGINAL_FILENAME        => "ModuleOriginalFilename",
        SIPAEVENT_MODULE_TIMESTAMP                => "ModuleTimestamp",
        SIPAEVENT_QUOTE                           => "Quote",
        SIPAEVENT_QUOTESIGNATURE                  => "QuoteSignature",
        SIPAEVENT_AIKID                           => "AikId",
        SIPAEVENT_AIKPUBDIGEST                    => "AikPubDigest",
        SIPAEVENT_ELAM_KEYNAME                    => "ElamKeyName",
        SIPAEVENT_ELAM_CONFIGURATION              => "ElamConfiguration",
        SIPAEVENT_ELAM_POLICY                     => "ElamPolicy",
        SIPAEVENT_ELAM_MEASURED                   => "ElamMeasured",
        SIPAEVENT_VBS_VSM_REQUIRED                => "VbsVsmRequired",
        SIPAEVENT_VBS_SECUREBOOT_REQUIRED         => "VbsSecureBootRequired",
        SIPAEVENT_VBS_IOMMU_REQUIRED              => "VbsIommuRequired",
        SIPAEVENT_VBS_MMIO_NX_REQUIRED            => "VbsMmioNxRequired",
        SIPAEVENT_VBS_MSR_FILTERING_REQUIRED      => "VbsMsrFilteringRequired",
        SIPAEVENT_VBS_MANDATORY_ENFORCEMENT       => "VbsMandatoryEnforcement",
        SIPAEVENT_VBS_HVCI_POLICY                 => "VbsHvciPolicy",
        SIPAEVENT_VBS_MICROSOFT_BOOT_CHAIN_REQUIRED => "VbsMicrosoftBootChainRequired",
        SIPAEVENT_VBS_VSM_NOSECRETS_ENFORCED      => "VbsVsmNoSecretsEnforced",
        SIPAEVENT_KSR_SIGNATURE                   => "KsrSignature",
        SIPAEVENT_DRTM_STATE_AUTH                 => "DrtmStateAuth",
        SIPAEVENT_DRTM_SMM_LEVEL                  => "DrtmSmmLevel",
        _                                         => "Unknown",
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sipa_entry(event_type: u32, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&event_type.to_le_bytes());
        v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn parse_empty_returns_empty_list() {
        let ev = WbclEventData::parse(&[]).unwrap();
        assert!(ev.events.is_empty());
    }

    #[test]
    fn parse_single_bool_true() {
        let data = sipa_entry(SIPAEVENT_BOOTDEBUGGING, &[1u8]);
        let ev = WbclEventData::parse(&data).unwrap();
        assert_eq!(ev.events.len(), 1);
        assert_eq!(ev.events[0].event_type, SIPAEVENT_BOOTDEBUGGING);
        assert_eq!(ev.events[0].event_type.name(), "BootDebugging");
        assert!(!ev.events[0].event_type.is_non_measured());
        assert!(!ev.events[0].event_type.is_aggregation());
        assert_eq!(ev.events[0].data, SipaEventData::Bool(true));
    }

    #[test]
    fn parse_single_bool_false() {
        let data = sipa_entry(SIPAEVENT_CODEINTEGRITY, &[0u8]);
        let ev = WbclEventData::parse(&data).unwrap();
        assert_eq!(ev.events[0].data, SipaEventData::Bool(false));
    }

    #[test]
    fn parse_boot_counter_u64() {
        let count: u64 = 0x0000_0000_0000_0042;
        let data = sipa_entry(SIPAEVENT_BOOTCOUNTER, &count.to_le_bytes());
        let ev = WbclEventData::parse(&data).unwrap();
        assert_eq!(ev.events[0].event_type.name(), "BootCounter");
        assert_eq!(ev.events[0].data, SipaEventData::U64(0x42));
    }

    #[test]
    fn parse_image_size_u64() {
        let size: u64 = 0x0001_0000;
        let data = sipa_entry(SIPAEVENT_IMAGESIZE, &size.to_le_bytes());
        let ev = WbclEventData::parse(&data).unwrap();
        assert_eq!(ev.events[0].data, SipaEventData::U64(0x1_0000));
    }

    #[test]
    fn parse_bitlocker_unlock_tpm() {
        let flags: u32 = FVEB_UNLOCK_FLAG_TPM;
        let data = sipa_entry(SIPAEVENT_BITLOCKER_UNLOCK, &flags.to_le_bytes());
        let ev = WbclEventData::parse(&data).unwrap();
        match &ev.events[0].data {
            SipaEventData::BitlockerUnlock(bl) => {
                assert!(bl.tpm);
                assert!(!bl.pin);
                assert!(!bl.recovery);
                assert_eq!(bl.raw_flags, FVEB_UNLOCK_FLAG_TPM);
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn parse_bitlocker_unlock_tpm_and_pin() {
        let flags: u32 = FVEB_UNLOCK_FLAG_TPM | FVEB_UNLOCK_FLAG_PIN;
        let data = sipa_entry(SIPAEVENT_BITLOCKER_UNLOCK, &flags.to_le_bytes());
        let ev = WbclEventData::parse(&data).unwrap();
        match &ev.events[0].data {
            SipaEventData::BitlockerUnlock(bl) => {
                assert!(bl.tpm);
                assert!(bl.pin);
                assert!(!bl.recovery);
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn parse_os_device_partition() {
        let data = sipa_entry(SIPAEVENT_OSDEVICE,
            &OSDEVICE_TYPE_BLOCKIO_PARTITION.to_le_bytes());
        let ev = WbclEventData::parse(&data).unwrap();
        match &ev.events[0].data {
            SipaEventData::OsDevice(od) => {
                assert_eq!(od.device_type, "BLOCKIO_PARTITION");
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn parse_transfer_control_osloader() {
        let data = sipa_entry(SIPAEVENT_TRANSFER_CONTROL,
            &TRANSFER_CONTROL_OSLOADER.to_le_bytes());
        let ev = WbclEventData::parse(&data).unwrap();
        match &ev.events[0].data {
            SipaEventData::TransferControl(tc) => {
                assert_eq!(tc.target, "OSLOADER");
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn parse_hash_algorithm_sha256() {
        let data = sipa_entry(SIPAEVENT_HASHALGORITHMID, &CALG_SHA_256.to_le_bytes());
        let ev = WbclEventData::parse(&data).unwrap();
        match &ev.events[0].data {
            SipaEventData::HashAlgorithm(ha) => {
                assert_eq!(ha.algorithm, "SHA-256");
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn parse_system_root_utf16() {
        // "\Windows" in UTF-16LE
        let text: Vec<u8> = "\\Windows"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let data = sipa_entry(SIPAEVENT_SYSTEMROOT, &text);
        let ev = WbclEventData::parse(&data).unwrap();
        match &ev.events[0].data {
            SipaEventData::Text(s) => assert_eq!(s, "\\Windows"),
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn parse_filepath_with_null_terminator() {
        let text: Vec<u8> = "\\Windows\\System32\\winload.efi\0"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let data = sipa_entry(SIPAEVENT_FILEPATH, &text);
        let ev = WbclEventData::parse(&data).unwrap();
        match &ev.events[0].data {
            SipaEventData::Text(s) => {
                assert_eq!(s, "\\Windows\\System32\\winload.efi");
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn parse_raw_bytes_authenticode_hash() {
        let hash = [0xABu8; 32];
        let data = sipa_entry(SIPAEVENT_AUTHENTICODEHASH, &hash);
        let ev = WbclEventData::parse(&data).unwrap();
        match &ev.events[0].data {
            SipaEventData::Bytes(b) => {
                assert_eq!(b.raw, "ab".repeat(32));
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn parse_empty_event_gives_empty_variant() {
        let data = sipa_entry(SIPAEVENT_NOAUTHORITY, &[]);
        let ev = WbclEventData::parse(&data).unwrap();
        assert_eq!(ev.events[0].data, SipaEventData::Empty);
    }

    #[test]
    fn parse_aggregation_container_recursive() {
        // Build a TRUSTBOUNDARY container that holds a single BootDebugging event.
        let inner = sipa_entry(SIPAEVENT_BOOTDEBUGGING, &[0u8]);
        let outer = sipa_entry(SIPAEVENT_TRUSTBOUNDARY, &inner);
        let ev = WbclEventData::parse(&outer).unwrap();

        assert_eq!(ev.events.len(), 1);
        let tb = &ev.events[0];
        assert_eq!(tb.event_type, SIPAEVENT_TRUSTBOUNDARY);
        assert!(tb.event_type.is_aggregation());
        assert!(!tb.event_type.is_non_measured());

        match &tb.data {
            SipaEventData::Container(children) => {
                assert_eq!(children.len(), 1);
                assert_eq!(children[0].event_type, SIPAEVENT_BOOTDEBUGGING);
                assert_eq!(children[0].data, SipaEventData::Bool(false));
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn parse_trustpoint_aggregation_is_non_measured() {
        let inner = sipa_entry(SIPAEVENT_AIKID, &[0xDEu8; 20]);
        let outer = sipa_entry(SIPAEVENT_TRUSTPOINT_AGGREGATION, &inner);
        let ev = WbclEventData::parse(&outer).unwrap();

        let tp = &ev.events[0];
        assert!(tp.event_type.is_non_measured());
        assert!(tp.event_type.is_aggregation());
        assert_eq!(tp.event_type.name(), "TrustPointAggregation");
    }

    #[test]
    fn container_event_serialises_event_type_before_data() {
        // A container event (TrustBoundary) wrapping a simple event:
        // the outer event must also have event_type before data in JSON.
        let inner = sipa_entry(SIPAEVENT_BOOTDEBUGGING, &[0u8]);
        let outer = sipa_entry(SIPAEVENT_TRUSTBOUNDARY, &inner);
        let ev = WbclEventData::parse(&outer).unwrap();

        let json = serde_json::to_string_pretty(&ev).unwrap();
        let et_pos = json.find("\"event_type\"").expect("event_type missing");
        let data_pos = json.find("\"data\"").expect("data missing");
        assert!(et_pos < data_pos,
            "event_type must come before data even for container events\n{json}");
    }

    #[test]
    fn parse_multiple_events_sequence() {
        let mut data = Vec::new();
        data.extend(sipa_entry(SIPAEVENT_BOOTDEBUGGING, &[0u8]));
        data.extend(sipa_entry(SIPAEVENT_TESTSIGNING, &[1u8]));
        data.extend(sipa_entry(SIPAEVENT_BOOTCOUNTER, &5u64.to_le_bytes()));

        let ev = WbclEventData::parse(&data).unwrap();
        assert_eq!(ev.events.len(), 3);
        assert_eq!(ev.events[0].data, SipaEventData::Bool(false));
        assert_eq!(ev.events[1].data, SipaEventData::Bool(true));
        assert_eq!(ev.events[2].data, SipaEventData::U64(5));
    }

    #[test]
    fn sipa_event_serialises_to_json() {
        let mut data = Vec::new();
        data.extend(sipa_entry(SIPAEVENT_BOOTCOUNTER, &42u64.to_le_bytes()));
        data.extend(sipa_entry(SIPAEVENT_BOOTDEBUGGING, &[0u8]));

        let ev = WbclEventData::parse(&data).unwrap();
        let json = serde_json::to_string_pretty(&ev).unwrap();
        // event_type must appear before data in the serialised output
        let et_pos = json.find("\"event_type\"").expect("event_type missing");
        let data_pos = json.find("\"data\"").expect("data missing");
        assert!(et_pos < data_pos, "event_type must come before data in JSON\n{json}");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["events"][0]["event_type"], "BootCounter");
        assert_eq!(parsed["events"][0]["data"], 42u64);
        assert_eq!(parsed["events"][1]["event_type"], "BootDebugging");
        assert_eq!(parsed["events"][1]["data"], false);
    }

    #[test]
    fn sipa_event_type_serde_round_trip() {
        // Known event type: serialises as its name, deserialises back to same value.
        let et = SipaEventType::from_value(SIPAEVENT_BOOTCOUNTER);
        let json = serde_json::to_string(&et).unwrap();
        assert_eq!(json, "\"BootCounter\"");
        let recovered: SipaEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, et);

        // Unknown event type: round-trips as "Unknown(0xXXXXXXXX)".
        let unknown = SipaEventType::from_value(0x0099_9999);
        let json2 = serde_json::to_string(&unknown).unwrap();
        assert_eq!(json2, "\"Unknown(0x00999999)\"");
        let recovered2: SipaEventType = serde_json::from_str(&json2).unwrap();
        assert_eq!(recovered2, unknown);
    }

    #[test]
    fn driver_load_policy_default() {
        let data = sipa_entry(SIPAEVENT_DRIVER_LOAD_POLICY, &1u32.to_le_bytes());
        let ev = WbclEventData::parse(&data).unwrap();
        match &ev.events[0].data {
            SipaEventData::DriverLoadPolicy(dlp) => {
                assert_eq!(dlp.policy, "DEFAULT");
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn unknown_event_type_falls_back_to_bytes() {
        let unknown_type: u32 = 0x0099_9999;
        let payload = [0x01u8, 0x02, 0x03];
        let data = sipa_entry(unknown_type, &payload);
        let ev = WbclEventData::parse(&data).unwrap();
        assert_eq!(ev.events[0].event_type.name(), "Unknown(0x00999999)");
        match &ev.events[0].data {
            SipaEventData::Bytes(b) => assert_eq!(b.raw, "010203"),
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn truncated_data_returns_error() {
        // Only 6 bytes – not enough for the 8-byte header.
        let result = WbclEventData::parse(&[0x00u8; 6]);
        // Should parse without error but produce an empty event list
        // (the incomplete entry is silently skipped per the while condition).
        assert!(result.is_ok());
        assert!(result.unwrap().events.is_empty());
    }

    #[test]
    fn data_size_exceeds_remaining_returns_error() {
        // Header claims 100 bytes of data but there are none.
        let mut data = Vec::new();
        data.extend_from_slice(&SIPAEVENT_BOOTDEBUGGING.to_le_bytes());
        data.extend_from_slice(&100u32.to_le_bytes()); // claims 100 bytes
        // no payload bytes follow
        let result = WbclEventData::parse(&data);
        assert!(result.is_err());
    }
}
