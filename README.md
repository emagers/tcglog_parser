# tcglog_parser

A Rust library for parsing **TCG (Trusted Computing Group) TPM event logs** into typed Rust structures with JSON serialization support.

## Overview

`tcglog_parser` reads binary TPM event logs and produces structured, serializable Rust types. It supports:

- **TCG 1.2** (SHA-1 only) event logs — the legacy format used by older BIOS/firmware
- **TCG 2.0 crypto-agile** event logs — the modern UEFI format supporting multiple hash algorithms simultaneously (SHA-1, SHA-256, SHA-384, SHA-512, SM3-256, SHA3-256, SHA3-384, SHA3-512)

The implementation follows the [TCG PC Client Platform Firmware Profile Specification](https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/) (TCG PFP) and the [TCG Algorithm Registry](https://trustedcomputinggroup.org/resource/tcg-algorithm-registry/).

## Features

- **Automatic format detection** — detects TCG 1.2 vs 2.0 from the SpecID header
- **Full event parsing** — built-in parsers for all standard UEFI event data types
- **PCR emulation** — computes final PCR values by replaying all events through `PCR_new = H(PCR_old || digest)`
- **Spec compliance warnings** — detects non-fatal anomalies (post-cap measurements, duplicate separators, suspicious digests, etc.)
- **JSON serialization** — all types implement `serde::Serialize` and `serde::Deserialize`
- **Extensible** — register custom event-data parsers for vendor or future event types

## Installation

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
tcglog_parser = "0.1"
```

## Quick Start

```rust
use tcglog_parser::TcgLogParser;

// Read a raw event log from a file (e.g. /sys/kernel/security/tpm0/binary_bios_measurements).
let raw = std::fs::read("/sys/kernel/security/tpm0/binary_bios_measurements")
    .expect("failed to read TPM event log");

// Parse the log.
let log = TcgLogParser::new().parse(&raw).unwrap();

// Access structured fields.
if let Some(ref spec) = log.spec_id {
    println!("TCG spec version {}.{}", spec.spec_version_major, spec.spec_version_minor);
    for alg in &spec.algorithms {
        println!("  algorithm {:#06x}, digest {} bytes", alg.algorithm_id, alg.digest_size);
    }
}

// Iterate over crypto-agile events (TCG 2.0).
for ev in &log.events {
    println!("PCR[{}] {:?}", ev.pcr_index, ev.event_type);
}

// Or iterate over legacy events (TCG 1.2-only logs).
for ev in &log.legacy_events {
    println!("PCR[{}] type={} sha1={}", ev.pcr_index, ev.event_type, ev.sha1_digest);
}

// Serialize the entire log to JSON.
let json = serde_json::to_string_pretty(&log).unwrap();
println!("{json}");
```

## Parsed Log Structure

The `TcgLog` struct returned by `parse()` contains:

| Field | Type | Description |
|---|---|---|
| `header` | `TcgPcrEvent` | First event (always TCG 1.2 format) |
| `spec_id` | `Option<SpecIdEvent>` | Parsed SpecID header (`None` for TCG 1.2-only logs) |
| `events` | `Vec<TcgPcrEvent2>` | TCG 2.0 crypto-agile events (empty for 1.2-only logs) |
| `legacy_events` | `Vec<TcgPcrEvent>` | TCG 1.2 events after header (empty for 2.0 logs) |
| `pcr_tables` | `Vec<PcrBank>` | Emulated PCR values per algorithm |

## Built-in Event Parsers

The following event types are parsed into structured data automatically:

| Event Type | Parsed Structure | Description |
|---|---|---|
| `EV_NO_ACTION` | `SpecIdEvent` / `StartupLocality` | Log header and TPM startup locality |
| `EV_EFI_VARIABLE_DRIVER_CONFIG` | `UefiVariableData` | EFI variable configuration |
| `EV_EFI_VARIABLE_BOOT` | `UefiVariableData` | EFI boot variable |
| `EV_EFI_VARIABLE_BOOT2` | `UefiVariableData` | EFI boot variable v2 |
| `EV_EFI_VARIABLE_AUTHORITY` | `UefiVariableData` | EFI variable authority |
| `EV_EFI_BOOT_SERVICES_APPLICATION` | `UefiImageLoadEvent` | EFI application image load |
| `EV_EFI_BOOT_SERVICES_DRIVER` | `UefiImageLoadEvent` | EFI driver image load |
| `EV_EFI_RUNTIME_SERVICES_DRIVER` | `UefiImageLoadEvent` | EFI runtime driver image load |
| `EV_EFI_PLATFORM_FIRMWARE_BLOB` | `UefiFirmwareBlob` | Firmware blob measurement |
| `EV_EFI_PLATFORM_FIRMWARE_BLOB2` | `UefiFirmwareBlob2` | Firmware blob v2 (with description) |
| `EV_EFI_HANDOFF_TABLES` | `UefiHandoffTables` | EFI handoff table pointers |
| `EV_EFI_HANDOFF_TABLES2` | `UefiHandoffTables2` | Handoff tables v2 (with description) |
| `EV_EFI_ACTION` / `EV_ACTION` | JSON `{ "action": "..." }` | Action strings |
| `EV_S_CRTM_VERSION` | JSON `{ "version": "..." }` | S-CRTM version (UTF-16LE) |
| `EV_SEPARATOR` | JSON `{ "value": N }` | Separator sentinel value |
| `EV_POST_CODE` | JSON `{ "post_code": "..." }` | POST code string |

All other event types produce `{ "raw": "<hex>" }` with hex-encoded event data.

## Extending with Custom Parsers

To parse proprietary or vendor-specific event types, implement the `EventDataParser` trait and register it with the parser. Custom parsers are tried **before** built-in ones, so you can also override built-in behavior.

### Step 1: Implement `EventDataParser`

```rust
use tcglog_parser::{EventDataParser, ParseError};

/// A parser for a hypothetical vendor event type.
struct VendorParser;

impl EventDataParser for VendorParser {
    /// Return `true` for event types this parser handles.
    fn can_parse(&self, event_type: u32) -> bool {
        event_type == 0xA0000001
    }

    /// Parse the raw event data bytes into a JSON value.
    fn parse(
        &self,
        _event_type: u32,
        data: &[u8],
    ) -> Result<serde_json::Value, ParseError> {
        // Example: interpret the payload as a UTF-8 string.
        let text = String::from_utf8_lossy(data).into_owned();
        Ok(serde_json::json!({ "vendor_message": text }))
    }
}
```

### Step 2: Register and Parse

```rust
use tcglog_parser::TcgLogParser;

let log = TcgLogParser::new()
    .with_parser(Box::new(VendorParser))  // register before parsing
    .parse(&raw_bytes)
    .unwrap();

// Custom event data appears in the JSON output.
let json = serde_json::to_string_pretty(&log).unwrap();
```

### Key Points for Custom Parsers

- **`can_parse(event_type: u32) -> bool`** — receives the raw numeric event type value. Return `true` for any types you handle.
- **`parse(event_type: u32, data: &[u8]) -> Result<serde_json::Value, ParseError>`** — receives the raw event data bytes. Return any `serde_json::Value` — it will be embedded verbatim in the `event_data` field.
- **Error handling** — return `ParseError::CustomParser { event_type, message }` for parse failures. If a custom parser returns an error, the library falls back to built-in parsers.
- **Precedence** — custom parsers are tried in registration order, before built-in parsers. The first matching parser wins.
- **Thread safety** — parsers must be `Send + Sync` (i.e. safe to share across threads).

## PCR Emulation

The library emulates TPM PCR extension for all algorithms declared in the SpecID header. After parsing, `TcgLog::pcr_tables` contains one `PcrBank` per algorithm with the final computed PCR values.

### PCR Initial Values

Per TCG PFP §3.3.2:

| Startup Locality | PCR 0 | PCRs 1–23 |
|---|---|---|
| 0 (normal firmware) | All `0x00` | All `0x00` |
| 3 or 4 (H-CRTM) | All `0xFF` | All `0x00` |

The `StartupLocality` event (if present) determines the initial PCR 0 value.

### Supported Hash Algorithms for PCR Emulation

PCR extension is supported for SHA-1, SHA-256, SHA-384, and SHA-512. SM3-256 and SHA3 variants are recognized but cannot be emulated (no hash implementation provided). Unknown algorithms are skipped during extension.

## JSON Output Format

All types implement `serde::Serialize` and `serde::Deserialize`. Encoding conventions:

| Field Type | JSON Encoding |
|---|---|
| Binary digest / raw bytes | Lowercase hexadecimal string |
| `HashAlgorithmId` | String name (e.g. `"sha256"`, `"sha3_256"`) |
| `EventType` | String name (e.g. `"EV_NO_ACTION"`, `"EV_EFI_VARIABLE_BOOT2"`) |
| UEFI `Guid` | `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` string |
| Custom event data | Embedded as-is (any valid JSON value) |

## Spec Compliance Warnings

Non-fatal anomalies are collected in `TcgPcrEvent2::warnings`. Each warning indicates a deviation from the TCG spec:

| Warning | Meaning |
|---|---|
| `PostCapMeasurement` | Event extends a PCR that was already capped by `EV_SEPARATOR` |
| `DuplicateSeparator` | Multiple `EV_SEPARATOR` events for the same PCR |
| `ErrorSeparator` | Separator data is `0xFFFFFFFF` (firmware error) |
| `SuspiciousSeparatorDigest` | Non-separator event carries a separator-valued digest |
| `NonZeroNoActionDigest` | `EV_NO_ACTION` event has non-zero digest (spec requires all-zero) |
| `InvalidPcrIndex` | PCR index > 23 |
| `DigestCountMismatch` | Number of digests doesn't match SpecID algorithm count |

## Supported Event Types

All event types from the TCG PC Client Platform Firmware Profile Specification are recognized:

**Standard (0x00–0x12):** `EV_PREBOOT_CERT`, `EV_POST_CODE`, `EV_UNUSED`, `EV_NO_ACTION`, `EV_SEPARATOR`, `EV_ACTION`, `EV_EVENT_TAG`, `EV_S_CRTM_CONTENTS`, `EV_S_CRTM_VERSION`, `EV_CPU_MICROCODE`, `EV_PLATFORM_CONFIG_FLAGS`, `EV_TABLE_OF_DEVICES`, `EV_COMPACT_HASH`, `EV_IPL`, `EV_IPL_PARTITION_DATA`, `EV_NONHOST_CODE`, `EV_NONHOST_CONFIG`, `EV_NONHOST_INFO`, `EV_OMIT_BOOT_DEVICE_EVENTS`

**EFI (0x80000001–0x80000010):** `EV_EFI_VARIABLE_DRIVER_CONFIG`, `EV_EFI_VARIABLE_BOOT`, `EV_EFI_BOOT_SERVICES_APPLICATION`, `EV_EFI_BOOT_SERVICES_DRIVER`, `EV_EFI_RUNTIME_SERVICES_DRIVER`, `EV_EFI_GPT_EVENT`, `EV_EFI_ACTION`, `EV_EFI_PLATFORM_FIRMWARE_BLOB`, `EV_EFI_HANDOFF_TABLES`, `EV_EFI_PLATFORM_FIRMWARE_BLOB2`, `EV_EFI_HANDOFF_TABLES2`, `EV_EFI_VARIABLE_BOOT2`, `EV_EFI_HCRTM_EVENT`

**EFI Extended (0x800000E0–0x800000E2):** `EV_EFI_VARIABLE_AUTHORITY`, `EV_EFI_SPDM_FIRMWARE_BLOB`, `EV_EFI_SPDM_FIRMWARE_CONFIG`

Unknown event types are preserved as `EventType::Unknown(value)`.

## Supported Hash Algorithms

| Algorithm | ID | Digest Size | PCR Emulation |
|---|---|---|---|
| SHA-1 | `0x0004` | 20 bytes | ✓ |
| SHA-256 | `0x000B` | 32 bytes | ✓ |
| SHA-384 | `0x000C` | 48 bytes | ✓ |
| SHA-512 | `0x000D` | 64 bytes | ✓ |
| SM3-256 | `0x0012` | 32 bytes | ✗ |
| SHA3-256 | `0x0027` | 32 bytes | ✗ |
| SHA3-384 | `0x0028` | 48 bytes | ✗ |
| SHA3-512 | `0x0029` | 64 bytes | ✗ |

Unknown algorithm IDs are preserved as `HashAlgorithmId::Unknown(id)`.

## Test Fixtures

The library provides public test fixture builders for integration testing:

```rust
use tcglog_parser::tests;

// Minimal TCG 2.0 log with SpecID + StartupLocality.
let raw = tests::minimal_tcg2_log();

// Log with an EFI variable event.
let raw = tests::tcg2_log_with_efi_variable();

// Log with a firmware blob event.
let raw = tests::tcg2_log_with_firmware_blob();

// Log with a specific startup locality (0, 1, 2, 3, or 4).
let raw = tests::tcg2_log_with_locality(3);
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
