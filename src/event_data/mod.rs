//! Parsed event-data structures for known TCG event types.
//!
//! Each structure corresponds to the `Event` field of a [`TcgPcrEvent`](crate::TcgPcrEvent)
//! or [`TcgPcrEvent2`](crate::TcgPcrEvent2) entry.  The library automatically
//! selects the correct parser based on the event type; callers typically do not
//! need to use these types directly.

pub mod wbcl;
pub use wbcl::WbclEventData;

use crate::error::{Cursor, ParseError};
use crate::types::{Guid, to_hex};
use serde::{Deserialize, Serialize};
use sha1::Digest as Sha1Digest;

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

// ── Certificate info (decoded from DER X.509) ─────────────────────────────────

/// Decoded X.509 certificate information extracted from a DER-encoded cert.
///
/// Attached as an optional field to [`UefiVariableData`] when the
/// `variable_data` bytes (after the 16-byte `SignatureOwner` GUID prefix)
/// contain a valid DER-encoded X.509 certificate.  This is the case for
/// `EV_EFI_VARIABLE_AUTHORITY` events (Secure Boot `db`/`KEK` measurements).
///
/// For all other UEFI variable events the field is `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateInfo {
    /// Subject Distinguished Name in RFC 4514 string form.
    /// Example: `"CN=Microsoft Windows, O=Microsoft Corporation, C=US"`.
    pub subject: String,
    /// Issuer Distinguished Name in RFC 4514 string form.
    /// Example: `"CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, C=US"`.
    pub issuer: String,
    /// Hex-encoded certificate serial number (big-endian bytes).
    pub serial_number: String,
    /// Validity start as a UTC timestamp string.
    pub not_before: String,
    /// Validity end as a UTC timestamp string.
    pub not_after: String,
    /// SHA-1 thumbprint (fingerprint) of the raw DER certificate bytes,
    /// hex-encoded.  Matches the Windows "Thumbprint" field in Certificate
    /// Manager.
    pub thumbprint_sha1: String,
}

/// Try to decode a DER-encoded X.509 certificate into a [`CertificateInfo`].
///
/// Uses a minimal inline DER walker that extracts only the fields we need
/// (serial, issuer, validity, subject) from the TBSCertificate, skipping
/// extensions, public key, and signature parsing entirely.  This is
/// dramatically faster than a full ASN.1/X.509 library.
///
/// Returns `None` if `der` is not a valid DER X.509 certificate.
fn try_decode_x509(der: &[u8]) -> Option<CertificateInfo> {
    // ── Minimal DER helpers ──────────────────────────────────────────────

    /// Read a DER tag + length at `pos`, returning `(content_start, content_len)`.
    /// Returns `None` on truncation.
    fn read_tl(data: &[u8], pos: usize) -> Option<(usize, usize)> {
        if pos >= data.len() { return None; }
        let _tag = data[pos];
        let mut p = pos + 1;
        if p >= data.len() { return None; }
        let len_byte = data[p];
        p += 1;
        let len = if len_byte < 0x80 {
            len_byte as usize
        } else {
            let n = (len_byte & 0x7F) as usize;
            if n == 0 || n > 4 || p + n > data.len() { return None; }
            let mut v = 0usize;
            for i in 0..n { v = (v << 8) | data[p + i] as usize; }
            p += n;
            v
        };
        if p + len > data.len() { return None; }
        Some((p, len))
    }

    /// Skip one DER TLV element starting at `pos`, returning the position
    /// after its content.
    fn skip_tlv(data: &[u8], pos: usize) -> Option<usize> {
        let (start, len) = read_tl(data, pos)?;
        Some(start + len)
    }

    /// Decode a DER `Name` (SEQUENCE OF SET OF SEQUENCE { OID, value })
    /// into an RFC 4514-ish string like `"C=US, ST=Washington, CN=Foo"`.
    fn decode_name(data: &[u8]) -> String {
        // Well-known OID bytes → abbreviation.
        // These are the encoded OID *content* bytes (without tag+length).
        fn oid_abbrev(oid: &[u8]) -> Option<&'static str> {
            match oid {
                [0x55, 0x04, 0x03] => Some("CN"),
                [0x55, 0x04, 0x06] => Some("C"),
                [0x55, 0x04, 0x07] => Some("L"),
                [0x55, 0x04, 0x08] => Some("ST"),
                [0x55, 0x04, 0x0A] => Some("O"),
                [0x55, 0x04, 0x0B] => Some("OU"),
                [0x55, 0x04, 0x05] => Some("serialNumber"),
                // emailAddress: 1.2.840.113549.1.9.1
                [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01] => Some("emailAddress"),
                _ => None,
            }
        }

        let mut parts: Vec<String> = Vec::new();
        // Iterate SET OF inside the outer SEQUENCE.
        let (mut rdn_pos, name_end) = match read_tl(data, 0) {
            Some((s, l)) => (s, s + l),
            None => return String::new(),
        };
        while rdn_pos < name_end {
            // Each RDN is a SET.
            let (set_start, set_len) = match read_tl(data, rdn_pos) {
                Some(v) => v,
                None => break,
            };
            let set_end = set_start + set_len;
            // Inside the SET: one or more SEQUENCE { OID, value }.
            let mut atv_pos = set_start;
            while atv_pos < set_end {
                let (seq_start, seq_len) = match read_tl(data, atv_pos) {
                    Some(v) => v,
                    None => break,
                };
                let seq_end = seq_start + seq_len;
                // OID
                if seq_start < seq_end && data[seq_start] == 0x06 {
                    let (oid_start, oid_len) = match read_tl(data, seq_start) {
                        Some(v) => v,
                        None => { atv_pos = seq_end; continue; }
                    };
                    let oid_bytes = &data[oid_start..oid_start + oid_len];
                    let val_pos = oid_start + oid_len;
                    // Value (skip its tag+length to get the content).
                    if val_pos < seq_end {
                        let (val_start, val_len) = match read_tl(data, val_pos) {
                            Some(v) => v,
                            None => { atv_pos = seq_end; continue; }
                        };
                        let val_bytes = &data[val_start..val_start + val_len];
                        let value = String::from_utf8_lossy(val_bytes);
                        if let Some(abbrev) = oid_abbrev(oid_bytes) {
                            parts.push(format!("{abbrev}={value}"));
                        } else {
                            // Format unknown OID as dotted decimal.
                            parts.push(format!("OID({})={value}", format_oid(oid_bytes)));
                        }
                    }
                }
                atv_pos = seq_end;
            }
            rdn_pos = set_end;
        }
        parts.join(", ")
    }

    /// Format OID content bytes as dotted-decimal (e.g. "2.5.4.3").
    fn format_oid(bytes: &[u8]) -> String {
        if bytes.is_empty() { return String::new(); }
        let mut components: Vec<u32> = Vec::new();
        // First byte encodes two components: c1 = byte/40, c2 = byte%40.
        components.push((bytes[0] / 40) as u32);
        components.push((bytes[0] % 40) as u32);
        let mut val = 0u32;
        for &b in &bytes[1..] {
            val = (val << 7) | (b & 0x7F) as u32;
            if b & 0x80 == 0 {
                components.push(val);
                val = 0;
            }
        }
        components.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(".")
    }

    /// Decode a DER UTCTime or GeneralizedTime into a string matching the
    /// format produced by the `x509-parser` crate:
    /// `"Mon DD HH:MM:SS YYYY +00:00"` (e.g. `"Oct 19 18:41:42 2026 +00:00"`).
    fn decode_time(data: &[u8], pos: usize) -> Option<(String, usize)> {
        if pos >= data.len() { return None; }
        let tag = data[pos];
        let (start, len) = read_tl(data, pos)?;
        let s = std::str::from_utf8(&data[start..start + len]).ok()?;
        let (year, month, day, hour, min, sec) = if tag == 0x17 {
            // UTCTime: YYMMDDHHMMSSZ
            if s.len() < 13 { return None; }
            let yy: u32 = s[0..2].parse().ok()?;
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            (year, &s[2..4], &s[4..6], &s[6..8], &s[8..10], &s[10..12])
        } else if tag == 0x18 {
            // GeneralizedTime: YYYYMMDDHHMMSSZ
            if s.len() < 15 { return None; }
            let year: u32 = s[0..4].parse().ok()?;
            (year, &s[4..6], &s[6..8], &s[8..10], &s[10..12], &s[12..14])
        } else {
            return None;
        };
        let mon: u32 = month.parse().ok()?;
        let d: u32 = day.parse().ok()?;
        let month_name = match mon {
            1 => "Jan", 2 => "Feb", 3 => "Mar", 4 => "Apr",
            5 => "May", 6 => "Jun", 7 => "Jul", 8 => "Aug",
            9 => "Sep", 10 => "Oct", 11 => "Nov", 12 => "Dec",
            _ => return None,
        };
        // x509-parser uses "%b %e" which pads day < 10 with a leading space.
        let formatted = format!("{month_name} {d:2} {hour}:{min}:{sec} {year} +00:00");
        Some((formatted, start + len))
    }

    // ── Main parse logic ─────────────────────────────────────────────────
    // Certificate ::= SEQUENCE { tbsCertificate, ... }
    let (cert_start, _cert_len) = read_tl(der, 0)?;
    // TBSCertificate ::= SEQUENCE { [0]version?, serial, sig, issuer, validity, subject, ... }
    let (tbs_start, _tbs_len) = read_tl(der, cert_start)?;

    let mut pos = tbs_start;

    // [0] EXPLICIT version (optional — present if first byte is 0xA0).
    if pos < der.len() && der[pos] == 0xA0 {
        pos = skip_tlv(der, pos)?;
    }

    // serialNumber INTEGER
    if pos >= der.len() || der[pos] != 0x02 { return None; }
    let (serial_start, serial_len) = read_tl(der, pos)?;
    let serial_bytes = &der[serial_start..serial_start + serial_len];
    // Strip leading zero byte used for positive-sign padding.
    let serial_trimmed = if serial_bytes.len() > 1 && serial_bytes[0] == 0x00 {
        &serial_bytes[1..]
    } else {
        serial_bytes
    };
    let serial_number = to_hex(serial_trimmed);
    pos = serial_start + serial_len;

    // signature AlgorithmIdentifier — skip.
    pos = skip_tlv(der, pos)?;

    // issuer Name
    let (issuer_start, issuer_len) = read_tl(der, pos)?;
    let issuer = decode_name(&der[pos..issuer_start + issuer_len]);
    pos = issuer_start + issuer_len;

    // validity Validity ::= SEQUENCE { notBefore, notAfter }
    let (val_start, _val_len) = read_tl(der, pos)?;
    let (not_before, after_nb) = decode_time(der, val_start)?;
    let (not_after, _) = decode_time(der, after_nb)?;
    pos = val_start + _val_len;

    // subject Name
    let (subj_start, subj_len) = read_tl(der, pos)?;
    let subject = decode_name(&der[pos..subj_start + subj_len]);

    // SHA-1 thumbprint of the full DER certificate.
    let thumbprint_sha1 = to_hex(&sha1::Sha1::digest(der));

    Some(CertificateInfo {
        subject,
        issuer,
        serial_number,
        not_before,
        not_after,
        thumbprint_sha1,
    })
}

// ── EFI_SIGNATURE_LIST parsing ────────────────────────────────────────────────

/// `EFI_CERT_X509_GUID` = `{a5c059a1-94e4-4aa7-87b5-ab155c2bf072}` raw bytes.
const EFI_CERT_X509_GUID_BYTES: [u8; 16] = [
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a,
    0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72,
];
/// `EFI_CERT_SHA256_GUID` = `{c1c41626-504c-4092-aca9-41f936934328}` raw bytes.
const EFI_CERT_SHA256_GUID_BYTES: [u8; 16] = [
    0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40,
    0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28,
];
/// `EFI_CERT_SHA1_GUID` = `{826ca512-cf10-4ac9-b187-be01496631bd}` raw bytes.
const EFI_CERT_SHA1_GUID_BYTES: [u8; 16] = [
    0x12, 0xa5, 0x6c, 0x82, 0x10, 0xcf, 0xc9, 0x4a,
    0xb1, 0x87, 0xbe, 0x01, 0x49, 0x66, 0x31, 0xbd,
];
/// `EFI_CERT_SHA384_GUID` = `{ff3e5307-9fd0-48c9-85f1-8ad56c701e01}` raw bytes.
const EFI_CERT_SHA384_GUID_BYTES: [u8; 16] = [
    0x07, 0x53, 0x3e, 0xff, 0xd0, 0x9f, 0xc9, 0x48,
    0x85, 0xf1, 0x8a, 0xd5, 0x6c, 0x70, 0x1e, 0x01,
];
/// `EFI_CERT_SHA512_GUID` = `{093e0fae-a6c4-4f50-9f1b-d41e2b89c19a}` raw bytes.
const EFI_CERT_SHA512_GUID_BYTES: [u8; 16] = [
    0xae, 0x0f, 0x3e, 0x09, 0xc4, 0xa6, 0x50, 0x4f,
    0x9f, 0x1b, 0xd4, 0x1e, 0x2b, 0x89, 0xc1, 0x9a,
];

/// A single entry within an [`EfiSignatureList`].
///
/// Corresponds to `EFI_SIGNATURE_DATA` in the UEFI specification.
/// The payload is decoded as either an X.509 certificate or a hash, depending
/// on the `signature_type` of the enclosing list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EfiSignatureEntry {
    /// `EFI_SIGNATURE_DATA.SignatureOwner` formatted as
    /// `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
    pub owner: String,
    /// Decoded X.509 certificate for `EFI_CERT_X509` lists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_info: Option<CertificateInfo>,
    /// Hex-encoded hash digest for SHA-* lists (dbx, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

/// A parsed `EFI_SIGNATURE_LIST` from a UEFI variable payload
/// (`PK`, `KEK`, `db`, `dbx`, …).
///
/// Each UEFI Secure Boot variable contains one or more signature lists.
/// A list groups entries of the same type (e.g. X.509 certificates or
/// SHA-256 revocation hashes) under a common `signature_type` name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EfiSignatureList {
    /// Human-readable signature type name derived from the
    /// `EFI_SIGNATURE_LIST.SignatureType` GUID:
    ///
    /// | Name | GUID |
    /// |---|---|
    /// | `EFI_CERT_X509` | `{a5c059a1-94e4-4aa7-87b5-ab155c2bf072}` |
    /// | `EFI_CERT_SHA256` | `{c1c41626-504c-4092-aca9-41f936934328}` |
    /// | `EFI_CERT_SHA1` | `{826ca512-cf10-4ac9-b187-be01496631bd}` |
    /// | `EFI_CERT_SHA384` | `{ff3e5307-9fd0-48c9-85f1-8ad56c701e01}` |
    /// | `EFI_CERT_SHA512` | `{093e0fae-a6c4-4f50-9f1b-d41e2b89c19a}` |
    pub signature_type: String,
    /// Individual signature entries (certs or hashes).
    pub entries: Vec<EfiSignatureEntry>,
}

/// Try to parse `data` as a concatenated sequence of `EFI_SIGNATURE_LIST`
/// structures.  Returns `None` if the data does not begin with a recognised
/// signature-type GUID (so non-signature variable data is left untouched).
///
/// `EFI_SIGNATURE_LIST` layout (UEFI spec §32.4.1):
/// ```text
/// [0..16]  SignatureType GUID
/// [16..20] SignatureListSize  (u32 LE)  — total bytes for this list
/// [20..24] SignatureHeaderSize (u32 LE) — bytes of extra header before entries
/// [24..28] SignatureSize      (u32 LE)  — bytes per EFI_SIGNATURE_DATA entry
/// [28 + SignatureHeaderSize .. SignatureListSize]  EFI_SIGNATURE_DATA[]
/// ```
/// Each `EFI_SIGNATURE_DATA` entry is `SignatureSize` bytes:
/// ```text
/// [0..16]  SignatureOwner GUID
/// [16..]   SignatureData  (cert DER or hash bytes)
/// ```
fn parse_signature_lists(data: &[u8]) -> Option<Vec<EfiSignatureList>> {
    // Minimum valid structure is a 28-byte list header with a known GUID.
    if data.len() < 28 {
        return None;
    }
    // Reject data whose first 16 bytes are not a known GUID — this avoids
    // misidentifying random variable data as a signature list.
    let first_guid = &data[..16];
    if first_guid != &EFI_CERT_X509_GUID_BYTES
        && first_guid != &EFI_CERT_SHA256_GUID_BYTES
        && first_guid != &EFI_CERT_SHA1_GUID_BYTES
        && first_guid != &EFI_CERT_SHA384_GUID_BYTES
        && first_guid != &EFI_CERT_SHA512_GUID_BYTES
    {
        return None;
    }

    let mut lists = Vec::new();
    let mut pos = 0usize;

    while pos + 28 <= data.len() {
        let sig_type_bytes = &data[pos..pos + 16];
        let list_size    = u32::from_le_bytes(data[pos + 16..pos + 20].try_into().unwrap()) as usize;
        let header_size  = u32::from_le_bytes(data[pos + 20..pos + 24].try_into().unwrap()) as usize;
        let sig_size     = u32::from_le_bytes(data[pos + 24..pos + 28].try_into().unwrap()) as usize;

        if list_size < 28 || pos + list_size > data.len() {
            break;
        }

        let type_name = if sig_type_bytes == &EFI_CERT_X509_GUID_BYTES {
            "EFI_CERT_X509"
        } else if sig_type_bytes == &EFI_CERT_SHA256_GUID_BYTES {
            "EFI_CERT_SHA256"
        } else if sig_type_bytes == &EFI_CERT_SHA1_GUID_BYTES {
            "EFI_CERT_SHA1"
        } else if sig_type_bytes == &EFI_CERT_SHA384_GUID_BYTES {
            "EFI_CERT_SHA384"
        } else if sig_type_bytes == &EFI_CERT_SHA512_GUID_BYTES {
            "EFI_CERT_SHA512"
        } else {
            break; // Unknown GUID — stop.
        };
        let is_x509 = type_name == "EFI_CERT_X509";

        let entries_start = pos + 28 + header_size;
        let entries_end   = pos + list_size;

        let mut entries = Vec::new();

        if sig_size >= 17 && entries_start < entries_end {
            let entry_count = (entries_end - entries_start) / sig_size;
            entries.reserve(entry_count);
            let mut ep = entries_start;
            while ep + sig_size <= entries_end {
                let owner_bytes: [u8; 16] = data[ep..ep + 16].try_into().unwrap();
                let owner   = Guid::from_bytes(owner_bytes).to_string();
                let payload = &data[ep + 16..ep + sig_size];

                let (certificate_info, hash) = if is_x509 {
                    (try_decode_x509(payload), None)
                } else {
                    (None, Some(to_hex(payload)))
                };

                entries.push(EfiSignatureEntry { owner, certificate_info, hash });
                ep += sig_size;
            }
        }

        lists.push(EfiSignatureList {
            signature_type: type_name.to_string(),
            entries,
        });
        pos += list_size;
    }

    if lists.is_empty() { None } else { Some(lists) }
}

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
    /// Raw variable data, hex-encoded.  Empty (and omitted from JSON) when
    /// the data has been fully decoded into [`Self::certificate_info`] or
    /// [`Self::signature_list`], avoiding redundant encoding of large blobs.
    #[serde(skip_serializing_if = "is_empty_str")]
    pub variable_data: String,
    /// Decoded X.509 certificate information, present when `variable_data`
    /// contains an `EFI_SIGNATURE_DATA` record whose payload is a valid
    /// DER-encoded X.509 certificate (e.g. `EV_EFI_VARIABLE_AUTHORITY`
    /// events).  `None` for all other UEFI variable events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_info: Option<CertificateInfo>,
    /// Parsed `EFI_SIGNATURE_LIST` contents for Secure Boot database
    /// variables (`PK`, `KEK`, `db`, `dbx`, …).  Each list entry contains
    /// either decoded X.509 certificates or revocation hashes.
    /// `None` when `variable_data` is not a signature-list structure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_list: Option<Vec<EfiSignatureList>>,
}

// Helper: is the variable_data field worth emitting?  It's redundant (and
// large) when the data has already been fully decoded into `signature_list`
// or `certificate_info`, so we suppress it in that case.
fn is_empty_str(s: &str) -> bool { s.is_empty() }

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

        // Try the structured decoders cheapest-to-most-expensive.
        // When one succeeds we skip the others and also skip the raw hex
        // encoding — the data is already fully represented in structured form.

        // (1) EFI_SIGNATURE_LIST (PK / KEK / db / dbx): the first 16 bytes
        //     must be a known signature-type GUID, so this bails out in O(1)
        //     for all non-database variable events.
        let signature_list = parse_signature_lists(var_data);

        // (2) Single DER X.509 cert (EV_EFI_VARIABLE_AUTHORITY): the data is
        //     [16-byte SignatureOwner GUID][DER cert].  Only attempt when
        //     signature_list failed (PK/KEK/db already handled above) and
        //     the byte at offset 16 is the DER SEQUENCE tag (0x30), skipping
        //     the attempt for BootOrder / Boot0000 / etc. at zero cost.
        let certificate_info = if signature_list.is_none()
            && var_data.len() > 17
            && var_data[16] == 0x30
        {
            try_decode_x509(&var_data[16..])
        } else {
            None
        };

        // (3) Raw hex fallback — only for variables that couldn't be decoded
        //     above (SecureBoot, BootOrder, Boot0000, …).  Skipping this for
        //     the decoded cases avoids ~8000 tiny allocs for the 8 KB dbx blob
        //     and hundreds more for db / KEK / PK.
        let variable_data = if certificate_info.is_none() && signature_list.is_none() {
            to_hex(var_data)
        } else {
            String::new()
        };

        Ok(Self {
            variable_name,
            unicode_name,
            variable_data,
            certificate_info,
            signature_list,
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
