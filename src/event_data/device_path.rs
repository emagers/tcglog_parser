//! UEFI Device Path decoding.
//!
//! A UEFI device path is a sequence of variable-length nodes, each starting
//! with a 4-byte header:
//!
//! ```text
//! u8   Type
//! u8   SubType
//! u16  Length  (total including header)
//! ```
//!
//! The path is terminated by an `End of Hardware Device Path` node
//! (Type=0x7F, SubType=0xFF).
//!
//! This module decodes common node types into human-readable strings,
//! matching the "display-only" format used by the UEFI shell and
//! `go-efilib`.

use crate::types::Guid;
use serde::{Deserialize, Serialize};

// ── Device path type constants ────────────────────────────────────────────────

const DEVICE_PATH_TYPE_HARDWARE: u8 = 0x01;
const DEVICE_PATH_TYPE_ACPI: u8 = 0x02;
const DEVICE_PATH_TYPE_MESSAGING: u8 = 0x03;
const DEVICE_PATH_TYPE_MEDIA: u8 = 0x04;
const DEVICE_PATH_TYPE_END: u8 = 0x7F;

// Hardware sub-types
const HW_PCI: u8 = 0x01;

// ACPI sub-types
const ACPI_DP: u8 = 0x01;

// Messaging sub-types
const MSG_SCSI: u8 = 0x02;
const MSG_USB: u8 = 0x05;
const MSG_SATA: u8 = 0x12;
const MSG_NVME: u8 = 0x17;

// Media sub-types
const MEDIA_HARD_DRIVE: u8 = 0x01;
const MEDIA_FILE_PATH: u8 = 0x04;
const MEDIA_PIWG_FV: u8 = 0x07;
const MEDIA_PIWG_FFS: u8 = 0x06;

/// A single decoded device path node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DevicePathNode {
    /// Node type (e.g. 0x01 = Hardware, 0x04 = Media).
    pub node_type: u8,
    /// Node sub-type.
    pub sub_type: u8,
    /// Human-readable description of this node.
    pub display: String,
}

/// A parsed UEFI device path, consisting of one or more nodes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EfiDevicePath {
    /// The decoded nodes in order.
    pub nodes: Vec<DevicePathNode>,
}

impl EfiDevicePath {
    /// Decode a UEFI device path from raw bytes.
    ///
    /// Returns `None` if the data is too short or malformed.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let mut nodes = Vec::new();
        let mut pos = 0;

        while pos + 4 <= data.len() {
            let node_type = data[pos];
            let sub_type = data[pos + 1];
            let length = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;

            if length < 4 || pos + length > data.len() {
                break;
            }

            // End of device path
            if node_type == DEVICE_PATH_TYPE_END {
                break;
            }

            let node_data = &data[pos + 4..pos + length];
            let display = decode_node(node_type, sub_type, node_data);

            nodes.push(DevicePathNode {
                node_type,
                sub_type,
                display,
            });

            pos += length;
        }

        if nodes.is_empty() {
            None
        } else {
            Some(Self { nodes })
        }
    }

    /// Returns a display-only string representation of the full device path,
    /// similar to the UEFI Shell format (nodes separated by `/`).
    pub fn display_string(&self) -> String {
        self.nodes
            .iter()
            .map(|n| n.display.as_str())
            .collect::<Vec<_>>()
            .join("/")
    }
}

impl std::fmt::Display for EfiDevicePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_string())
    }
}

/// Decode a single device path node into a human-readable string.
fn decode_node(node_type: u8, sub_type: u8, data: &[u8]) -> String {
    match (node_type, sub_type) {
        // ── Hardware ──────────────────────────────────────────────────────
        (DEVICE_PATH_TYPE_HARDWARE, HW_PCI) if data.len() >= 2 => {
            format!("Pci({:#x},{:#x})", data[0], data[1])
        }

        // ── ACPI ──────────────────────────────────────────────────────────
        (DEVICE_PATH_TYPE_ACPI, ACPI_DP) if data.len() >= 8 => {
            let hid = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            let uid = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
            // Decode EISA-style HID
            if hid & 0xFFFF == 0x41D0 {
                let dev_id = (hid >> 16) & 0xFFFF;
                match dev_id {
                    0x0A03 => format!("PciRoot({:#x})", uid),
                    0x0A08 => format!("PcieRoot({:#x})", uid),
                    0x0604 => format!("Floppy({:#x})", uid),
                    _ => format!("Acpi(PNP{:04X},{:#x})", dev_id, uid),
                }
            } else {
                format!("Acpi({:#x},{:#x})", hid, uid)
            }
        }

        // ── Messaging ─────────────────────────────────────────────────────
        (DEVICE_PATH_TYPE_MESSAGING, MSG_SCSI) if data.len() >= 4 => {
            let pun = u16::from_le_bytes([data[0], data[1]]);
            let lun = u16::from_le_bytes([data[2], data[3]]);
            format!("Scsi({},{}))", pun, lun)
        }
        (DEVICE_PATH_TYPE_MESSAGING, MSG_USB) if data.len() >= 2 => {
            format!("USB({},{})", data[0], data[1])
        }
        (DEVICE_PATH_TYPE_MESSAGING, MSG_SATA) if data.len() >= 6 => {
            let port = u16::from_le_bytes([data[0], data[1]]);
            let pmport = u16::from_le_bytes([data[2], data[3]]);
            let lun = u16::from_le_bytes([data[4], data[5]]);
            format!("Sata({},{},{})", port, pmport, lun)
        }
        (DEVICE_PATH_TYPE_MESSAGING, MSG_NVME) if data.len() >= 12 => {
            let nsid = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            let eui64 = u64::from_le_bytes([
                data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
            ]);
            format!("NVMe({:#x},{:016X})", nsid, eui64)
        }

        // ── Media ─────────────────────────────────────────────────────────
        (DEVICE_PATH_TYPE_MEDIA, MEDIA_HARD_DRIVE) if data.len() >= 38 => {
            let part_num = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            let _start = u64::from_le_bytes([
                data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
            ]);
            let _size = u64::from_le_bytes([
                data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19],
            ]);
            let sig_type = data[36];
            let mbr_type = data[37];
            match sig_type {
                2 => {
                    // GPT GUID signature
                    let guid_bytes: [u8; 16] = data[20..36].try_into().unwrap();
                    let guid = Guid::from_bytes(guid_bytes);
                    format!(
                        "HD({},GPT,{})",
                        part_num,
                        guid.to_string().trim_matches(|c| c == '{' || c == '}')
                    )
                }
                1 => {
                    // MBR signature (4-byte)
                    let sig = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
                    format!("HD({},MBR,{:#010x},{})", part_num, sig, mbr_type)
                }
                _ => format!("HD({})", part_num),
            }
        }
        (DEVICE_PATH_TYPE_MEDIA, MEDIA_FILE_PATH) => {
            // UTF-16LE file path string
            let u16s: Vec<u16> = data
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect();
            let text = String::from_utf16_lossy(&u16s)
                .trim_matches('\0')
                .to_string();
            text
        }
        (DEVICE_PATH_TYPE_MEDIA, MEDIA_PIWG_FV) if data.len() >= 16 => {
            let guid_bytes: [u8; 16] = data[..16].try_into().unwrap();
            let guid = Guid::from_bytes(guid_bytes);
            format!("Fv({})", guid)
        }
        (DEVICE_PATH_TYPE_MEDIA, MEDIA_PIWG_FFS) if data.len() >= 16 => {
            let guid_bytes: [u8; 16] = data[..16].try_into().unwrap();
            let guid = Guid::from_bytes(guid_bytes);
            format!("FvFile({})", guid)
        }

        // ── Fallback ──────────────────────────────────────────────────────
        _ => {
            format!(
                "Path({:#04x},{:#04x},{})",
                node_type,
                sub_type,
                crate::types::to_hex(data)
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(node_type: u8, sub_type: u8, data: &[u8]) -> Vec<u8> {
        let length = (4 + data.len()) as u16;
        let mut buf = vec![node_type, sub_type];
        buf.extend_from_slice(&length.to_le_bytes());
        buf.extend_from_slice(data);
        buf
    }

    fn make_end_node() -> Vec<u8> {
        vec![0x7F, 0xFF, 4, 0]
    }

    #[test]
    fn parse_pci_root_and_pci() {
        let mut dp = Vec::new();
        // ACPI PciRoot(0x0)
        let mut acpi_data = Vec::new();
        acpi_data.extend_from_slice(&0x0A0341D0u32.to_le_bytes()); // PNP0A03
        acpi_data.extend_from_slice(&0u32.to_le_bytes()); // UID=0
        dp.extend_from_slice(&make_node(0x02, 0x01, &acpi_data));
        // PCI(0x1F, 0x02)
        dp.extend_from_slice(&make_node(0x01, 0x01, &[0x1F, 0x02]));
        dp.extend_from_slice(&make_end_node());

        let path = EfiDevicePath::parse(&dp).unwrap();
        assert_eq!(path.nodes.len(), 2);
        assert_eq!(path.nodes[0].display, "PciRoot(0x0)");
        assert_eq!(path.nodes[1].display, "Pci(0x1f,0x2)");
        assert_eq!(path.display_string(), "PciRoot(0x0)/Pci(0x1f,0x2)");
    }

    #[test]
    fn parse_file_path() {
        let file_name = "\\EFI\\BOOT\\BOOTX64.EFI\0";
        let data: Vec<u8> = file_name
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let mut dp = make_node(0x04, 0x04, &data);
        dp.extend_from_slice(&make_end_node());

        let path = EfiDevicePath::parse(&dp).unwrap();
        assert_eq!(path.nodes.len(), 1);
        assert_eq!(path.nodes[0].display, "\\EFI\\BOOT\\BOOTX64.EFI");
    }

    #[test]
    fn parse_hd_gpt() {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes()); // partition 1
        data.extend_from_slice(&0u64.to_le_bytes()); // start
        data.extend_from_slice(&0u64.to_le_bytes()); // size
        // GPT GUID signature (16 bytes)
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                  0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]);
        data.push(2); // sig_type = GPT
        data.push(2); // mbr_type

        let mut dp = make_node(0x04, 0x01, &data);
        dp.extend_from_slice(&make_end_node());

        let path = EfiDevicePath::parse(&dp).unwrap();
        assert!(path.nodes[0].display.starts_with("HD(1,GPT,"));
    }

    #[test]
    fn parse_nvme() {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes()); // NSID
        data.extend_from_slice(&0u64.to_le_bytes()); // EUI-64

        let mut dp = make_node(0x03, 0x17, &data);
        dp.extend_from_slice(&make_end_node());

        let path = EfiDevicePath::parse(&dp).unwrap();
        assert_eq!(path.nodes[0].display, "NVMe(0x1,0000000000000000)");
    }

    #[test]
    fn parse_empty_returns_none() {
        assert!(EfiDevicePath::parse(&[]).is_none());
    }

    #[test]
    fn parse_only_end_returns_none() {
        assert!(EfiDevicePath::parse(&make_end_node()).is_none());
    }

    #[test]
    fn unknown_node_type_uses_fallback() {
        let mut dp = make_node(0x99, 0x01, &[0xAB, 0xCD]);
        dp.extend_from_slice(&make_end_node());

        let path = EfiDevicePath::parse(&dp).unwrap();
        assert!(path.nodes[0].display.starts_with("Path("));
    }
}
