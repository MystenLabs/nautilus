use anyhow::{bail, ensure, Context, Result};
use std::fs;
use std::path::Path;

const EIF_MAGIC: &[u8; 4] = b".eif";
const HEADER_SIZE: usize = 0x224; // 548 bytes
const SECTION_HEADER_SIZE: usize = 12;
const MAX_SECTIONS: usize = 32;

const SECTION_KERNEL: u16 = 1;
const SECTION_CMDLINE: u16 = 2;
const SECTION_RAMDISK: u16 = 3;
const SECTION_SIGNATURE: u16 = 4;
const SECTION_METADATA: u16 = 5;

pub struct EifContents {
    pub kernel: Vec<u8>,
    pub cmdline: String,
    pub ramdisk: Vec<u8>,
    pub metadata: Option<String>,
}

pub struct EifInfo {
    pub version: u16,
    pub flags: u16,
    pub default_mem: u64,
    pub default_cpus: u64,
    pub num_sections: u16,
    pub sections: Vec<SectionInfo>,
}

pub struct SectionInfo {
    pub section_type: u16,
    pub offset: u64,
    pub size: u64,
}

pub fn section_type_name(t: u16) -> &'static str {
    match t {
        0 => "Invalid",
        SECTION_KERNEL => "Kernel",
        SECTION_CMDLINE => "Cmdline",
        SECTION_RAMDISK => "Ramdisk",
        SECTION_SIGNATURE => "Signature",
        SECTION_METADATA => "Metadata",
        _ => "Unknown",
    }
}

// --- Big-endian readers ---

fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
}

fn read_u64(buf: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[off..off + 8]);
    u64::from_be_bytes(b)
}

// --- Header parsing ---

#[allow(dead_code)]
struct Header {
    version: u16,
    flags: u16,
    default_mem: u64,
    default_cpus: u64,
    num_sections: u16,
    section_offsets: [u64; MAX_SECTIONS],
    section_sizes: [u64; MAX_SECTIONS],
}

fn parse_header(buf: &[u8]) -> Result<Header> {
    ensure!(buf.len() >= HEADER_SIZE, "file too small for EIF header ({} bytes)", buf.len());
    ensure!(&buf[0..4] == EIF_MAGIC, "bad EIF magic: expected {:?}, got {:?}", EIF_MAGIC, &buf[0..4]);

    let version = read_u16(buf, 4);
    let flags = read_u16(buf, 6);
    let default_mem = read_u64(buf, 8);
    let default_cpus = read_u64(buf, 16);
    // 2 bytes reserved at offset 24
    let num_sections = read_u16(buf, 26);
    ensure!(num_sections as usize <= MAX_SECTIONS, "num_sections {} exceeds max {}", num_sections, MAX_SECTIONS);

    let mut section_offsets = [0u64; MAX_SECTIONS];
    let mut section_sizes = [0u64; MAX_SECTIONS];
    for i in 0..MAX_SECTIONS {
        section_offsets[i] = read_u64(buf, 28 + i * 8);
        section_sizes[i] = read_u64(buf, 28 + MAX_SECTIONS * 8 + i * 8);
    }

    Ok(Header { version, flags, default_mem, default_cpus, num_sections, section_offsets, section_sizes })
}

// --- Read a section's type + data slice from a buffer at a given offset ---

fn read_section<'a>(buf: &'a [u8], offset: u64) -> Result<(u16, &'a [u8])> {
    let off = offset as usize;
    ensure!(buf.len() >= off + SECTION_HEADER_SIZE, "section header at {:#x} out of bounds", off);
    let stype = read_u16(buf, off);
    // 2 bytes flags at off+2 (always 0, skip)
    let size = read_u64(buf, off + 4) as usize;
    let start = off + SECTION_HEADER_SIZE;
    ensure!(buf.len() >= start + size, "section data at {:#x} (size {}) out of bounds", off, size);
    Ok((stype, &buf[start..start + size]))
}

/// Return high-level metadata about an EIF without extracting full section contents.
pub fn inspect_eif(path: &Path) -> Result<EifInfo> {
    let buf = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let hdr = parse_header(&buf)?;

    let mut sections = Vec::with_capacity(hdr.num_sections as usize);
    for i in 0..hdr.num_sections as usize {
        let off = hdr.section_offsets[i] as usize;
        ensure!(buf.len() >= off + SECTION_HEADER_SIZE, "section {} header out of bounds", i);
        let stype = read_u16(&buf, off);
        let size = read_u64(&buf, off + 4);
        sections.push(SectionInfo { section_type: stype, offset: hdr.section_offsets[i], size });
    }

    Ok(EifInfo {
        version: hdr.version,
        flags: hdr.flags,
        default_mem: hdr.default_mem,
        default_cpus: hdr.default_cpus,
        num_sections: hdr.num_sections,
        sections,
    })
}

/// Parse an EIF file and extract kernel, cmdline, ramdisk, and optional metadata.
/// The ramdisk is returned as-is (gzip-compressed cpio).
pub fn parse_eif(path: &Path) -> Result<EifContents> {
    let buf = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let hdr = parse_header(&buf)?;

    let mut kernel: Option<Vec<u8>> = None;
    let mut cmdline: Option<String> = None;
    let mut ramdisk: Option<Vec<u8>> = None;
    let mut metadata: Option<String> = None;

    for i in 0..hdr.num_sections as usize {
        let (stype, data) =
            read_section(&buf, hdr.section_offsets[i]).with_context(|| format!("section {}", i))?;
        match stype {
            SECTION_KERNEL => kernel = Some(data.to_vec()),
            SECTION_CMDLINE => {
                cmdline = Some(String::from_utf8(data.to_vec()).context("cmdline is not valid UTF-8")?)
            }
            SECTION_RAMDISK => ramdisk = Some(data.to_vec()),
            SECTION_SIGNATURE => {} // skip
            SECTION_METADATA => {
                metadata = Some(String::from_utf8(data.to_vec()).context("metadata is not valid UTF-8")?)
            }
            other => bail!("unknown section type {}", other),
        }
    }

    Ok(EifContents {
        kernel: kernel.context("EIF missing kernel section")?,
        cmdline: cmdline.context("EIF missing cmdline section")?,
        ramdisk: ramdisk.context("EIF missing ramdisk section")?,
        metadata,
    })
}
