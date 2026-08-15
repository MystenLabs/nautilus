//! Build a minimal CPIO newc-format overlay initrd at runtime.
//!
//! This overlay is passed to QEMU alongside the production rootfs using
//! QEMU's initrd chaining (comma-separated paths). Files in the overlay
//! take precedence over those in the base initrd.

use anyhow::Result;

/// Cross-compiled mock-nsm binary for x86_64-unknown-linux-musl (static-pie).
/// Built via `docker build` in tools/mock-nsm/.
pub const MOCK_NSM_BINARY: &[u8] = include_bytes!("../mock-nsm-x86_64");

/// Kernel modules needed for networking (from Alpine linux-virt).
/// These are only needed when using the local kernel (not the Nitro kernel).
pub const MOD_E1000: &[u8] = include_bytes!("../e1000.ko");

/// FUSE/CUSE kernel modules built from Linux 6.6.129 source.
/// CUSE is needed for mock-nsm to create /dev/nsm as a character device.
pub const MOD_FUSE: &[u8] = include_bytes!("../fuse.ko");
pub const MOD_CUSE: &[u8] = include_bytes!("../cuse.ko");


/// Content of the local-mode init script that shadows the production `/run.sh`.
const RUN_LOCAL_SH: &str = r#"#!/bin/sh
set -e
echo "nautilus-local: run.sh starting"

export PYTHONPATH=/lib/python3.11:/usr/local/lib/python3.11/lib-dynload:/usr/local/lib/python3.11/site-packages:/lib
export LD_LIBRARY_PATH=/lib:$LD_LIBRARY_PATH

# Load kernel modules for networking (needed with local kernel)
if [ -f /modules/e1000.ko ]; then
    echo "Loading e1000 network driver..."
    insmod /modules/e1000.ko 2>&1 || true
    echo "Module loaded"
fi

# Load FUSE/CUSE kernel modules (needed for mock-nsm to create /dev/nsm)
if [ -f /modules/fuse.ko ]; then
    echo "Loading fuse module..."
    insmod /modules/fuse.ko 2>&1 || true
fi
if [ -f /modules/cuse.ko ]; then
    echo "Loading cuse module..."
    insmod /modules/cuse.ko 2>&1 || true
fi
ls -la /dev/cuse /dev/fuse 2>&1 || true

# Setup loopback networking
busybox ip addr add 127.0.0.1/32 dev lo
busybox ip link set dev lo up
echo "127.0.0.1   localhost" > /etc/hosts

# Configure virtio-net interface with static IP
# QEMU user-mode networking uses 10.0.2.0/24, gateway 10.0.2.2
echo "Configuring network..."
for iface in eth0 ens3 enp0s3; do
    if busybox ip link show "$iface" > /dev/null 2>&1; then
        busybox ip link set dev "$iface" up
        # Wait for carrier (virtio-net needs a moment)
        for i in $(seq 1 20); do
            carrier=$(cat /sys/class/net/$iface/carrier 2>/dev/null || echo 0)
            [ "$carrier" = "1" ] && break
            sleep 0.2
        done
        busybox ip addr add 10.0.2.15/24 dev "$iface"
        busybox ip route add default via 10.0.2.2
        echo "nameserver 10.0.2.3" > /etc/resolv.conf
        echo "Network interface $iface configured (10.0.2.15)"
        busybox ip addr show "$iface"
        break
    fi
done

# Start mock NSM daemon
if [ -x /mock-nsm ]; then
    echo "Starting mock-nsm..."
    /mock-nsm &
    sleep 1
    echo "mock-nsm started, waiting for /dev/nsm..."
    for i in $(seq 1 30); do
        [ -e /dev/nsm ] && break
        sleep 0.1
    done
    if [ -e /dev/nsm ]; then
        echo "/dev/nsm is ready"
        ls -la /dev/nsm 2>&1
    else
        echo "WARNING: /dev/nsm did not appear, attestation will fail"
    fi
fi

# Read secrets from overlay file (injected at CPIO build time)
if [ -f /secrets.json ]; then
    echo "Reading secrets from /secrets.json..."
    jq -r 'to_entries[] | "\(.key)=\(.value)"' /secrets.json > /tmp/kvpairs
    while IFS="=" read -r key value; do
        export "$key"="$value"
    done < /tmp/kvpairs
    rm -f /tmp/kvpairs
    echo "Secrets loaded"
else
    echo "WARNING: /secrets.json not found, no secrets loaded"
fi

# Start the nautilus server
echo "Starting nautilus-server..."
/nautilus-server
"#;

/// Align `offset` up to the next multiple of 4.
fn align4(offset: usize) -> usize {
    (offset + 3) & !3
}

/// Write a single CPIO newc entry (header + filename + data) into `buf`,
/// returning the new offset.
fn write_cpio_entry(
    buf: &mut Vec<u8>,
    ino: u32,
    mode: u32,
    filesize: u32,
    filename: &str,
    data: &[u8],
) {
    // namesize includes the NUL terminator
    let namesize = filename.len() as u32 + 1;

    // 110-byte ASCII header
    let header = format!(
        "070701\
         {ino:08X}\
         {mode:08X}\
         {uid:08X}\
         {gid:08X}\
         {nlink:08X}\
         {mtime:08X}\
         {filesize:08X}\
         {devmajor:08X}\
         {devminor:08X}\
         {rdevmajor:08X}\
         {rdevminor:08X}\
         {namesize:08X}\
         {check:08X}",
        ino = ino,
        mode = mode,
        uid = 0u32,
        gid = 0u32,
        nlink = 1u32,
        mtime = 0u32,
        filesize = filesize,
        devmajor = 0u32,
        devminor = 0u32,
        rdevmajor = 0u32,
        rdevminor = 0u32,
        namesize = namesize,
        check = 0u32,
    );
    debug_assert_eq!(header.len(), 110);

    let header_plus_name = 110 + namesize as usize; // includes NUL
    let padded_header_plus_name = align4(header_plus_name);
    let padded_data = align4(filesize as usize);

    buf.extend_from_slice(header.as_bytes());
    buf.extend_from_slice(filename.as_bytes());
    buf.push(0); // NUL terminator
    // Pad after filename to 4-byte boundary
    for _ in 0..(padded_header_plus_name - header_plus_name) {
        buf.push(0);
    }

    buf.extend_from_slice(data);
    // Pad after data to 4-byte boundary
    for _ in 0..(padded_data - filesize as usize) {
        buf.push(0);
    }
}

/// Build a CPIO newc overlay archive containing `run.sh`, optionally
/// `mock-nsm`, kernel modules, and secrets. Returns raw (uncompressed) CPIO bytes.
pub fn build_overlay(mock_nsm_binary: Option<&[u8]>, include_modules: bool, secrets_json: Option<&str>) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut ino: u32 = 1;

    // Entry 1: run.sh (executable script)
    let run_sh_bytes = RUN_LOCAL_SH.as_bytes();
    write_cpio_entry(
        &mut buf,
        ino,
        0o100755,
        run_sh_bytes.len() as u32,
        "run.sh",
        run_sh_bytes,
    );
    ino += 1;

    // Entry 2 (optional): mock-nsm binary
    if let Some(nsm_bytes) = mock_nsm_binary {
        write_cpio_entry(
            &mut buf,
            ino,
            0o100755,
            nsm_bytes.len() as u32,
            "mock-nsm",
            nsm_bytes,
        );
        ino += 1;
    }

    // Entry: secrets JSON file
    if let Some(json) = secrets_json {
        let json_bytes = json.as_bytes();
        write_cpio_entry(
            &mut buf,
            ino,
            0o100644,
            json_bytes.len() as u32,
            "secrets.json",
            json_bytes,
        );
        ino += 1;
    }

    // Kernel modules for networking (when using local kernel)
    if include_modules {
        // Create /modules directory
        write_cpio_entry(&mut buf, ino, 0o040755, 0, "modules", &[]);
        ino += 1;

        for (name, data) in [
            ("modules/e1000.ko", MOD_E1000),
            ("modules/fuse.ko", MOD_FUSE),
            ("modules/cuse.ko", MOD_CUSE),
        ] {
            write_cpio_entry(&mut buf, ino, 0o100644, data.len() as u32, name, data);
            ino += 1;
        }
    }

    // Trailer entry
    let _ = ino;
    write_cpio_entry(&mut buf, 0, 0, 0, "TRAILER!!!", &[]);

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_without_mock_nsm() {
        let archive = build_overlay(None, false, None).unwrap();
        assert!(archive.starts_with(b"070701"));
        let archive_str = String::from_utf8_lossy(&archive);
        assert!(archive_str.contains("run.sh"));
        assert!(archive_str.contains("TRAILER!!!"));
        assert!(!archive.windows(10).any(|w| w == b"\x00mock-nsm\x00"));
    }

    #[test]
    fn overlay_with_mock_nsm() {
        let fake_binary = b"\x7fELF_fake_binary_data";
        let archive = build_overlay(Some(fake_binary), false, None).unwrap();
        let archive_str = String::from_utf8_lossy(&archive);
        assert!(archive_str.contains("run.sh"));
        assert!(archive_str.contains("mock-nsm"));
        assert!(archive_str.contains("TRAILER!!!"));
        assert!(archive.windows(fake_binary.len()).any(|w| w == fake_binary));
    }

    #[test]
    fn overlay_with_modules() {
        let archive = build_overlay(None, true, None).unwrap();
        let archive_str = String::from_utf8_lossy(&archive);
        assert!(archive_str.contains("modules/e1000.ko"));
    }

    #[test]
    fn header_length_is_110() {
        let archive = build_overlay(None, false, None).unwrap();
        assert_eq!(&archive[0..6], b"070701");
    }
}
