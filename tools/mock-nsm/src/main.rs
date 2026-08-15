//! Mock NSM device daemon for local Nautilus testing.
//!
//! Creates `/dev/nsm` via CUSE (Character device in Userspace) and handles
//! the NSM ioctl protocol. Processes NSM requests and returns mock attestation
//! documents. Injected into the QEMU VM via the overlay initrd.

mod certs;
mod ioctl;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use ioctl::{PcrBank, decode_request, encode_response, handle_request};

/// Build attestation document (COSE_Sign1) for mock responses.
/// Uses a proper cert chain: fixed root CA → ephemeral leaf cert.
fn build_mock_attestation(
    public_key: Option<&[u8]>,
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
    pcrs: &BTreeMap<usize, Vec<u8>>,
) -> Vec<u8> {
    use p384::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    // Fixed root CA key and cert (deterministic across calls)
    let root_key = certs::root_ca_signing_key();
    let root_cert_der = certs::build_root_ca_cert(&root_key);

    // Ephemeral leaf key for this attestation
    let leaf_key = SigningKey::random(&mut OsRng);
    let leaf_cert_der = certs::build_leaf_cert(&root_key, &root_cert_der, leaf_key.verifying_key());

    // Build attestation payload as CBOR
    let payload = build_attestation_payload(
        "mock-enclave",
        "SHA384",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        pcrs,
        &leaf_cert_der,
        &[root_cert_der],
        public_key,
        user_data,
        nonce,
    );

    // Sign COSE_Sign1 with the leaf key
    build_cose_sign1(&payload, &leaf_key)
}

fn build_attestation_payload(
    module_id: &str,
    digest: &str,
    timestamp: u64,
    pcrs: &BTreeMap<usize, Vec<u8>>,
    certificate: &[u8],
    cabundle: &[Vec<u8>],
    public_key: Option<&[u8]>,
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
) -> Vec<u8> {
    use ciborium::Value;

    let pcr_map: Vec<(Value, Value)> = pcrs
        .iter()
        .map(|(k, v)| (Value::Integer((*k as i64).into()), Value::Bytes(v.clone())))
        .collect();

    let cabundle_arr: Vec<Value> = cabundle
        .iter()
        .map(|c| Value::Bytes(c.clone()))
        .collect();

    let map = Value::Map(vec![
        (Value::Text("module_id".into()), Value::Text(module_id.into())),
        (Value::Text("digest".into()), Value::Text(digest.into())),
        (Value::Text("timestamp".into()), Value::Integer((timestamp as i64).into())),
        (Value::Text("pcrs".into()), Value::Map(pcr_map)),
        (Value::Text("certificate".into()), Value::Bytes(certificate.to_vec())),
        (Value::Text("cabundle".into()), Value::Array(cabundle_arr)),
        (
            Value::Text("public_key".into()),
            match public_key {
                Some(pk) => Value::Bytes(pk.to_vec()),
                None => Value::Null,
            },
        ),
        (
            Value::Text("user_data".into()),
            match user_data {
                Some(ud) => Value::Bytes(ud.to_vec()),
                None => Value::Null,
            },
        ),
        (
            Value::Text("nonce".into()),
            match nonce {
                Some(n) => Value::Bytes(n.to_vec()),
                None => Value::Null,
            },
        ),
    ]);

    let mut buf = Vec::new();
    ciborium::into_writer(&map, &mut buf).expect("CBOR encode failed");
    buf
}

fn build_cose_sign1(payload: &[u8], signing_key: &p384::ecdsa::SigningKey) -> Vec<u8> {
    use coset::{CoseSign1Builder, HeaderBuilder, iana};
    use p384::ecdsa::signature::Signer;

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES384)
        .build();

    let cose_sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload.to_vec())
        .create_signature(b"", |data| {
            let sig: p384::ecdsa::Signature = signing_key.sign(data);
            sig.to_bytes().to_vec()
        })
        .build();

    use coset::CborSerializable;
    cose_sign1.to_vec().expect("COSE_Sign1 serialization failed")
}

fn main() {
    eprintln!("mock-nsm: starting");

    let pcr_bank = Arc::new(Mutex::new(PcrBank::new()));

    if !std::path::Path::new("/dev/cuse").exists() {
        eprintln!("mock-nsm: /dev/cuse not found — CUSE kernel module required");
        eprintln!("mock-nsm: ensure fuse.ko and cuse.ko are loaded before starting");
        std::process::exit(1);
    }

    eprintln!("mock-nsm: /dev/cuse found, using CUSE");
    run_cuse(pcr_bank);
}

/// CUSE-based /dev/nsm implementation.
/// Uses low-level CUSE protocol to create a character device in userspace.
fn run_cuse(pcr_bank: Arc<Mutex<PcrBank>>) {
    use libc::*;
    use std::os::unix::io::RawFd;

    // CUSE/FUSE protocol constants
    const FUSE_KERNEL_VERSION: u32 = 7;
    const FUSE_KERNEL_MINOR_VERSION: u32 = 31;
    // FUSE/CUSE opcodes (from linux/include/uapi/linux/fuse.h)
    const FUSE_GETATTR: u32 = 3;
    const FUSE_OPEN: u32 = 14;
    const FUSE_RELEASE: u32 = 18;
    const FUSE_FLUSH: u32 = 25;
    const FUSE_IOCTL: u32 = 39;
    const FUSE_POLL: u32 = 40;
    const CUSE_INIT: u32 = 4096;

    #[repr(C)]
    struct FuseInHeader {
        len: u32,
        opcode: u32,
        unique: u64,
        nodeid: u64,
        uid: u32,
        gid: u32,
        pid: u32,
        padding: u32,
    }

    #[repr(C)]
    struct FuseOutHeader {
        len: u32,
        error: i32,
        unique: u64,
    }

    #[repr(C)]
    #[derive(Default)]
    struct CuseInitOut {
        major: u32,
        minor: u32,
        unused: u32,
        flags: u32,
        max_read: u32,
        max_write: u32,
        dev_major: u32,
        dev_minor: u32,
        spare: [u32; 10],
    }

    #[repr(C)]
    struct FuseIoctlIn {
        fh: u64,
        flags: u32,
        cmd: u32,
        arg: u64,
        in_size: u32,
        out_size: u32,
    }

    #[repr(C)]
    struct FuseIoctlOut {
        result: i32,
        flags: u32,
        in_iovs: u32,
        out_iovs: u32,
    }

    // Open /dev/cuse
    let fd: RawFd = unsafe {
        open(b"/dev/cuse\0".as_ptr() as *const c_char, O_RDWR)
    };
    if fd < 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        eprintln!("mock-nsm: failed to open /dev/cuse: errno={} ({})",
            errno, std::io::Error::from_raw_os_error(errno));
        std::process::exit(1);
    }

    let mut buf = vec![0u8; 0x21000]; // 128K + 4K buffer

    // Read CUSE_INIT request
    let n = unsafe { read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
    if n < 0 {
        eprintln!("mock-nsm: failed to read CUSE_INIT");
        std::process::exit(1);
    }

    let in_header: &FuseInHeader = unsafe { &*(buf.as_ptr() as *const FuseInHeader) };
    if in_header.opcode != CUSE_INIT {
        eprintln!("mock-nsm: expected CUSE_INIT, got opcode {}", in_header.opcode);
        std::process::exit(1);
    }

    // Send CUSE_INIT reply with device name "nsm"
    let dev_name = b"DEVNAME=nsm\0";
    let out_header_size = std::mem::size_of::<FuseOutHeader>();
    let init_out_size = std::mem::size_of::<CuseInitOut>();
    let total_len = out_header_size + init_out_size + dev_name.len();

    let mut reply = vec![0u8; total_len];
    let out_header = FuseOutHeader {
        len: total_len as u32,
        error: 0,
        unique: in_header.unique,
    };
    unsafe {
        std::ptr::copy_nonoverlapping(
            &out_header as *const _ as *const u8,
            reply.as_mut_ptr(),
            out_header_size,
        );
    }

    // CUSE_UNRESTRICTED_IOCTL = (1 << 0) - needed for pointer-based NSM ioctl protocol
    const CUSE_UNRESTRICTED_IOCTL: u32 = 1;
    let init_out = CuseInitOut {
        major: FUSE_KERNEL_VERSION,
        minor: FUSE_KERNEL_MINOR_VERSION,
        flags: CUSE_UNRESTRICTED_IOCTL,
        max_read: 0x20000,
        max_write: 0x20000,
        dev_major: 0, // auto-assign
        dev_minor: 0, // auto-assign
        ..Default::default()
    };
    unsafe {
        std::ptr::copy_nonoverlapping(
            &init_out as *const _ as *const u8,
            reply.as_mut_ptr().add(out_header_size),
            init_out_size,
        );
    }
    reply[out_header_size + init_out_size..].copy_from_slice(dev_name);

    let written = unsafe { write(fd, reply.as_ptr() as *const c_void, reply.len()) };
    if written < 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        eprintln!("mock-nsm: failed to write CUSE_INIT reply: errno={} ({}) reply_len={}",
            errno, std::io::Error::from_raw_os_error(errno), reply.len());
        std::process::exit(1);
    }

    eprintln!("mock-nsm: CUSE device registered as /dev/nsm");

    eprintln!("mock-nsm: ready");

    // Main loop: handle ioctl requests
    loop {
        let n = unsafe { read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            eprintln!("mock-nsm: read error: {}", err);
            break;
        }
        if n == 0 {
            eprintln!("mock-nsm: read returned 0, exiting");
            break;
        }

        let in_header: &FuseInHeader = unsafe { &*(buf.as_ptr() as *const FuseInHeader) };

        match in_header.opcode {
            FUSE_OPEN => {
                // Reply with fh=0
                let reply_len = out_header_size + 16; // FuseOpenOut is 16 bytes
                let mut reply = vec![0u8; reply_len];
                let out_hdr = FuseOutHeader {
                    len: reply_len as u32,
                    error: 0,
                    unique: in_header.unique,
                };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &out_hdr as *const _ as *const u8,
                        reply.as_mut_ptr(),
                        out_header_size,
                    );
                }
                unsafe { write(fd, reply.as_ptr() as *const c_void, reply.len()) };
            }
            FUSE_RELEASE => {
                let reply_len = out_header_size;
                let mut reply = vec![0u8; reply_len];
                let out_hdr = FuseOutHeader {
                    len: reply_len as u32,
                    error: 0,
                    unique: in_header.unique,
                };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &out_hdr as *const _ as *const u8,
                        reply.as_mut_ptr(),
                        out_header_size,
                    );
                }
                unsafe { write(fd, reply.as_ptr() as *const c_void, reply.len()) };
            }
            FUSE_IOCTL => {
                let ioctl_in: &FuseIoctlIn = unsafe {
                    &*(buf.as_ptr().add(std::mem::size_of::<FuseInHeader>()) as *const FuseIoctlIn)
                };

                let ioctl_data_offset = std::mem::size_of::<FuseInHeader>() + std::mem::size_of::<FuseIoctlIn>();
                let ioctl_data = &buf[ioctl_data_offset..n as usize];

                const FUSE_IOCTL_RETRY: u32 = (1 << 2); // bit 2, value 4

                #[repr(C)]
                struct FuseIoctlIovec {
                    base: u64,
                    len: u64,
                }

                // Phase detection based on in_size (kernel doesn't set RETRY flag in requests)
                if ioctl_in.in_size == 0 && ioctl_data.is_empty() {

                    let ioctl_out = FuseIoctlOut {
                        result: 0,
                        flags: FUSE_IOCTL_RETRY,
                        in_iovs: 1,
                        out_iovs: 0,
                    };

                    let iov = FuseIoctlIovec {
                        base: ioctl_in.arg,
                        len: 32, // sizeof(NsmMessage)
                    };

                    let ioctl_out_size = std::mem::size_of::<FuseIoctlOut>();
                    let iov_size = std::mem::size_of::<FuseIoctlIovec>();
                    let reply_len = out_header_size + ioctl_out_size + iov_size;
                    let mut reply = vec![0u8; reply_len];

                    let out_hdr = FuseOutHeader {
                        len: reply_len as u32,
                        error: 0,
                        unique: in_header.unique,
                    };
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            &out_hdr as *const _ as *const u8,
                            reply.as_mut_ptr(),
                            out_header_size,
                        );
                        std::ptr::copy_nonoverlapping(
                            &ioctl_out as *const _ as *const u8,
                            reply.as_mut_ptr().add(out_header_size),
                            ioctl_out_size,
                        );
                        std::ptr::copy_nonoverlapping(
                            &iov as *const _ as *const u8,
                            reply.as_mut_ptr().add(out_header_size + ioctl_out_size),
                            iov_size,
                        );
                    }
                    unsafe { write(fd, reply.as_ptr() as *const c_void, reply.len()) };
                    continue;
                }

                if ioctl_data.len() < 32 {
                    send_ioctl_error(fd, in_header.unique, -libc::EINVAL);
                    continue;
                }

                // We have at least the NsmMessage struct (32 bytes)
                let req_ptr = u64::from_ne_bytes(ioctl_data[0..8].try_into().unwrap());
                let req_len = u64::from_ne_bytes(ioctl_data[8..16].try_into().unwrap());
                let resp_ptr = u64::from_ne_bytes(ioctl_data[16..24].try_into().unwrap());
                let resp_len = u64::from_ne_bytes(ioctl_data[24..32].try_into().unwrap());

                if ioctl_data.len() < 32 + req_len as usize {

                    let ioctl_out = FuseIoctlOut {
                        result: 0,
                        flags: FUSE_IOCTL_RETRY,
                        in_iovs: 2,  // NsmMessage + request data
                        out_iovs: 2, // NsmMessage (to update iov_len) + response data
                    };

                    let in_iovs = [
                        FuseIoctlIovec { base: ioctl_in.arg, len: 32 },
                        FuseIoctlIovec { base: req_ptr, len: req_len },
                    ];
                    let out_iovs = [
                        FuseIoctlIovec { base: ioctl_in.arg, len: 32 }, // write back NsmMessage
                        FuseIoctlIovec { base: resp_ptr, len: resp_len },
                    ];

                    let ioctl_out_size = std::mem::size_of::<FuseIoctlOut>();
                    let iovs_size = std::mem::size_of::<FuseIoctlIovec>() * 4; // 2 in + 2 out
                    let reply_len = out_header_size + ioctl_out_size + iovs_size;
                    let mut reply = vec![0u8; reply_len];

                    let out_hdr = FuseOutHeader {
                        len: reply_len as u32,
                        error: 0,
                        unique: in_header.unique,
                    };
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            &out_hdr as *const _ as *const u8,
                            reply.as_mut_ptr(),
                            out_header_size,
                        );
                        std::ptr::copy_nonoverlapping(
                            &ioctl_out as *const _ as *const u8,
                            reply.as_mut_ptr().add(out_header_size),
                            ioctl_out_size,
                        );
                        std::ptr::copy_nonoverlapping(
                            in_iovs.as_ptr() as *const u8,
                            reply.as_mut_ptr().add(out_header_size + ioctl_out_size),
                            std::mem::size_of::<FuseIoctlIovec>() * 2,
                        );
                        std::ptr::copy_nonoverlapping(
                            out_iovs.as_ptr() as *const u8,
                            reply.as_mut_ptr().add(out_header_size + ioctl_out_size + std::mem::size_of::<FuseIoctlIovec>() * 2),
                            std::mem::size_of::<FuseIoctlIovec>() * 2,
                        );
                    }
                    unsafe { write(fd, reply.as_ptr() as *const c_void, reply.len()) };
                    continue;
                }

                // We have both NsmMessage and request data
                eprintln!("mock-nsm: processing {} byte request", req_len);
                let request_data = &ioctl_data[32..32 + req_len as usize];

                // Decode and handle the NSM request
                let response_bytes = match decode_request(request_data) {
                    Ok(request) => {
                        let mut bank = pcr_bank.lock().unwrap();
                        let response = handle_request(request, &mut bank, &build_mock_attestation);
                        encode_response(&response)
                    }
                    Err(e) => {
                        eprintln!("mock-nsm: decode error: {}", e);
                        let response = ioctl::NsmResponse::Error("InternalError".to_string());
                        encode_response(&response)
                    }
                };

                eprintln!("mock-nsm: response {} bytes", response_bytes.len());

                // Truncate response if needed
                let actual_resp_len = std::cmp::min(response_bytes.len(), resp_len as usize);
                let resp_bytes = &response_bytes[..actual_resp_len];

                // Build the updated NsmMessage to write back to user space.
                // The key change: set response.iov_len to actual response length
                // so serde_cbor::from_slice only sees the valid CBOR data.
                let mut updated_msg = [0u8; 32];
                updated_msg[0..8].copy_from_slice(&req_ptr.to_ne_bytes());
                updated_msg[8..16].copy_from_slice(&req_len.to_ne_bytes());
                updated_msg[16..24].copy_from_slice(&resp_ptr.to_ne_bytes());
                updated_msg[24..32].copy_from_slice(&(actual_resp_len as u64).to_ne_bytes());

                // Send ioctl reply: updated NsmMessage (32 bytes) + response CBOR data
                let ioctl_out = FuseIoctlOut {
                    result: 0,
                    flags: 0,
                    in_iovs: 0,
                    out_iovs: 0,
                };

                let ioctl_out_size = std::mem::size_of::<FuseIoctlOut>();
                let reply_len = out_header_size + ioctl_out_size + 32 + resp_bytes.len();
                let mut reply = vec![0u8; reply_len];

                let out_hdr = FuseOutHeader {
                    len: reply_len as u32,
                    error: 0,
                    unique: in_header.unique,
                };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &out_hdr as *const _ as *const u8,
                        reply.as_mut_ptr(),
                        out_header_size,
                    );
                    std::ptr::copy_nonoverlapping(
                        &ioctl_out as *const _ as *const u8,
                        reply.as_mut_ptr().add(out_header_size),
                        ioctl_out_size,
                    );
                }
                // First out_iov: updated NsmMessage (32 bytes)
                reply[out_header_size + ioctl_out_size..out_header_size + ioctl_out_size + 32]
                    .copy_from_slice(&updated_msg);
                // Second out_iov: response CBOR data
                reply[out_header_size + ioctl_out_size + 32..].copy_from_slice(resp_bytes);

                unsafe { write(fd, reply.as_ptr() as *const c_void, reply.len()) };
            }
            FUSE_GETATTR => {
                // FuseAttrOut: attr_valid(u64) + attr_valid_nsec(u32) + dummy(u32) + FuseAttr
                // FuseAttr is 88 bytes on 64-bit. Total FuseAttrOut = 16 + 88 = 104 bytes
                // We just need mode to indicate char device
                let reply_len = out_header_size + 104;
                let mut reply = vec![0u8; reply_len];
                let out_hdr = FuseOutHeader {
                    len: reply_len as u32,
                    error: 0,
                    unique: in_header.unique,
                };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &out_hdr as *const _ as *const u8,
                        reply.as_mut_ptr(),
                        out_header_size,
                    );
                }
                // Set mode to S_IFCHR | 0666 at offset 16+24 (mode is at byte 24 of FuseAttr)
                let mode: u32 = libc::S_IFCHR as u32 | 0o666;
                let mode_offset = out_header_size + 16 + 24; // after attr_valid(8)+attr_valid_nsec(4)+dummy(4) + ino(8)+size(8)+blocks(8)
                reply[mode_offset..mode_offset+4].copy_from_slice(&mode.to_ne_bytes());
                // Set nlink=1 at offset +28
                let nlink: u32 = 1;
                reply[mode_offset+4..mode_offset+8].copy_from_slice(&nlink.to_ne_bytes());
                unsafe { write(fd, reply.as_ptr() as *const c_void, reply.len()) };
            }
            FUSE_FLUSH => {
                let reply_len = out_header_size;
                let mut reply = vec![0u8; reply_len];
                let out_hdr = FuseOutHeader {
                    len: reply_len as u32,
                    error: 0,
                    unique: in_header.unique,
                };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &out_hdr as *const _ as *const u8,
                        reply.as_mut_ptr(),
                        out_header_size,
                    );
                    write(fd, reply.as_ptr() as *const c_void, reply.len());
                }
            }
            FUSE_POLL => {
                // fuse_poll_out is 8 bytes: revents(u32) + padding(u32)
                let reply_len = out_header_size + 8;
                let mut reply = vec![0u8; reply_len];
                let out_hdr = FuseOutHeader {
                    len: reply_len as u32,
                    error: 0,
                    unique: in_header.unique,
                };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &out_hdr as *const _ as *const u8,
                        reply.as_mut_ptr(),
                        out_header_size,
                    );
                }
                // revents = POLLIN | POLLOUT (device is always ready for read/write)
                let revents: u32 = 0x0001 | 0x0004; // POLLIN | POLLOUT
                reply[out_header_size..out_header_size+4].copy_from_slice(&revents.to_ne_bytes());
                unsafe { write(fd, reply.as_ptr() as *const c_void, reply.len()) };
            }
            // Unknown opcode - reply with ENOSYS
            opcode => {
                eprintln!("mock-nsm: unhandled opcode {}", opcode);
                let reply_len = out_header_size;
                let mut reply = vec![0u8; reply_len];
                let out_hdr = FuseOutHeader {
                    len: reply_len as u32,
                    error: -libc::ENOSYS,
                    unique: in_header.unique,
                };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &out_hdr as *const _ as *const u8,
                        reply.as_mut_ptr(),
                        out_header_size,
                    );
                    write(fd, reply.as_ptr() as *const c_void, reply.len());
                }
            }
        }
    }

    unsafe { libc::close(fd) };

    fn send_ioctl_error(fd: libc::c_int, unique: u64, error: i32) {
        let out_header_size = std::mem::size_of::<FuseOutHeader>();
        let mut reply = vec![0u8; out_header_size];
        let out_hdr = FuseOutHeader {
            len: out_header_size as u32,
            error,
            unique,
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                &out_hdr as *const _ as *const u8,
                reply.as_mut_ptr(),
                out_header_size,
            );
            libc::write(fd, reply.as_ptr() as *const libc::c_void, reply.len());
        }
    }

}

