// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use aws::{get_entropy, init_platform};
use std::env;
use std::process::Command;
use system::{dmesg, freopen, mount, reboot, seed_entropy};

// Referenced from: https://git.distrust.co/public/enclaveos/src/branch/master/src/init/init.rs
// Mount common filesystems with conservative permissions
fn init_rootfs() {
    use libc::{MS_NODEV, MS_NOEXEC, MS_NOSUID};
    let no_dse = MS_NODEV | MS_NOSUID | MS_NOEXEC;
    let no_se = MS_NOSUID | MS_NOEXEC;
    let args = [
        ("devtmpfs", "/dev", "devtmpfs", no_se, "mode=0755"),
        ("devpts", "/dev/pts", "devpts", no_se, ""),
        ("shm", "/dev/shm", "tmpfs", no_dse, "mode=0755"),
        ("proc", "/proc", "proc", no_dse, "hidepid=2"),
        ("tmpfs", "/run", "tmpfs", no_dse, "mode=0755"),
        ("tmpfs", "/tmp", "tmpfs", no_dse, ""),
        ("sysfs", "/sys", "sysfs", no_dse, ""),
        (
            "cgroup_root",
            "/sys/fs/cgroup",
            "tmpfs",
            no_dse,
            "mode=0755",
        ),
    ];
    for (src, target, fstype, flags, data) in args {
        if std::fs::exists(target).unwrap_or(false) {
            match std::fs::create_dir_all(target) {
                Ok(()) => dmesg(format!("Created mount point {}", target)),
                Err(e) => eprintln!("{}", e),
            }
        }
        match mount(src, target, fstype, flags, data) {
            Ok(()) => dmesg(format!("Mounted {}", target)),
            Err(e) => eprintln!("{}", e),
        }
    }
}

// Initialize console with stdin/stdout/stderr
fn init_console() {
    let args = [
        ("/dev/console", "r", 0),
        ("/dev/console", "w", 1),
        ("/dev/console", "w", 2),
    ];
    for (filename, mode, file) in args {
        match freopen(filename, mode, file) {
            Ok(()) => {}
            Err(e) => eprintln!("{}", e),
        }
    }
}

fn boot() {
    init_rootfs();
    init_console();
    init_platform();
    match seed_entropy(4096, get_entropy) {
        Ok(size) => dmesg(format!("Seeded kernel with entropy: {}", size)),
        Err(e) => eprintln!("{}", e),
    };
}

fn main() {
    boot();
    dmesg("EnclaveOS Booted".to_string());
    // Set the SSL_CERT_FILE environment variable
    env::set_var("SSL_CERT_FILE", "/ca-certificates.crt");
    env::set_var("PATH", "/bin:/sbin:/usr/bin:/usr/sbin:/");

    println!("SSL_CERT_FILE set to ca-certificates.crt");

    match Command::new("/sh").arg("/run.sh").spawn() {
        Ok(mut child) => {
            dmesg("Spawned run.sh script".to_string());
            // Wait for the child process to finish
            match child.wait() {
                Ok(status) => dmesg(format!("run.sh exited with status: {}", status)),
                Err(e) => eprintln!("Error waiting for run.sh: {}", e),
            }
        }
        Err(e) => eprintln!("Failed to execute run.sh: {}", e),
    }
    reboot();
}
