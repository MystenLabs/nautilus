use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use anyhow::Context;

pub struct QemuConfig {
    pub kernel: PathBuf,
    pub rootfs: PathBuf,    // production rootfs.cpio from EIF
    pub overlay: PathBuf,   // overlay initrd with run-local.sh + mock-nsm
    pub cmdline: String,    // kernel cmdline from EIF
    pub memory: String,     // e.g. "512M"
    pub cpus: u32,          // e.g. 2
    pub app_port: u16,      // host port for enclave:3000 (default: 3000)
    pub secrets_port: u16,  // host port for enclave:7777 (default: 7777)
    pub qemu_path: PathBuf, // path to qemu-system-x86_64
    pub verbose: bool,      // show console output
}

impl QemuConfig {
    pub fn default_qemu_path() -> PathBuf {
        // Let Command's PATH resolution handle finding the binary
        PathBuf::from("qemu-system-x86_64")
    }
}

/// Check if QEMU is available and return its version string.
pub fn check_qemu(qemu_path: &Path) -> anyhow::Result<String> {
    let output = Command::new(qemu_path)
        .arg("--version")
        .output()
        .with_context(|| format!("Could not run {:?}", qemu_path))?;

    let version = String::from_utf8_lossy(&output.stdout);
    Ok(version.lines().next().unwrap_or("unknown").to_string())
}

/// Detect the best acceleration method for the current platform.
fn detect_accel() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        // Check if HVF is available (Intel Macs)
        // On Apple Silicon, HVF doesn't support x86_64 guests well
        // Use TCG (software emulation) as fallback
        if std::process::Command::new("sysctl")
            .args(["-n", "hw.optional.vmx"])
            .output()
            .map(|o| o.stdout.starts_with(b"1"))
            .unwrap_or(false)
        {
            return "hvf";
        }
        "tcg"
    }
    #[cfg(target_os = "linux")]
    {
        if std::path::Path::new("/dev/kvm").exists() {
            return "kvm";
        }
        "tcg"
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        "tcg"
    }
}

/// Launch QEMU and return the child process handle.
pub fn launch(config: &QemuConfig) -> anyhow::Result<Child> {
    let accel = detect_accel();

    // Concatenate rootfs (gzip-compressed CPIO) + gzip-compressed overlay CPIO.
    // Linux initramfs handles concatenated gzip streams natively — each stream
    // contains a CPIO archive, and later entries override earlier ones.
    let combined_initrd = config.rootfs.with_file_name("combined-initrd.cpio.gz");
    {
        use std::io::Write;
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let rootfs_data = std::fs::read(&config.rootfs)
            .with_context(|| format!("reading rootfs {}", config.rootfs.display()))?;
        let overlay_data = std::fs::read(&config.overlay)
            .with_context(|| format!("reading overlay {}", config.overlay.display()))?;

        // Gzip-compress the overlay CPIO
        let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
        gz.write_all(&overlay_data)?;
        let overlay_gz = gz.finish()?;

        let mut f = std::fs::File::create(&combined_initrd)
            .with_context(|| format!("creating combined initrd {}", combined_initrd.display()))?;
        f.write_all(&rootfs_data)?;
        f.write_all(&overlay_gz)?;
    }
    let initrd = combined_initrd.to_string_lossy().to_string();

    // Build netdev with port forwarding
    let netdev = format!(
        "user,id=net0,hostfwd=tcp::{}-:3000,hostfwd=tcp::{}-:7777",
        config.app_port, config.secrets_port
    );

    let mut cmd = Command::new(&config.qemu_path);
    cmd.args([
        "-m",
        &config.memory,
        "-smp",
        &config.cpus.to_string(),
        "-nographic",
        "-no-reboot",
        "-accel",
        accel,
        "-cpu",
        if accel == "tcg" { "max" } else { "host" },
        "-kernel",
        &config.kernel.to_string_lossy(),
        "-initrd",
        &initrd,
        "-append",
        &config.cmdline,
        "-netdev",
        &netdev,
        "-device",
        "e1000,netdev=net0",
    ]);

    if config.verbose {
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());
    } else {
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());
    }

    // No interactive stdin needed
    cmd.stdin(Stdio::null());

    let child = cmd
        .spawn()
        .with_context(|| {
            format!(
                "Failed to start QEMU at {:?}. Is qemu-system-x86_64 installed?",
                config.qemu_path
            )
        })?;

    eprintln!(
        "QEMU started (PID: {}, accel: {}, ports: app={}, secrets={})",
        child.id(),
        accel,
        config.app_port,
        config.secrets_port
    );

    Ok(child)
}
