mod attestation;
mod eif;
mod overlay;
mod qemu;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "nautilus-local", about = "Local mock environment for Nautilus enclaves")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Parse an EIF file and display metadata
    Parse {
        /// Path to the EIF file
        eif_path: PathBuf,
    },
    /// Boot an EIF in QEMU with mock NSM
    Run {
        /// Path to the EIF file
        eif_path: PathBuf,
        /// Use kernel directly (skip EIF parse)
        #[arg(long)]
        kernel: Option<PathBuf>,
        /// Use rootfs directly (skip EIF parse)
        #[arg(long)]
        rootfs: Option<PathBuf>,
        /// Use the kernel from the EIF instead of the local kernel
        #[arg(long)]
        eif_kernel: bool,
        /// Secrets JSON to inject
        #[arg(long)]
        secrets: Option<String>,
        /// Path to secrets JSON file
        #[arg(long)]
        secrets_file: Option<PathBuf>,
        /// Show VM console output
        #[arg(long)]
        verbose: bool,
        /// Host port for enclave:3000
        #[arg(long, default_value = "3000")]
        port: u16,
        /// Host port for secrets injection (enclave:7777)
        #[arg(long, default_value = "7777")]
        secrets_port: u16,
        /// VM memory
        #[arg(long, default_value = "512M")]
        memory: String,
        /// VM CPUs
        #[arg(long, default_value = "2")]
        cpus: u32,
        /// Path to qemu-system-x86_64
        #[arg(long)]
        qemu: Option<PathBuf>,
    },
    /// Generate a standalone mock attestation document
    Attest {
        /// Ed25519 public key (hex-encoded)
        #[arg(long)]
        public_key: String,
        /// PCR0 value (hex, default all zeros)
        #[arg(long)]
        pcr0: Option<String>,
        /// PCR1 value (hex, default all zeros)
        #[arg(long)]
        pcr1: Option<String>,
        /// PCR2 value (hex, default all zeros)
        #[arg(long)]
        pcr2: Option<String>,
        /// Output file (default: stdout hex)
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

fn parse_pcrs(pcr0: &Option<String>, pcr1: &Option<String>, pcr2: &Option<String>) -> Result<BTreeMap<usize, Vec<u8>>> {
    let mut pcrs = BTreeMap::new();
    let parse_hex_pcr = |idx: usize, hex_str: &str| -> Result<(usize, Vec<u8>)> {
        let bytes = hex::decode(hex_str)
            .with_context(|| format!("invalid hex for PCR{}", idx))?;
        anyhow::ensure!(bytes.len() == 48, "PCR{} must be 48 bytes (got {})", idx, bytes.len());
        Ok((idx, bytes))
    };

    if let Some(v) = pcr0 {
        let (idx, bytes) = parse_hex_pcr(0, v)?;
        pcrs.insert(idx, bytes);
    }
    if let Some(v) = pcr1 {
        let (idx, bytes) = parse_hex_pcr(1, v)?;
        pcrs.insert(idx, bytes);
    }
    if let Some(v) = pcr2 {
        let (idx, bytes) = parse_hex_pcr(2, v)?;
        pcrs.insert(idx, bytes);
    }
    Ok(pcrs)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Parse { eif_path } => {
            let info = eif::inspect_eif(&eif_path)?;
            println!("EIF version:  {}", info.version);
            println!("Flags:        {:#06x}", info.flags);
            println!("Default mem:  {} bytes", info.default_mem);
            println!("Default CPUs: {}", info.default_cpus);
            println!("Sections:     {}", info.num_sections);
            println!();
            for (i, s) in info.sections.iter().enumerate() {
                println!(
                    "  [{}] {:<12} offset={:#010x}  size={:#010x} ({} bytes)",
                    i,
                    eif::section_type_name(s.section_type),
                    s.offset,
                    s.size,
                    s.size,
                );
            }
            // Also print cmdline if present
            let contents = eif::parse_eif(&eif_path)?;
            println!("\nCmdline: {}", contents.cmdline);
            if let Some(meta) = &contents.metadata {
                println!("\nMetadata: {}", meta);
            }
        }

        Commands::Run {
            eif_path,
            kernel,
            rootfs,
            eif_kernel,
            secrets,
            secrets_file,
            verbose,
            port,
            secrets_port,
            memory,
            cpus,
            qemu,
        } => {
            // Resolve QEMU path
            let qemu_path = qemu.unwrap_or_else(qemu::QemuConfig::default_qemu_path);
            let version = qemu::check_qemu(&qemu_path)?;
            eprintln!("Using QEMU: {}", version);

            // Embedded local kernel (Alpine linux-virt with virtio-net support)
            const LOCAL_KERNEL: &[u8] = include_bytes!("../local-kernel-x86_64");

            // Extract rootfs from EIF (always needed) and optionally kernel
            let (eif_kernel_data, rootfs_data) = if kernel.is_some() && rootfs.is_some() {
                let k = std::fs::read(kernel.as_ref().unwrap())
                    .context("reading kernel file")?;
                let r = std::fs::read(rootfs.as_ref().unwrap())
                    .context("reading rootfs file")?;
                (k, r)
            } else {
                eprintln!("Parsing EIF: {}", eif_path.display());
                let contents = eif::parse_eif(&eif_path)?;
                eprintln!(
                    "  kernel={} bytes, ramdisk={} bytes",
                    contents.kernel.len(),
                    contents.ramdisk.len()
                );
                (contents.kernel, contents.ramdisk)
            };

            // Use local kernel by default (has virtio-net driver for QEMU networking).
            // The Nitro EIF kernel lacks PCI/virtio-net drivers needed for local testing.
            let use_local_kernel = !eif_kernel;
            let kernel_data = if use_local_kernel {
                eprintln!("Using local kernel (Alpine linux-virt, {} bytes)", LOCAL_KERNEL.len());
                LOCAL_KERNEL.to_vec()
            } else {
                eprintln!("Using EIF kernel (may lack virtio-net driver)");
                eif_kernel_data
            };

            // Build cmdline for local kernel
            let cmdline = "reboot=k root=/dev/ram0 panic=1 console=ttyS0 i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd nit.target=/run.sh".to_string();
            eprintln!("  cmdline: {}", cmdline);

            // Write kernel and rootfs to temp files
            let tmp_dir = std::env::temp_dir().join("nautilus-local");
            std::fs::create_dir_all(&tmp_dir)?;
            let kernel_path = tmp_dir.join("kernel");
            let rootfs_path = tmp_dir.join("rootfs.cpio");
            let overlay_path = tmp_dir.join("overlay.cpio");

            std::fs::write(&kernel_path, &kernel_data)?;
            std::fs::write(&rootfs_path, &rootfs_data)?;

            // Resolve secrets JSON
            let secrets_json = if let Some(json) = secrets {
                json
            } else if let Some(path) = secrets_file {
                std::fs::read_to_string(&path)
                    .with_context(|| format!("reading secrets file {}", path.display()))?
            } else {
                "{}".to_string()
            };

            // Build overlay with embedded mock-nsm binary, kernel modules, and secrets
            let include_modules = use_local_kernel;
            eprintln!("Building overlay initrd (mock-nsm={} bytes, modules={}, secrets={} bytes)...",
                overlay::MOCK_NSM_BINARY.len(), include_modules, secrets_json.len());
            let overlay_bytes = overlay::build_overlay(Some(overlay::MOCK_NSM_BINARY), include_modules, Some(&secrets_json))?;
            std::fs::write(&overlay_path, &overlay_bytes)?;

            // Launch QEMU
            let config = qemu::QemuConfig {
                kernel: kernel_path,
                rootfs: rootfs_path,
                overlay: overlay_path,
                cmdline,
                memory,
                cpus,
                app_port: port,
                secrets_port,
                qemu_path,
                verbose,
            };

            let mut child = qemu::launch(&config)?;

            // Set up Ctrl+C handler to kill QEMU
            let child_id = child.id();
            ctrlc::set_handler(move || {
                eprintln!("\nShutting down QEMU (PID {})...", child_id);
                unsafe {
                    libc::kill(child_id as i32, libc::SIGTERM);
                }
            })
            .ok();

            eprintln!("Secrets embedded in overlay initrd");
            eprintln!("Enclave server should be available at http://localhost:{}", port);

            // Wait for QEMU to exit
            let status = child.wait()?;
            eprintln!("QEMU exited with: {}", status);
        }

        Commands::Attest {
            public_key,
            pcr0,
            pcr1,
            pcr2,
            output,
        } => {
            let pk_bytes = hex::decode(&public_key).context("invalid hex for public key")?;
            let pcrs = parse_pcrs(&pcr0, &pcr1, &pcr2)?;

            eprintln!("Generating test CA chain...");
            let ca = attestation::TestCa::new()?;

            eprintln!("Building attestation document...");
            let doc = attestation::build_attestation_document(
                Some(&pk_bytes),
                None,
                None,
                &pcrs,
                &ca,
            )?;

            if let Some(path) = output {
                std::fs::write(&path, &doc)
                    .with_context(|| format!("writing attestation to {}", path.display()))?;
                eprintln!("Wrote {} bytes to {}", doc.len(), path.display());
            } else {
                println!("{}", hex::encode(&doc));
            }
        }
    }

    Ok(())
}
