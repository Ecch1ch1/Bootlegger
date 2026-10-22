use bootlegger_core::{
    accountant::DilutionAccountant,
    dispersion::SecretPayload,
    error::BootlegError,
    tripwire::CarrierEntry,
};
use bootlegger_format::{DecoyFile, TarEngine, TAR_BLOCK_SIZE};
use clap::{Parser, Subcommand};
use colored::*;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "bootlegger",
    author = "Bootlegger Contributors",
    version,
    about = "Plausible Deniability & Dilution Steganography for Covert Data Storage",
    long_about = "Bootlegger conceals secret payloads inside standard, valid archives (e.g. TAR) using micro-dispersion into block slack space and strict dilution budgets. Incorporates Tripwire anti-tamper pinning."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Conceal secret file into a cover archive with plausible deniability
    Pack {
        /// Path to secret file to hide
        #[arg(short, long)]
        secret: PathBuf,

        /// One or more cover files or directories to serve as carrier decoys
        #[arg(short, long, num_args = 1..)]
        cover: Vec<PathBuf>,

        /// Destination path for generated TAR archive
        #[arg(short, long)]
        out: PathBuf,

        /// Secret passphrase (if omitted, prompts interactively or checks BOOTLEGGER_PASSWORD env)
        #[arg(short, long)]
        password: Option<String>,

        /// Optional harmless decoy secret for Coercion/Duress defense (revealed only if duress password is used)
        #[arg(long)]
        duress_secret: Option<PathBuf>,

        /// Passphrase for duress layer (prompts if omitted when --duress-secret is used)
        #[arg(long)]
        duress_password: Option<String>,

        /// Enable Tripwire anti-tamper pinning (if carrier is altered or inspected, secret self-destructs)
        #[arg(long, default_value_t = false)]
        tripwire: bool,

        /// Maximum safe dilution ratio (default: 0.03 = 3% of carrier volume)
        #[arg(short, long, default_value_t = 0.03)]
        ratio: f64,
    },

    /// Extract and recover concealed secret from a carrier archive
    Unpack {
        /// Path to carrier archive (.tar)
        #[arg(short = 'i', long = "in")]
        archive: PathBuf,

        /// Output path for recovered secret (or directory)
        #[arg(short, long)]
        out: Option<PathBuf>,

        /// Secret passphrase
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Analyze whether cover files provide sufficient volume for safe dilution
    Check {
        /// Path to secret file to assess
        #[arg(short, long)]
        secret: PathBuf,

        /// Cover files or directories to assess
        #[arg(short, long, num_args = 1..)]
        cover: Vec<PathBuf>,

        /// Maximum safe dilution ratio (default: 0.03)
        #[arg(short, long, default_value_t = 0.03)]
        ratio: f64,
    },

    /// Forensically inspect an archive for slack usage and entropy profile
    Audit {
        /// Path to archive to inspect
        #[arg(short = 'i', long = "in")]
        archive: PathBuf,
    },

    /// Extract only the visible decoy files to a directory (simulates what an inspector sees)
    ExtractDecoys {
        /// Path to archive
        #[arg(short = 'i', long = "in")]
        archive: PathBuf,

        /// Destination directory for decoy files
        #[arg(short, long)]
        out: PathBuf,
    },
}

/// Recursively collect all regular files from a list of paths
fn collect_files(paths: &[PathBuf]) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for p in paths {
        if p.is_file() {
            files.push(p.clone());
        } else if p.is_dir() {
            for entry in fs::read_dir(p)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    files.push(path);
                } else if path.is_dir() {
                    files.extend(collect_files(&[path])?);
                }
            }
        }
    }
    // Filter out .git, target, and temporary editor swap files
    files.retain(|p| {
        let s = p.to_string_lossy();
        !s.contains("/.git/") && !s.contains("/target/") && !s.ends_with(".swp")
    });
    Ok(files)
}

/// Load collected files into DecoyFile structs
fn load_decoys(paths: &[PathBuf], base_dir: Option<&Path>) -> io::Result<Vec<DecoyFile>> {
    let mut decoys = Vec::new();
    for p in paths {
        let content = fs::read(p)?;
        let rel_path = if let Some(base) = base_dir {
            p.strip_prefix(base).unwrap_or(p).to_string_lossy().to_string()
        } else {
            p.file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| p.to_string_lossy().to_string())
        };

        let metadata = fs::metadata(p)?;
        let mtime = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(1700000000);

        decoys.push(DecoyFile {
            path: rel_path,
            content,
            mtime,
            mode: 0o644,
        });
    }
    Ok(decoys)
}

/// Resolves password from flag, env, or interactive prompt
fn get_password(pass_opt: Option<String>) -> String {
    if let Some(p) = pass_opt {
        return p;
    }
    if let Ok(env_pass) = std::env::var("BOOTLEGGER_PASSWORD")
        && !env_pass.is_empty() {
            return env_pass;
        }

    print!("{}", "🔑 Enter secret passphrase: ".bold().cyan());
    io::stdout().flush().unwrap();
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).unwrap();
    buf.trim_end_matches(['\r', '\n']).to_string()
}

/// Calculates Shannon entropy of a byte slice (0.0 to 8.0)
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let total = data.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Pack {
            secret,
            cover,
            out,
            password,
            duress_secret,
            duress_password,
            tripwire,
            ratio,
        } => {
            println!("{}", "🥾 Bootlegger Packing Pipeline".bold().green());

            if !secret.exists() {
                eprintln!("{} Secret file not found: {:?}", "Error:".red().bold(), secret);
                std::process::exit(1);
            }

            let secret_data = match fs::read(&secret) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("{} Failed to read secret: {}", "Error:".red().bold(), e);
                    std::process::exit(1);
                }
            };

            let secret_filename = secret
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| "secret.bin".to_string());

            let payload = SecretPayload::new(secret_filename, secret_data);

            let cover_files = match collect_files(&cover) {
                Ok(files) => files,
                Err(e) => {
                    eprintln!("{} Failed to scan cover paths: {}", "Error:".red().bold(), e);
                    std::process::exit(1);
                }
            };

            if cover_files.is_empty() {
                eprintln!("{} No valid cover files found in provided paths.", "Error:".red().bold());
                std::process::exit(1);
            }

            let base_dir = if cover.len() == 1 && cover[0].is_dir() {
                Some(cover[0].as_path())
            } else {
                None
            };

            let decoys = match load_decoys(&cover_files, base_dir) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("{} Failed to read decoy files: {}", "Error:".red().bold(), e);
                    std::process::exit(1);
                }
            };

            let total_cover_bytes: usize = decoys.iter().map(|d| d.content.len()).sum();
            println!(
                "  📁 Carrier Decoys: {} files, {} bytes total",
                decoys.len().to_string().cyan(),
                total_cover_bytes.to_string().cyan()
            );
            println!(
                "  🔒 Secret Payload: '{}' ({} bytes)",
                payload.filename.yellow(),
                payload.data.len().to_string().yellow()
            );

            let pass = get_password(password);
            if pass.is_empty() {
                eprintln!("{} Passphrase cannot be empty.", "Error:".red().bold());
                std::process::exit(1);
            }

            println!("  ⚙️  Enforcing Dilution Budget (max ratio {:.1}%)...", ratio * 100.0);
            if tripwire {
                println!("  🛡️  Tripwire Anti-Tamper: {}", "ACTIVE (Carrier Pinned)".green().bold());
            } else {
                println!("  🛡️  Tripwire Anti-Tamper: {}", "Disabled".yellow());
            }

            let res_archive = if let Some(ref d_secret_path) = duress_secret {
                let d_data = match fs::read(d_secret_path) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("{} Failed to read duress secret: {}", "Error:".red().bold(), e);
                        std::process::exit(1);
                    }
                };
                let d_name = d_secret_path
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_else(|| "decoy_secret.txt".to_string());
                let duress_payload = SecretPayload::new(d_name, d_data);

                let d_pass = if let Some(p) = duress_password {
                    p
                } else if let Ok(env_p) = std::env::var("BOOTLEGGER_DURESS_PASSWORD") {
                    env_p
                } else {
                    print!("{}", "🔑 Enter DURESS (decoy) passphrase: ".bold().magenta());
                    io::stdout().flush().unwrap();
                    let mut buf = String::new();
                    io::stdin().read_line(&mut buf).unwrap();
                    buf.trim_end_matches(['\r', '\n']).to_string()
                };

                println!("  🎭 Multi-Tier Plausible Deniability: {}", "Active (Primary + Duress)".magenta().bold());
                TarEngine::pack_dual(
                    &decoys,
                    &payload,
                    pass.as_bytes(),
                    &duress_payload,
                    d_pass.as_bytes(),
                    tripwire,
                    Some(ratio),
                )
            } else {
                TarEngine::pack(&decoys, &payload, pass.as_bytes(), tripwire, Some(ratio))
            };

            match res_archive {
                Ok(archive_bytes) => {
                    if let Err(e) = fs::write(&out, &archive_bytes) {
                        eprintln!("{} Failed to write output archive: {}", "Error:".red().bold(), e);
                        std::process::exit(1);
                    }
                    println!(
                        "{} Successfully packaged carrier archive -> {:?}",
                        "✓".green().bold(),
                        out
                    );
                    println!(
                        "  📦 Output Archive Size: {} bytes (100% compliant POSIX TAR)",
                        archive_bytes.len().to_string().cyan()
                    );
                    println!(
                        "  ✨ Plausible Deniability: Standard tools (tar, unzip, 7-zip) see only ordinary files."
                    );
                }
                Err(BootlegError::InsufficientCapacity {
                    needed_bytes,
                    available_bytes,
                    additional_files_needed,
                }) => {
                    eprintln!("\n{}", "⚠️  CARRIER CAPACITY INSUFFICIENT FOR SAFE DILUTION".red().bold());
                    eprintln!("  Secret payload requires {} bytes of stealth budget.", needed_bytes.to_string().yellow());
                    eprintln!("  Selected cover files only provide {} bytes under safe dilution ratio.", available_bytes.to_string().yellow());
                    eprintln!("  {}", "Rule: \"Buď tak akorát nebo víc, ale nikdy ne míň.\"".italic().bold());
                    eprintln!("  👉 Please add at least {} more decoy files to the carrier set.", additional_files_needed.to_string().cyan().bold());
                    std::process::exit(2);
                }
                Err(e) => {
                    eprintln!("{} Packaging failed: {}", "Error:".red().bold(), e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Unpack {
            archive,
            out,
            password,
        } => {
            println!("{}", "🥾 Bootlegger Unpack Pipeline".bold().green());

            if !archive.exists() {
                eprintln!("{} Archive not found: {:?}", "Error:".red().bold(), archive);
                std::process::exit(1);
            }

            let archive_bytes = match fs::read(&archive) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("{} Failed to read archive: {}", "Error:".red().bold(), e);
                    std::process::exit(1);
                }
            };

            let pass = get_password(password);

            match TarEngine::unpack_secret(&archive_bytes, pass.as_bytes()) {
                Ok((secret, tripwire_info)) => {
                    println!("{} Authentication & decryption successful!", "✓".green().bold());

                    if let Some(tw) = tripwire_info {
                        println!(
                            "  🛡️  Tripwire Verified: {}",
                            format!("Carrier 100% intact ({} files verified, 0 byte shift)", tw.file_count).green().bold()
                        );
                    }

                    println!(
                        "  📄 Recovered Secret: '{}' ({} bytes)",
                        secret.filename.yellow().bold(),
                        secret.data.len().to_string().cyan()
                    );

                    let out_path = if let Some(p) = out {
                        if p.is_dir() {
                            p.join(&secret.filename)
                        } else {
                            p
                        }
                    } else {
                        PathBuf::from(&secret.filename)
                    };

                    if let Err(e) = fs::write(&out_path, &secret.data) {
                        eprintln!("{} Failed to write recovered secret: {}", "Error:".red().bold(), e);
                        std::process::exit(1);
                    }

                    println!("{} Saved secret to {:?}", "✓".green().bold(), out_path);
                }
                Err(BootlegError::TamperDetected(reason)) => {
                    eprintln!("\n{}", "🚨 TRIPWIRE ALARM TRIGGERED: TAMPER DETECTED!".red().bold());
                    eprintln!("  The carrier archive has been modified, inspected, or re-packed.");
                    eprintln!("  Forensic detail: {}", reason.yellow());
                    eprintln!("  Security Policy: Decryption aborted to prevent exploitation.");
                    std::process::exit(3);
                }
                Err(BootlegError::AuthenticationFailed) => {
                    eprintln!(
                        "\n{} Authentication failed: invalid passphrase or modified carrier archive.",
                        "Error:".red().bold()
                    );
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("{} Unpack failed: {}", "Error:".red().bold(), e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Check {
            secret,
            cover,
            ratio,
        } => {
            println!("{}", "🔍 Bootlegger Dilution Assessment".bold().cyan());

            let secret_size = match fs::metadata(&secret) {
                Ok(m) => m.len() as usize,
                Err(e) => {
                    eprintln!("{} Cannot read secret file: {}", "Error:".red().bold(), e);
                    std::process::exit(1);
                }
            };

            let cover_files = collect_files(&cover).unwrap_or_default();
            let entries: Vec<CarrierEntry> = cover_files
                .iter()
                .filter_map(|p| {
                    let content = fs::read(p).ok()?;
                    Some(CarrierEntry::new(
                        p.to_string_lossy().to_string(),
                        content.len() as u64,
                        &content,
                        1700000000,
                    ))
                })
                .collect();

            match DilutionAccountant::assess(&entries, secret_size + 44, Some(ratio)) {
                Ok(cap) => {
                    println!("{} Carrier capacity is SUFFICIENT for stealth storage.", "✓".green().bold());
                    println!("  Total Decoy Files: {}", cap.file_count.to_string().cyan());
                    println!("  Total Decoy Volume: {} bytes", cap.total_decoy_bytes.to_string().cyan());
                    println!("  Safe Stealth Capacity: {} bytes", cap.safe_capacity_bytes.to_string().green());
                    println!("  Secret Size: {} bytes", cap.secret_payload_bytes.to_string().yellow());
                    println!("  Effective Dilution Ratio: {:.2}%", cap.effective_dilution_ratio * 100.0);
                }
                Err(BootlegError::InsufficientCapacity {
                    needed_bytes,
                    available_bytes,
                    additional_files_needed,
                }) => {
                    println!("{} Carrier capacity is INSUFFICIENT.", "✗".red().bold());
                    println!("  Needed: {} bytes", needed_bytes.to_string().yellow());
                    println!("  Available safe capacity: {} bytes", available_bytes.to_string().yellow());
                    println!("  👉 Need at least {} more decoy files.", additional_files_needed.to_string().cyan().bold());
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        Commands::Audit { archive } => {
            println!("{}", "🔬 Bootlegger Forensic Audit".bold().cyan());

            if !archive.exists() {
                eprintln!("{} Archive not found: {:?}", "Error:".red().bold(), archive);
                std::process::exit(1);
            }

            let data = fs::read(&archive).unwrap();
            let total_entropy = shannon_entropy(&data);

            println!("  Archive Path: {:?}", archive);
            println!("  Total Archive Size: {} bytes", data.len());
            println!("  Overall Shannon Entropy: {:.4} / 8.0000", total_entropy);

            let decoys = TarEngine::extract_decoys(&data).unwrap_or_default();
            println!("  Extracted Decoy Files: {}", decoys.len().to_string().cyan());

            let mut total_slack = 0;
            for d in &decoys {
                let remainder = d.content.len() % TAR_BLOCK_SIZE;
                if remainder != 0 {
                    total_slack += TAR_BLOCK_SIZE - remainder;
                }
            }
            println!("  Total Block Slack Space: {} bytes across {} slots", total_slack.to_string().cyan(), decoys.len());

            if total_entropy < 7.95 {
                println!("  Stealth Profile: {}", "NATURAL (Conforms to standard file/text mixture)".green().bold());
            } else {
                println!("  Stealth Profile: {}", "HIGH ENTROPY (Archive consists predominantly of compressed/encrypted data)".yellow().bold());
            }
        }

        Commands::ExtractDecoys { archive, out } => {
            println!("{}", "📂 Extracting Legitimate Decoy Files".bold().cyan());

            let data = fs::read(&archive).unwrap();
            let decoys = match TarEngine::extract_decoys(&data) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("{} Failed to parse archive: {}", "Error:".red().bold(), e);
                    std::process::exit(1);
                }
            };

            fs::create_dir_all(&out).unwrap();
            for d in &decoys {
                let target = out.join(&d.path);
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).unwrap();
                }
                fs::write(&target, &d.content).unwrap();
                println!("  Extracted: {:?}", target);
            }
            println!("{} Extracted {} decoy files to {:?}", "✓".green().bold(), decoys.len(), out);
        }
    }
}
