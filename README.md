# Bootlegger 🥾📦

> **Plausible Deniability & Dilution Steganography for Covert Data Storage**  
> *"Být paranoidní nestačí."*

[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)
[![Language: Rust](https://img.shields.io/badge/Language-Rust_2024-orange.svg)](https://www.rust-lang.org/)
[![Build: Passing](https://img.shields.io/badge/Tests-100%25_Passing-success.svg)](#)

Bootlegger dissolves confidential data into ordinary, legitimate carrier archives (POSIX/GNU TAR archives containing source code, documents, or data files) using **micro-dispersion into block slack space**, strict **dilution budgets**, and an optional bitwise-pinned **Tripwire anti-tamper system**.

The generated archive contains **zero magic headers**, behaves as a 100% standard archive in everyday tools (`tar`, `unzip`, 7-zip, file explorer), and resists both coercive inspection and statistical forensic analysis.

---

## ⚡ Key Capabilities

* 🥾 **Zero-Footprint Format:** No `BOOTLEG` magic bytes or detectable markers. The archive is 100% compliant POSIX USTAR. Standard tools extract all visible decoy files with exact checksums.
* ⚖️ **Dilution Accountant:** Enforces mathematical stealth budgets. Decoy volume must naturally swallow the secret — *"buď tak akorát nebo víc, ale nikdy ne míň"*. Halts packaging if cover volume is insufficient.
* 🛡️ **Tripwire Anti-Tamper:** Pinned carrier integrity via Merkle tree / BLAKE3. If an investigator touches, modifies, re-packs, or inspects even 1 bit of any decoy file, AEAD decryption automatically aborts.
* 🔐 **Modern Cryptography:** ChaCha20-Poly1305 authenticated encryption, Argon2id key derivation, HKDF-SHA256 key schedule, and ChaCha20 PRNG deterministic shard dispersion.
* 🔬 **Built-in Forensic Audit:** Built-in Shannon entropy scanner, slack-space accountant, and anomaly detector.

---

## 🚀 Quick Start

### 1. Installation

```bash
git clone https://github.com/Ecch1ch1/Bootlegger.git
cd Bootlegger
cargo build --release
```

The compiled binary will be located at `target/release/bootlegger`.

### 2. Verify Capacity Before Packaging

Check whether your decoy documents provide sufficient safe capacity for your secret:

```bash
bootlegger check --secret secret_keys.kdbx --cover ./my_project_code/
```

### 3. Pack with Plausible Deniability & Tripwire

Conceal the secret into a valid TAR archive:

```bash
bootlegger pack \
  --secret secret_keys.kdbx \
  --cover ./my_project_code/ \
  --out backup_project.tar \
  --tripwire
```

* Prompts for passphrase interactively (or via `BOOTLEGGER_PASSWORD` environment variable).
* Visible archive size is normal. When inspected with `tar -tvf backup_project.tar` or extracted with `tar -xf backup_project.tar`, only the legitimate project files are shown!

### 4. Forensic Audit

Analyze the resulting archive to verify its stealth profile:

```bash
bootlegger audit --in backup_project.tar
```

### 5. Unpack Secret

Recover the original file:

```bash
bootlegger unpack \
  --in backup_project.tar \
  --out recovered_keys.kdbx
```

If `--tripwire` was enabled during pack, Bootlegger automatically validates that the carrier was not tampered with before releasing the secret.

---

## 🏗️ Architecture

```
Bootlegger/
├── Cargo.toml                  # Workspace Manifest
├── crates/
│   ├── bootlegger-core/        # Cryptography, Tripwire, Dilution Accountant, PRNG dispersion
│   ├── bootlegger-format/      # TAR format engine & block-slack steganography
│   └── bootlegger-cli/         # Command-line interface (`bootlegger`)
├── docs/
│   ├── SPECIFICATION.md        # Mathematical & protocol specification
│   └── SECURITY.md             # Threat model, forensic resistance & paranoid security analysis
└── tests/                      # GNU tar compatibility and roundtrip tests
```

---

## 📚 Documentation

* [Technical Specification](docs/SPECIFICATION.md): Mathematical formulations, key schedules, TAR block layout, and dispersion algorithm.
* [Security Model & Paranoid Threat Assessment](docs/SECURITY.md): Threat vectors, Rubber-hose cryptanalysis defense, Tripwire mechanics, and entropy analysis.

---

## 📄 License

This Source Code Form is subject to the terms of the **Mozilla Public License, v. 2.0**.  
See the [LICENSE](LICENSE) file for details.
