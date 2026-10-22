# Bootlegger 🥾📦

> **Plausible Deniability & Dilution Steganography for Covert Data Storage**  
> *"Být paranoidní nestačí."*

[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)
[![Language: Rust](https://img.shields.io/badge/Language-Rust_2024-orange.svg)](https://www.rust-lang.org/)
[![Web Demo: GitHub Pages](https://img.shields.io/badge/Interactive_Visualizer-Live_Demo-blue.svg)](https://ecch1ch1.github.io/Bootlegger/)
[![Arch Linux: PKGBUILD](https://img.shields.io/badge/Arch_Linux-PKGBUILD-1793d1.svg)](packaging/arch/PKGBUILD)
[![Debian/Ubuntu: .deb](https://img.shields.io/badge/Debian%20%2F%20Ubuntu-.deb_package-a81d33.svg)](packaging/debian/build-deb.sh)

Bootlegger dissolves confidential data into ordinary, legitimate carrier archives (POSIX/GNU TAR archives containing source code, documents, or data files) using **micro-dispersion into block slack space**, strict **dilution budgets**, and an optional bitwise-pinned **Tripwire anti-tamper system**.

The generated archive contains **zero magic headers**, behaves as a 100% standard archive in everyday tools (`tar`, `unzip`, 7-zip, file explorer), and resists both coercive inspection (**Duress decoy layer**) and statistical forensic analysis.

---

## 🌐 Live Interactive Visualizer

Experience Bootlegger's memory architecture, dual-passphrase decryption, Tripwire tamper simulator, and Shannon entropy analyzer directly in your browser:

🔗 **[https://ecch1ch1.github.io/Bootlegger/](https://ecch1ch1.github.io/Bootlegger/)**

---

## ⚡ Key Capabilities

* 🥾 **Zero-Footprint Format:** No `BOOTLEG` magic bytes or detectable markers. The archive is 100% compliant POSIX USTAR. Standard tools extract all visible decoy files with exact checksums.
* 🎭 **Multi-Tier Duress Decoy:** Dual-layer plausible deniability. Entering the **Master Passphrase** extracts the true secret. Entering the **Duress Passphrase** extracts a harmless decoy document. The examiner has zero mathematical or statistical proof that a second secret exists!
* ⚖️ **Dilution Accountant:** Enforces mathematical stealth budgets. Decoy volume must naturally swallow the secret — *"buď tak akorát nebo víc, ale nikdy ne míň"*. Halts packaging if cover volume is insufficient.
* 🛡️ **Tripwire Anti-Tamper:** Pinned carrier integrity via Merkle tree / BLAKE3. If an investigator touches, modifies, re-packs, or inspects even 1 bit of any decoy file, AEAD decryption automatically aborts.
* 🧙 **Interactive Guided Wizard:** Run `bootlegger wizard` (or just `bootlegger`) for an intuitive step-by-step terminal interface.
* 🐚 **Shell Auto-Completions:** Built-in auto-completion generator for Bash, Zsh, Fish, and PowerShell.

---

## 📦 Linux Installation

Bootlegger can be installed directly as a system command on all major Linux distributions:

### 1. One-Command Quick Install (Any Linux distro)

```bash
./install.sh
```
*Installs the compiled binary into `~/.local/bin/bootlegger` (or `/usr/local/bin/bootlegger` if run as root).*

### 2. Arch Linux (PKGBUILD / AUR)

```bash
cd packaging/arch
makepkg -si
```
*Builds and installs native Arch Linux package via `pacman`.*

### 3. Debian / Ubuntu (.deb Package)

```bash
./packaging/debian/build-deb.sh
sudo dpkg -i target/debian/bootlegger_0.1.0_amd64.deb
```

### 4. Makefile / Cargo

```bash
# User install (no sudo required):
make install-user

# System-wide install:
sudo make install

# Via Cargo:
cargo install --path crates/bootlegger-cli
```

---

## 🚀 CLI Usage & Examples

### 1. Interactive Step-by-Step Wizard (Easiest)

Simply run:
```bash
bootlegger wizard
# or simply:
bootlegger
```
The wizard guides you interactively through choosing secret files, configuring Duress decoys, selecting cover files, and setting passphrases.

### 2. Pack a Secret with Tripwire Protection

```bash
bootlegger pack \
  --secret classified_keys.kdbx \
  --cover ./project_sources/ \
  --out backup_project.tar \
  --tripwire
```

### 3. Pack with Duress Coercion Protection (Dual Secrets)

Conceal both your true secret and a believable decoy in the same archive:

```bash
bootlegger pack \
  --secret real_passwords.txt \
  --duress-secret innocent_notes.txt \
  --cover ./crates/ \
  --out secure_carrier.tar \
  --password "TrueMasterPassword123" \
  --duress-password "CoercedDecoyPassword" \
  --tripwire
```

### 4. Unpack Secret

Bootlegger automatically recognizes which passphrase you provide:

```bash
# If you enter TrueMasterPassword123:
bootlegger unpack -i secure_carrier.tar -o recovered.txt
# -> Recovers real_passwords.txt!

# If under duress you enter CoercedDecoyPassword:
bootlegger unpack -i secure_carrier.tar -o recovered.txt
# -> Recovers innocent_notes.txt seamlessly with zero errors or traces of the real secret!
```

### 5. Check Cover Capacity (Dilution Assessment)

Verify if your decoy documents have enough safe slack capacity before packaging:

```bash
bootlegger check --secret large_payload.pdf --cover ./my_docs/
```

### 6. Forensic Audit (Shannon Entropy Profile)

Analyze the generated archive to verify that its entropy profile matches normal files:

```bash
bootlegger audit -i secure_carrier.tar
```

### 7. Install Shell Auto-Completions

```bash
# Bash:
bootlegger completions bash > ~/.local/share/bash-completion/completions/bootlegger

# Zsh:
bootlegger completions zsh > ~/.zfunc/_bootlegger

# Fish:
bootlegger completions fish > ~/.config/fish/completions/bootlegger.fish
```

---

## 🏗️ Architecture

```
Bootlegger/
├── Cargo.toml                  # Workspace Manifest
├── Makefile                    # Linux build & install targets
├── install.sh                  # Standalone user installer
├── packaging/
│   ├── arch/PKGBUILD           # Arch Linux pacman package
│   └── debian/build-deb.sh     # Debian / Ubuntu .deb package generator
├── crates/
│   ├── bootlegger-core/        # Cryptography, Tripwire, Dilution Accountant, PRNG dispersion
│   ├── bootlegger-format/      # TAR format engine, block-slack steganography & Duress scheduler
│   └── bootlegger-cli/         # CLI utility with interactive wizard & shell completions
├── visualizer/                 # Interactive HTML5/JS Web Visualizer & Entropy Spectrum
├── docs/                       # Technical specifications, security analysis & GitHub Pages host
└── tests/                      # GNU tar compatibility and roundtrip tests
```

---

## 📚 Technical & Security Specifications

* [Technical Specification](docs/SPECIFICATION.md): Mathematical formulations, key schedules, TAR block layout, and dispersion algorithm.
* [Security Model & Paranoid Threat Assessment](docs/SECURITY.md): Threat vectors, Rubber-hose cryptanalysis defense, Tripwire mechanics, and entropy analysis.

---

## 📄 License

This Source Code Form is subject to the terms of the **Mozilla Public License, v. 2.0**.  
See the [LICENSE](LICENSE) file for details.
