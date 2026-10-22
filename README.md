# Bootlegger 🥾📦

> **Plausible Deniability & Dilution Steganography for Covert Data Storage**

Bootlegger takes sensitive data and dissolves it into completely legitimate, standard cover media (TAR archives, ZIP files, code repositories, document bundles) using **micro-dispersion**, strict **dilution ratios**, and optional **tamper-evident Tripwire protection**.

The resulting archive contains **zero magic headers**, behaves as a 100% normal archive in standard tools (`tar`, `unzip`, WinRAR), and mathematically resists both statistical entropy analysis and coercion attacks.

---

## ⚡ Core Principles

* **Zero-Footprint Format:** No `BOOTLEG` magic bytes or recognizable headers. Output is a 100% compliant POSIX / GNU TAR or ZIP archive.
* **Dilution Accountant:** Enforces safe capacity limits. Decoy volume must be proportional to secret size — *"buď tak akorát nebo víc, ale nikdy ne míň"*.
* **Tripwire Anti-Tamper:** Pinned carrier integrity via Merkle tree / BLAKE3. If any file inside the carrier is inspected, modified, re-packed or touched by even a single byte, AEAD decryption automatically aborts.
* **Modern Cryptography:** ChaCha20-Poly1305 authenticated encryption, Argon2id key derivation, and ChaCha20 PRNG deterministic micro-shard dispersion.

---

## 🏗️ Architecture

```
Bootlegger/
├── crates/
│   ├── bootlegger-core/      # Cryptography, Tripwire, Dilution Accountant, PRNG dispersion
│   ├── bootlegger-format/    # TAR, ZIP, whitespace and block slack steganography adapters
│   └── bootlegger-cli/       # CLI utility (`bootlegger pack / unpack / audit`)
```

---

## 📄 License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
